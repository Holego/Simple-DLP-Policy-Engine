"""Local mode: watch a folder that simulates the gateway in front of outgoing files."""

from __future__ import annotations

import logging
import os
import stat
import threading
import time
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.api import BaseObserver
from watchdog.observers.polling import PollingObserver

from src.actions import (
    ActionExecutor,
    AlertAction,
    LocalBlock,
    LocalQuarantine,
    LogNotifier,
    Notifier,
    WebhookNotifier,
    is_blocked,
)
from src.detectors.scanner import DEFAULT_MAX_SCAN_BYTES, Scanner
from src.engine.engine import PolicyEngine
from src.incident import MODE_LOCAL
from src.pipeline import DlpPipeline, PipelineResult
from src.storage.base import IncidentStore

from .manifest import DIRECTORY_MANIFEST, LocalDestinationResolver

logger = logging.getLogger(__name__)

_IGNORED_SUFFIXES = (
    ".meta.json",
    ".dlp-blocked",
    ".incident.json",
    ".tmp",
    ".part",
    ".partial",
    ".swp",
    ".crdownload",
    "~",
)


def should_ignore(path: Path) -> bool:
    """Manifests, markers and editor/download temp files are not payloads."""
    name = path.name
    return name.startswith(".") or name == DIRECTORY_MANIFEST or name.endswith(_IGNORED_SUFFIXES)


def build_local_pipeline(
    *,
    engine: PolicyEngine,
    quarantine_dir: Path,
    store: IncidentStore,
    webhook_url: str | None = None,
    extra_notifiers: tuple[Notifier, ...] = (),
) -> DlpPipeline:
    """Wire the shared pipeline with the local action handlers."""
    notifiers: list[Notifier] = [LogNotifier(), *extra_notifiers]
    if webhook_url:
        notifiers.append(WebhookNotifier(webhook_url))
    executor = ActionExecutor(
        [AlertAction(notifiers), LocalQuarantine(quarantine_dir), LocalBlock()]
    )
    return DlpPipeline(
        mode=MODE_LOCAL, scanner=Scanner(), engine=engine, executor=executor, store=store
    )


def _read_regular_file(path: Path, max_bytes: int) -> tuple[os.stat_result, bytes, bool] | None:
    """Open without following symlinks or blocking on pipes; read only regular files."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as exc:
        logger.warning("cannot open %s: %s", path, exc.strerror or exc)
        return None
    with os.fdopen(fd, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode):
            return None
        data = handle.read(max_bytes + 1)
    return info, data[:max_bytes], len(data) > max_bytes


class LocalFileProcessor:
    """Reads one file from the watched tree and runs it through the pipeline."""

    def __init__(
        self,
        pipeline: DlpPipeline,
        watch_dir: Path,
        *,
        quarantine_dir: Path | None = None,
        max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES,
    ) -> None:
        self.pipeline = pipeline
        self.watch_dir = watch_dir.resolve()
        self.quarantine_dir = quarantine_dir.resolve() if quarantine_dir else None
        self.max_scan_bytes = max_scan_bytes
        self.resolver = LocalDestinationResolver(self.watch_dir)

    def is_candidate(self, path: Path) -> bool:
        if should_ignore(path):
            return False
        if self.quarantine_dir and self.quarantine_dir in path.resolve().parents:
            return False
        return not is_blocked(path)

    def process(self, path: Path) -> PipelineResult | None:
        path = path.absolute()
        if not self.is_candidate(path):
            return None
        loaded = _read_regular_file(path, self.max_scan_bytes)
        if loaded is None:
            return None
        info, data, truncated = loaded
        return self.pipeline.process(
            data,
            source=str(path),
            destination=self.resolver.resolve(path),
            target=path,
            event_key=f"{info.st_mtime_ns}:{info.st_size}",
            file_info={"name": path.name, "size": info.st_size, "truncated": truncated},
        )


class _Handler(FileSystemEventHandler):
    def __init__(self, watcher: LocalWatcher) -> None:
        self.watcher = watcher

    def _submit(self, raw_path: str | bytes, is_directory: bool) -> None:
        if not is_directory:
            self.watcher.submit(Path(os.fsdecode(raw_path)))

    def on_created(self, event: FileSystemEvent) -> None:
        self._submit(event.src_path, event.is_directory)

    def on_modified(self, event: FileSystemEvent) -> None:
        self._submit(event.src_path, event.is_directory)

    def on_moved(self, event: FileSystemEvent) -> None:
        self._submit(event.dest_path, event.is_directory)


class LocalWatcher:
    """Watches a folder tree and processes files once they stop changing.

    Editors and copy tools produce several events per file and may still be writing when the
    first one arrives. Events are therefore collected per path and a file is processed only
    after ``settle_seconds`` without further events. A single worker thread handles the files
    one at a time, so a create and a modify event for one file never race each other.
    """

    def __init__(
        self,
        processor: LocalFileProcessor,
        *,
        settle_seconds: float = 0.5,
        use_polling: bool = False,
        poll_interval: float = 1.0,
    ) -> None:
        self.processor = processor
        self.settle_seconds = settle_seconds
        self.use_polling = use_polling
        self.poll_interval = poll_interval
        self._pending: dict[Path, float] = {}
        self._handled: dict[Path, tuple[int, int]] = {}
        self._busy = False
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._worker: threading.Thread | None = None
        self._observer: BaseObserver | None = None

    # -- lifecycle --------------------------------------------------------------------------

    def start(self, scan_existing: bool = True) -> None:
        root = self.processor.watch_dir
        root.mkdir(parents=True, exist_ok=True)
        self._stop.clear()
        self._worker = threading.Thread(target=self._run, name="dlp-worker", daemon=True)
        self._worker.start()

        observer = PollingObserver(timeout=self.poll_interval) if self.use_polling else Observer()
        observer.schedule(_Handler(self), str(root), recursive=True)
        observer.start()
        self._observer = observer
        logger.info("watching %s (%s)", root, "polling" if self.use_polling else "native events")

        if scan_existing:
            for current, _, names in os.walk(root):
                for name in names:
                    self.submit(Path(current) / name)

    def stop(self) -> None:
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
            self._observer = None
        self._stop.set()
        if self._worker is not None:
            self._worker.join(timeout=10)
            self._worker = None

    def __enter__(self) -> LocalWatcher:
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()

    # -- event handling ---------------------------------------------------------------------

    def submit(self, path: Path) -> None:
        """Register a file event; processing happens after the file has settled."""
        if should_ignore(path):
            return
        with self._lock:
            self._pending[path] = time.monotonic()

    def wait_idle(self, timeout: float = 10.0) -> bool:
        """Block until every submitted file has been processed. Returns False on timeout."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if not self._pending and not self._busy:
                    return True
            time.sleep(0.02)
        return False

    def _run(self) -> None:
        while not self._stop.is_set():
            path = self._next_due()
            if path is None:
                self._stop.wait(0.05)
                continue
            try:
                self._handle(path)
            except Exception:
                logger.exception("failed to process %s", path)
            finally:
                with self._lock:
                    self._busy = False

    def _next_due(self) -> Path | None:
        now = time.monotonic()
        with self._lock:
            for path, last_event in self._pending.items():
                if now - last_event >= self.settle_seconds:
                    del self._pending[path]
                    self._busy = True
                    return path
        return None

    def _handle(self, path: Path) -> None:
        try:
            info = path.stat()
        except OSError:
            self._handled.pop(path, None)
            return
        signature = (info.st_size, info.st_mtime_ns)
        if self._handled.get(path) == signature:
            return  # chmod, touch of a marker, duplicate events: nothing new to inspect
        result = self.processor.process(path)
        if result is not None and path.exists():
            self._handled[path] = signature
        else:
            self._handled.pop(path, None)
