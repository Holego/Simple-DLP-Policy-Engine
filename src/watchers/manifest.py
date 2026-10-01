"""Simulated send context for the local mode.

A real endpoint agent sees the mail envelope or the upload target. Here the context is
described next to the file, in decreasing order of precedence:

1. ``<file>.meta.json``            - a manifest for that one file
2. ``metadata.json``               - a manifest for a directory (nearest ancestor wins)
3. a folder name under the watch root that is a destination category, e.g.
   ``outbox/external_email/report.csv``
4. nothing found                   - destination ``unknown``

Manifest example::

    {"channel": "email", "recipient": "someone@vendor.example", "destination": "external_email"}

Write the manifest before (or atomically with) the file it describes.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from src.engine.destination import KNOWN_CHANNELS, KNOWN_DESTINATIONS, Destination

logger = logging.getLogger(__name__)

SIDECAR_SUFFIX = ".meta.json"
DIRECTORY_MANIFEST = "metadata.json"
MAX_MANIFEST_BYTES = 64 * 1024

_MANIFEST_KEYS = ("channel", "destination", "recipient", "domain", "public")
_FOLDER_CATEGORIES = KNOWN_DESTINATIONS - {"unknown"}


class ManifestError(ValueError):
    """The manifest is unreadable or describes an impossible destination."""


def parse_manifest(data: Any) -> Destination:
    if not isinstance(data, dict):
        raise ManifestError("manifest must be a JSON object")
    unknown = sorted(set(data) - set(_MANIFEST_KEYS))
    if unknown:
        raise ManifestError(f"unknown manifest field(s): {', '.join(unknown)}")

    channel = data.get("channel", "unknown")
    if channel not in KNOWN_CHANNELS:
        raise ManifestError(f"channel must be one of {', '.join(sorted(KNOWN_CHANNELS))}")

    declared = data.get("destination", [])
    declared = [declared] if isinstance(declared, str) else declared
    if not isinstance(declared, list) or any(item not in KNOWN_DESTINATIONS for item in declared):
        raise ManifestError(
            f"destination must be one or more of {', '.join(sorted(KNOWN_DESTINATIONS))}"
        )

    for field in ("recipient", "domain"):
        if data.get(field) is not None and not isinstance(data[field], str):
            raise ManifestError(f"{field} must be a string")
    recipient = data.get("recipient")
    if recipient is not None and "@" not in recipient:
        raise ManifestError("recipient must be an email address")
    public = data.get("public")
    if public is not None and not isinstance(public, bool):
        raise ManifestError("public must be true or false")

    return Destination(
        channel=channel,
        recipient=recipient,
        domain=data.get("domain"),
        public=public,
        declared=tuple(declared),
    )


def load_manifest(path: Path) -> Destination:
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError(f"manifest is larger than {MAX_MANIFEST_BYTES} bytes")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    return parse_manifest(data)


class LocalDestinationResolver:
    """Works out where a file in the watched tree is headed."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def resolve(self, path: Path) -> Destination:
        # Resolve the folder (it may sit behind symlinks) but never the file itself: a
        # symlinked file must be judged by where the link lives, not by what it points to.
        path = path.absolute()
        path = path.parent.resolve() / path.name
        for manifest in self._manifest_candidates(path):
            if not manifest.is_file():
                continue
            try:
                return load_manifest(manifest)
            except ManifestError as exc:
                logger.warning("ignoring invalid manifest %s: %s", manifest, exc)
        folder = self._folder_category(path)
        return Destination(declared=(folder,)) if folder else Destination()

    def _manifest_candidates(self, path: Path) -> list[Path]:
        """Sidecar first, then ``metadata.json`` from the file's folder up to the watch root."""
        candidates = [path.with_name(path.name + SIDECAR_SUFFIX)]
        directory = path.parent
        while True:
            candidates.append(directory / DIRECTORY_MANIFEST)
            if directory == self.root or self.root not in directory.parents:
                return candidates
            directory = directory.parent

    def _folder_category(self, path: Path) -> str | None:
        try:
            parts = path.relative_to(self.root).parts[:-1]
        except ValueError:
            return None
        return next((part for part in reversed(parts) if part in _FOLDER_CATEGORIES), None)
