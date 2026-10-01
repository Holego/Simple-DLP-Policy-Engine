"""Runtime settings read from environment variables (see .env.example)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from src.detectors.scanner import DEFAULT_MAX_SCAN_BYTES

DEFAULT_RETENTION_DAYS = 365


def _int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


def _text(env: Mapping[str, str], name: str) -> str | None:
    return env.get(name, "").strip() or None


@dataclass(frozen=True, slots=True)
class LocalSettings:
    policy_path: Path = Path("config/policies.yaml")
    watch_dir: Path = Path("outbox")
    quarantine_dir: Path = Path("quarantine")
    db_path: Path = Path("data/incidents.db")
    log_file: Path | None = None
    webhook_url: str | None = None
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LocalSettings:
        env = os.environ if env is None else env
        defaults = cls()
        log_file = _text(env, "DLP_LOG_FILE")
        return cls(
            policy_path=Path(_text(env, "DLP_POLICY_PATH") or defaults.policy_path),
            watch_dir=Path(_text(env, "DLP_WATCH_DIR") or defaults.watch_dir),
            quarantine_dir=Path(_text(env, "DLP_QUARANTINE_DIR") or defaults.quarantine_dir),
            db_path=Path(_text(env, "DLP_DB_PATH") or defaults.db_path),
            log_file=Path(log_file) if log_file else None,
            webhook_url=_text(env, "DLP_WEBHOOK_URL"),
            max_scan_bytes=_int(env, "DLP_MAX_SCAN_BYTES", defaults.max_scan_bytes),
        )


@dataclass(frozen=True, slots=True)
class LambdaSettings:
    table_name: str
    sns_topic_arn: str
    quarantine_bucket: str | None = None
    policy_path: str = "policies.yaml"
    webhook_url: str | None = None
    max_scan_bytes: int = DEFAULT_MAX_SCAN_BYTES
    retention_days: int = DEFAULT_RETENTION_DAYS

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> LambdaSettings:
        env = os.environ if env is None else env
        missing = [name for name in ("DLP_TABLE_NAME", "DLP_SNS_TOPIC_ARN") if not _text(env, name)]
        if missing:
            raise RuntimeError(f"missing required environment variables: {', '.join(missing)}")
        return cls(
            table_name=env["DLP_TABLE_NAME"].strip(),
            sns_topic_arn=env["DLP_SNS_TOPIC_ARN"].strip(),
            quarantine_bucket=_text(env, "DLP_QUARANTINE_BUCKET"),
            policy_path=_text(env, "DLP_POLICY_PATH") or cls.policy_path,
            webhook_url=_text(env, "DLP_WEBHOOK_URL"),
            max_scan_bytes=_int(env, "DLP_MAX_SCAN_BYTES", DEFAULT_MAX_SCAN_BYTES),
            retention_days=_int(env, "DLP_RETENTION_DAYS", DEFAULT_RETENTION_DAYS),
        )
