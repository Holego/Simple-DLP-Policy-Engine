"""The structured incident event written to the journal and the log."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

MODE_LOCAL = "local"
MODE_AWS = "aws"


def utc_timestamp(moment: datetime | None = None) -> str:
    """ISO 8601 UTC with millisecond precision; sorts lexicographically by time."""
    moment = (moment or datetime.now(timezone.utc)).astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def timestamp_before(delta: timedelta, now: datetime | None = None) -> str:
    return utc_timestamp((now or datetime.now(timezone.utc)) - delta)


def sha256_hex(*parts: str | bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode() if isinstance(part, str) else part)
        digest.update(b"\0")
    return digest.hexdigest()


def make_evaluation_id(source: str, event_key: str, content_sha256: str) -> str:
    """Stable id of one file event: a replay of the same event maps to the same id."""
    return sha256_hex(source, event_key, content_sha256)[:16]


def make_incident_id(evaluation_id: str, rule: str) -> str:
    return sha256_hex(evaluation_id, rule)[:32]


@dataclass(frozen=True, slots=True)
class Incident:
    """One triggered rule for one file event. Contains masked findings only."""

    incident_id: str
    evaluation_id: str
    timestamp: str
    mode: str
    source: str
    rule: str
    severity: str
    priority: int
    declared_actions: tuple[str, ...]
    effective_actions: tuple[str, ...]
    suppressed_by: str | None
    action_results: tuple[Mapping[str, Any], ...]
    destination: Mapping[str, Any]
    findings: tuple[Mapping[str, Any], ...]
    file: Mapping[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable form: plain str/int/bool/None, lists and dicts (no floats)."""
        return {
            "incident_id": self.incident_id,
            "evaluation_id": self.evaluation_id,
            "timestamp": self.timestamp,
            "mode": self.mode,
            "source": self.source,
            "rule": self.rule,
            "severity": self.severity,
            "priority": self.priority,
            "declared_actions": list(self.declared_actions),
            "effective_actions": list(self.effective_actions),
            "suppressed_by": self.suppressed_by,
            "action_results": [dict(result) for result in self.action_results],
            "destination": dict(self.destination),
            "findings": [dict(finding) for finding in self.findings],
            "file": dict(self.file),
        }


def describe_actions(incident: Mapping[str, Any]) -> str:
    """Short text such as ``quarantine:ok, alert:ok`` for tables and messages."""
    results: Sequence[Mapping[str, Any]] = incident.get("action_results") or []
    if not results:
        return "none (suppressed)" if incident.get("suppressed_by") else "none"
    return ", ".join(f"{r['action']}:{r['status']}" for r in results)
