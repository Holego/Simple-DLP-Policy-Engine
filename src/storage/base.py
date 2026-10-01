"""Incident journal interface shared by the SQLite and DynamoDB adapters."""

from __future__ import annotations

import re
from collections.abc import Sequence
from datetime import timedelta
from typing import Any, Protocol

from src.incident import Incident

DEFAULT_QUERY_LIMIT = 100

_DURATION = re.compile(r"^\s*(\d+)\s*([smhdw])\s*$", re.IGNORECASE)
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


def parse_duration(text: str) -> timedelta:
    """Parse ``30m``, ``12h``, ``7d`` or ``2w`` into a timedelta."""
    match = _DURATION.match(text)
    if not match:
        raise ValueError(f"invalid duration {text!r}; use a number and s, m, h, d or w (e.g. 7d)")
    return timedelta(**{_UNITS[match.group(2).lower()]: int(match.group(1))})


class IncidentStore(Protocol):
    def add(self, incident: Incident) -> bool:
        """Persist an incident. Returns False if an incident with the same id already exists."""
        ...

    def exists(self, incident_id: str) -> bool: ...

    def query(
        self,
        *,
        severities: Sequence[str] | None = None,
        since: str | None = None,
        rule: str | None = None,
        limit: int = DEFAULT_QUERY_LIMIT,
    ) -> list[dict[str, Any]]:
        """Incidents newest first, optionally filtered by severity, start time and rule."""
        ...
