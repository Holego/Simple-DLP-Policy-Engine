"""SQLite incident journal for the local mode."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any

from src.incident import Incident

from .base import DEFAULT_QUERY_LIMIT

_SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    timestamp   TEXT NOT NULL,
    mode        TEXT NOT NULL,
    source      TEXT NOT NULL,
    rule        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    payload     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_incidents_severity_ts ON incidents (severity, timestamp);
CREATE INDEX IF NOT EXISTS idx_incidents_ts ON incidents (timestamp);
"""


class SqliteIncidentStore:
    """Thread-safe: every operation uses its own short-lived connection."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        if str(path) != ":memory:":
            self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # closing() releases the file handle; `with conn` commits or rolls back the transaction.
        with closing(sqlite3.connect(self.path, timeout=10)) as conn, conn:
            yield conn

    def add(self, incident: Incident) -> bool:
        data = incident.to_dict()
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT OR IGNORE INTO incidents "
                "(incident_id, timestamp, mode, source, rule, severity, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    data["incident_id"],
                    data["timestamp"],
                    data["mode"],
                    data["source"],
                    data["rule"],
                    data["severity"],
                    json.dumps(data, sort_keys=True),
                ),
            )
            return cursor.rowcount == 1

    def exists(self, incident_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM incidents WHERE incident_id = ?", (incident_id,)
            ).fetchone()
        return row is not None

    def query(
        self,
        *,
        severities: Sequence[str] | None = None,
        since: str | None = None,
        rule: str | None = None,
        limit: int = DEFAULT_QUERY_LIMIT,
    ) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if severities:
            clauses.append(f"severity IN ({', '.join('?' * len(severities))})")
            params.extend(severities)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if rule:
            clauses.append("rule = ?")
            params.append(rule)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT payload FROM incidents {where} ORDER BY timestamp DESC LIMIT ?"
        with self._connect() as conn:
            rows = conn.execute(sql, [*params, limit]).fetchall()
        return [json.loads(row[0]) for row in rows]
