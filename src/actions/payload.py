"""The alert message built from one evaluated file."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .base import ActionContext

_SUBJECT_LIMIT = 100


@dataclass(frozen=True, slots=True)
class AlertPayload:
    evaluation_id: str
    timestamp: str
    mode: str
    source: str
    severity: str
    rules: tuple[dict[str, Any], ...]
    actions: tuple[dict[str, str], ...]
    destination: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    file: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "evaluation_id": self.evaluation_id,
            "timestamp": self.timestamp,
            "mode": self.mode,
            "source": self.source,
            "severity": self.severity,
            "rules": [dict(rule) for rule in self.rules],
            "actions": [dict(action) for action in self.actions],
            "destination": dict(self.destination),
            "findings": [dict(finding) for finding in self.findings],
            "file": dict(self.file),
        }

    def title(self) -> str:
        names = ", ".join(rule["name"] for rule in self.rules if not rule.get("suppressed_by"))
        return f"[DLP][{self.severity.upper()}] {names}"

    def subject(self) -> str:
        """Title limited to what an SNS subject allows: ASCII, single line, 100 chars."""
        clean = self.title().encode("ascii", "replace").decode().replace("\n", " ")
        return clean[:_SUBJECT_LIMIT]

    def text(self) -> str:
        """Plain-text message for logs, Slack and Discord. Masked values only."""
        destination = self.destination
        where = ", ".join(destination.get("categories") or []) or "unknown"
        enforcement = ", ".join(
            f"{a['action']} ({a['status']})" if a["status"] != "ok" else a["action"]
            for a in self.actions
        )
        findings = "; ".join(
            f"{f['type']} x{f['count']} ({', '.join(f['samples'])})" for f in self.findings
        )
        suppressed = [r["name"] for r in self.rules if r.get("suppressed_by")]
        lines = [
            self.title(),
            f"source: {self.source}",
            f"destination: {where}",
            f"enforcement: {enforcement or 'none (alert only)'}",
            f"findings: {findings or 'none'}",
        ]
        if suppressed:
            lines.append(f"also matched (overridden by priority): {', '.join(suppressed)}")
        return "\n".join(lines)


def build_alert_payload(ctx: ActionContext) -> AlertPayload:
    decision = ctx.decision
    severity = decision.severity.label if decision.severity else "low"
    return AlertPayload(
        evaluation_id=ctx.evaluation_id,
        timestamp=ctx.timestamp,
        mode=ctx.mode,
        source=ctx.source,
        severity=severity,
        rules=tuple(
            {
                "name": match.rule.name,
                "severity": match.rule.severity.label,
                "suppressed_by": match.suppressed_by,
            }
            for match in decision.matches
        ),
        actions=tuple(result.to_dict() for result in ctx.results),
        destination={**ctx.destination.to_dict(), "categories": sorted(decision.categories)},
        findings=tuple(summary.to_dict() for summary in ctx.summaries.values()),
        file=dict(ctx.file_info),
    )
