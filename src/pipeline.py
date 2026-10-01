"""Event source -> detector -> policy engine -> actions -> incident journal.

Both modes (local watcher, AWS Lambda) feed this same pipeline; they differ only in how
they obtain the bytes and the destination, and in which action handlers they wire in.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.actions.base import ActionContext, ActionExecutor, ActionResult
from src.detectors.scanner import DEFAULT_MAX_SAMPLES, FindingSummary, Scanner, summarize
from src.engine.destination import Destination
from src.engine.engine import PolicyEngine
from src.engine.models import Decision, RuleMatch
from src.incident import Incident, make_evaluation_id, make_incident_id, utc_timestamp
from src.storage.base import IncidentStore

logger = logging.getLogger(__name__)
incident_logger = logging.getLogger("dlp.incident")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True, slots=True)
class PipelineResult:
    findings: Mapping[str, FindingSummary]
    total_findings: int
    decision: Decision
    incidents: tuple[Incident, ...] = ()
    action_results: tuple[ActionResult, ...] = ()
    duplicate: bool = False


class DlpPipeline:
    def __init__(
        self,
        *,
        mode: str,
        scanner: Scanner,
        engine: PolicyEngine,
        executor: ActionExecutor,
        store: IncidentStore,
        clock: Callable[[], datetime] = _utcnow,
        max_samples: int = DEFAULT_MAX_SAMPLES,
    ) -> None:
        self.mode = mode
        self.scanner = scanner
        self.engine = engine
        self.executor = executor
        self.store = store
        self.clock = clock
        self.max_samples = max_samples

    def inspect(self, data: bytes, destination: Destination) -> PipelineResult:
        """Dry run: scan and evaluate without running actions or writing the journal."""
        findings = self.scanner.scan_bytes(data)
        decision = self.engine.evaluate(findings, destination)
        return PipelineResult(summarize(findings, self.max_samples), len(findings), decision)

    def process(
        self,
        data: bytes,
        *,
        source: str,
        destination: Destination,
        target: Any,
        event_key: str,
        file_info: Mapping[str, Any] | None = None,
    ) -> PipelineResult:
        """Scan one file event, apply the winning actions and journal every triggered rule.

        ``event_key`` identifies this particular event (file mtime locally, the S3 event
        sequencer in AWS). The same event delivered twice is recognised and skipped, while
        a new upload of identical content is a new event and is enforced again.
        """
        result = self.inspect(data, destination)
        decision = result.decision
        if not decision.triggered:
            return result

        content_sha = hashlib.sha256(data).hexdigest()
        evaluation_id = make_evaluation_id(source, event_key, content_sha)
        if all(
            self.store.exists(make_incident_id(evaluation_id, match.rule.name))
            for match in decision.matches
        ):
            logger.info("event already processed, skipping: %s", source)
            return PipelineResult(result.findings, result.total_findings, decision, duplicate=True)

        timestamp = utc_timestamp(self.clock())
        info = {**(file_info or {}), "sha256": content_sha, "scanned_bytes": len(data)}
        ctx = ActionContext(
            mode=self.mode,
            source=source,
            target=target,
            destination=destination,
            decision=decision,
            summaries=result.findings,
            evaluation_id=evaluation_id,
            timestamp=timestamp,
            file_info=info,
        )
        action_results = tuple(self.executor.execute(ctx))

        incidents = tuple(self._incident(match, ctx, action_results) for match in decision.matches)
        self._journal(incidents)
        return PipelineResult(
            result.findings,
            result.total_findings,
            decision,
            incidents=incidents,
            action_results=action_results,
        )

    def _incident(
        self, match: RuleMatch, ctx: ActionContext, results: tuple[ActionResult, ...]
    ) -> Incident:
        types = match.matched_types or tuple(ctx.summaries)
        categories = sorted(ctx.decision.categories)
        return Incident(
            incident_id=make_incident_id(ctx.evaluation_id, match.rule.name),
            evaluation_id=ctx.evaluation_id,
            timestamp=ctx.timestamp,
            mode=self.mode,
            source=ctx.source,
            rule=match.rule.name,
            severity=match.rule.severity.label,
            priority=match.rule.priority,
            declared_actions=match.rule.actions,
            effective_actions=ctx.decision.actions,
            suppressed_by=match.suppressed_by,
            # A suppressed rule did not decide anything, so none of the actions are its own.
            action_results=() if match.suppressed else tuple(r.to_dict() for r in results),
            destination={**ctx.destination.to_dict(), "categories": categories},
            findings=tuple(ctx.summaries[t].to_dict() for t in types if t in ctx.summaries),
            file=dict(ctx.file_info),
        )

    def _journal(self, incidents: tuple[Incident, ...]) -> None:
        """Log every incident as JSON first, then store it.

        The log line is the fallback record: if the store is unavailable the incident is
        still in the log, and the error is raised only after every incident was attempted.
        """
        first_error: Exception | None = None
        for incident in incidents:
            incident_logger.info("%s", json.dumps(incident.to_dict(), sort_keys=True))
            try:
                self.store.add(incident)
            except Exception as exc:
                logger.exception("failed to store incident %s", incident.incident_id)
                first_error = first_error or exc
        if first_error is not None:
            raise first_error
