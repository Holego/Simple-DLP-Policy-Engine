"""Action plumbing: context, results, handler protocol and the executor."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol

from src.detectors.scanner import FindingSummary
from src.engine.destination import Destination
from src.engine.models import Decision

logger = logging.getLogger(__name__)

STATUS_OK = "ok"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class ActionResult:
    action: str
    status: str
    detail: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"action": self.action, "status": self.status, "detail": self.detail}


@dataclass
class ActionContext:
    """Everything an action handler needs to know about one evaluated file."""

    mode: str
    source: str
    target: Any  # what to act on: a pathlib.Path (local) or an S3Object (AWS)
    destination: Destination
    decision: Decision
    summaries: Mapping[str, FindingSummary]
    evaluation_id: str
    timestamp: str
    file_info: Mapping[str, Any] = field(default_factory=dict)
    results: list[ActionResult] = field(default_factory=list)  # results of earlier actions


class ActionHandler(Protocol):
    name: str

    def run(self, ctx: ActionContext) -> ActionResult: ...


class ActionExecutor:
    """Runs the actions of a decision in order, isolating failures between them.

    The decision lists the disposition (quarantine/block) before ``alert``, so the alert
    can report whether enforcement worked. A failing handler never stops the others.
    """

    def __init__(self, handlers: Iterable[ActionHandler]) -> None:
        self.handlers: dict[str, ActionHandler] = {handler.name: handler for handler in handlers}

    def execute(self, ctx: ActionContext) -> list[ActionResult]:
        for action in ctx.decision.actions:
            handler = self.handlers.get(action)
            if handler is None:
                result = ActionResult(action, STATUS_SKIPPED, "no handler configured")
            else:
                try:
                    result = handler.run(ctx)
                except Exception as exc:
                    logger.exception("action %s failed for %s", action, ctx.source)
                    result = ActionResult(action, STATUS_FAILED, f"{type(exc).__name__}: {exc}")
            ctx.results.append(result)
        return list(ctx.results)
