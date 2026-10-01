"""The alert action: build one message per evaluated file and fan it out to notifiers."""

from __future__ import annotations

import logging
from collections.abc import Sequence

from .base import STATUS_FAILED, STATUS_OK, STATUS_PARTIAL, ActionContext, ActionResult
from .notifiers import Notifier
from .payload import build_alert_payload

logger = logging.getLogger(__name__)


class AlertAction:
    """Sends the alert to every notifier. One failing channel does not block the others."""

    name = "alert"

    def __init__(self, notifiers: Sequence[Notifier]) -> None:
        self.notifiers = tuple(notifiers)

    def run(self, ctx: ActionContext) -> ActionResult:
        payload = build_alert_payload(ctx)
        outcomes: list[str] = []
        failures = 0
        for notifier in self.notifiers:
            try:
                notifier.send(payload)
                outcomes.append(f"{notifier.name}:ok")
            except Exception as exc:
                failures += 1
                logger.warning("notifier %s failed: %s", notifier.name, exc)
                outcomes.append(f"{notifier.name}:failed ({exc})")
        if not self.notifiers or failures == len(self.notifiers):
            return ActionResult(self.name, STATUS_FAILED, "; ".join(outcomes) or "no notifiers")
        status = STATUS_PARTIAL if failures else STATUS_OK
        return ActionResult(self.name, status, ", ".join(outcomes))
