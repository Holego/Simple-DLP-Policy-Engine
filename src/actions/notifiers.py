"""Notification channels used by the alert action."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Protocol
from urllib.parse import urlparse

from .payload import AlertPayload

alert_logger = logging.getLogger("dlp.alerts")

DISCORD_LIMIT = 1900
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class Notifier(Protocol):
    name: str

    def send(self, payload: AlertPayload) -> None:
        """Deliver the alert; raise on failure."""
        ...


class LogNotifier:
    """Writes a readable alert line to the ``dlp.alerts`` logger (console, CloudWatch)."""

    name = "log"

    def send(self, payload: AlertPayload) -> None:
        alert_logger.warning("%s", payload.text())


def validate_webhook_url(url: str) -> str:
    """Require https (plain http only for loopback tests) and no embedded credentials."""
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValueError("webhook URL must be an absolute http(s) URL")
    if parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS:
        raise ValueError("webhook URL must use https")
    if parsed.username or parsed.password:
        raise ValueError("webhook URL must not contain credentials")
    return url


def detect_webhook_kind(url: str) -> str:
    host = urlparse(url).hostname or ""
    if host == "hooks.slack.com":
        return "slack"
    if host in {"discord.com", "discordapp.com"} or host.endswith(".discord.com"):
        return "discord"
    return "generic"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A webhook that answers with a redirect is misconfigured; do not follow it blindly."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: D102
        return None


class WebhookNotifier:
    """Posts the alert to an incoming webhook (Slack, Discord or a generic JSON endpoint).

    The URL is a secret (it carries the token), so it never appears in logs or errors.
    """

    name = "webhook"

    def __init__(self, url: str, kind: str = "auto", timeout: float = 5.0) -> None:
        self.url = validate_webhook_url(url)
        self.kind = detect_webhook_kind(url) if kind == "auto" else kind
        if self.kind not in {"slack", "discord", "generic"}:
            raise ValueError(f"unknown webhook kind {kind!r}")
        self.timeout = timeout
        self._opener = urllib.request.build_opener(_NoRedirect)

    def build_body(self, payload: AlertPayload) -> dict[str, Any]:
        if self.kind == "slack":
            return {"text": payload.text()}
        if self.kind == "discord":
            return {"content": payload.text()[:DISCORD_LIMIT]}
        return payload.to_dict()

    def send(self, payload: AlertPayload) -> None:
        request = urllib.request.Request(
            self.url,
            data=json.dumps(self.build_body(payload)).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "dlp-policy-engine"},
            method="POST",
        )
        try:
            with self._opener.open(request, timeout=self.timeout):
                pass
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"webhook returned HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            reason = getattr(exc, "reason", exc)
            raise RuntimeError(f"webhook unreachable ({type(reason).__name__})") from None


class SnsNotifier:
    """Publishes the alert to an SNS topic with the severity as a filterable attribute."""

    name = "sns"

    def __init__(self, client: Any, topic_arn: str) -> None:
        self.client = client
        self.topic_arn = topic_arn

    def send(self, payload: AlertPayload) -> None:
        self.client.publish(
            TopicArn=self.topic_arn,
            Subject=payload.subject(),
            Message=json.dumps(payload.to_dict(), indent=2, sort_keys=True),
            MessageAttributes={
                "severity": {"DataType": "String", "StringValue": payload.severity},
                "mode": {"DataType": "String", "StringValue": payload.mode},
            },
        )
