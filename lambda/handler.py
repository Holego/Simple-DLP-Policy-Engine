"""AWS Lambda entrypoint: S3 ObjectCreated event -> scan -> policy -> actions -> journal.

Configuration comes from environment variables set by infra/terraform:

* DLP_TABLE_NAME        DynamoDB table for the incident journal (required)
* DLP_SNS_TOPIC_ARN     SNS topic for alerts (required)
* DLP_QUARANTINE_BUCKET bucket that receives quarantined objects; without it the
                        quarantine action blocks the object in place instead
* DLP_POLICY_PATH       policy file, relative to this file (default: policies.yaml)
* DLP_WEBHOOK_URL       optional Slack/Discord/generic webhook for alerts
* DLP_MAX_SCAN_BYTES    scan at most this many bytes per object (default 10 MiB)
* DLP_RETENTION_DAYS    TTL of journal items; 0 keeps them forever (default 365)
* LOG_LEVEL             logging level (default INFO)
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import boto3

from src.actions import (
    ActionExecutor,
    AlertAction,
    LogNotifier,
    Notifier,
    S3Block,
    S3InPlaceQuarantine,
    S3Quarantine,
    SnsNotifier,
    WebhookNotifier,
)
from src.actions.targets import S3Object
from src.detectors import Scanner
from src.engine import PolicyEngine
from src.incident import MODE_AWS
from src.pipeline import DlpPipeline
from src.settings import LambdaSettings
from src.storage.dynamodb_store import DynamoDbIncidentStore
from src.watchers.s3 import S3DestinationResolver, fetch_object, parse_s3_event

logger = logging.getLogger("dlp.lambda")


class ProcessingError(RuntimeError):
    """Raised after the whole event was attempted, so Lambda retries and then dead-letters it."""


@dataclass
class Runtime:
    settings: LambdaSettings
    s3: Any
    resolver: S3DestinationResolver
    pipeline: DlpPipeline

    def process(self, obj: S3Object) -> str:
        """Handle one object. Returns ``scanned:<incidents>`` or ``skipped: <reason>``."""
        if obj.bucket == self.settings.quarantine_bucket:
            return "skipped: quarantine bucket"
        if obj.key.endswith("/"):
            return "skipped: folder placeholder"
        fetched = fetch_object(self.s3, obj, self.settings.max_scan_bytes)
        if fetched is None:
            return "skipped: object no longer exists"
        data, truncated = fetched

        result = self.pipeline.process(
            data,
            source=obj.uri,
            destination=self.resolver.resolve(obj),
            target=obj,
            event_key=obj.sequencer or obj.version_id or obj.etag or "",
            file_info={
                "name": obj.key.rsplit("/", 1)[-1],
                "size": obj.size if obj.size is not None else len(data),
                "truncated": truncated,
            },
        )
        if result.duplicate:
            return "skipped: event already processed"
        return f"scanned:{len(result.incidents)}"


def _policy_path(setting: str) -> Path:
    path = Path(setting)
    return path if path.is_absolute() else Path(__file__).resolve().parent / path


def build_runtime(
    env: dict[str, str] | None = None,
    *,
    s3_client: Any = None,
    sns_client: Any = None,
    dynamodb_resource: Any = None,
) -> Runtime:
    settings = LambdaSettings.from_env(env)
    s3 = s3_client or boto3.client("s3")
    sns = sns_client or boto3.client("sns")

    notifiers: list[Notifier] = [LogNotifier(), SnsNotifier(sns, settings.sns_topic_arn)]
    if settings.webhook_url:
        notifiers.append(WebhookNotifier(settings.webhook_url))
    quarantine = (
        S3Quarantine(s3, settings.quarantine_bucket)
        if settings.quarantine_bucket
        else S3InPlaceQuarantine(s3)
    )
    pipeline = DlpPipeline(
        mode=MODE_AWS,
        scanner=Scanner(),
        engine=PolicyEngine.from_file(_policy_path(settings.policy_path)),
        executor=ActionExecutor([AlertAction(notifiers), quarantine, S3Block(s3)]),
        store=DynamoDbIncidentStore.from_table_name(
            settings.table_name,
            retention_days=settings.retention_days,
            resource=dynamodb_resource,
        ),
    )
    return Runtime(settings, s3, S3DestinationResolver(s3), pipeline)


_runtime: Runtime | None = None


def get_runtime() -> Runtime:
    """Build the runtime on the first invocation and reuse it while the container is warm."""
    global _runtime
    if _runtime is None:
        # The Lambda runtime installs a root handler but leaves the level at WARNING.
        logging.getLogger().setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
        _runtime = build_runtime()
    return _runtime


def reset_runtime() -> None:
    global _runtime
    _runtime = None


def lambda_handler(event: dict[str, Any], context: Any = None) -> dict[str, Any]:
    runtime = get_runtime()
    objects = parse_s3_event(event)
    summary: dict[str, Any] = {"objects": len(objects), "scanned": 0, "incidents": 0, "skipped": 0}
    failed: list[str] = []

    for obj in objects:
        try:
            outcome = runtime.process(obj)
        except Exception:
            logger.exception("failed to process %s", obj.uri)
            failed.append(obj.uri)
            continue
        if outcome.startswith("scanned"):
            summary["scanned"] += 1
            summary["incidents"] += int(outcome.partition(":")[2])
        else:
            summary["skipped"] += 1
        logger.info("%s -> %s", obj.uri, outcome)

    if failed:
        raise ProcessingError(
            f"{len(failed)} of {len(objects)} objects failed: {', '.join(failed)}"
        )
    logger.info("summary %s", summary)
    return summary
