"""Block: stop further handling of the file.

Locally this is a simulation of a gateway refusing to forward the file. In AWS the Lambda
runs after the object already exists, so blocking means tagging it ``dlp-status=blocked``;
the bucket policy in infra/terraform denies reads of objects carrying that tag.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from .base import ActionContext, ActionResult
from .payload import build_alert_payload
from .targets import STATUS_BLOCKED, TAG_EVALUATION, TAG_SEVERITY, TAG_STATUS, S3Object

BLOCK_MARKER_SUFFIX = ".dlp-blocked"


def marker_path(path: Path) -> Path:
    return path.with_name(path.name + BLOCK_MARKER_SUFFIX)


def is_blocked(path: Path) -> bool:
    """True if a block marker exists for ``path``. Gateways and watchers honour it."""
    return marker_path(path).exists()


class LocalBlock:
    """Leaves the file in place, withdraws all access to it and records why.

    Release a file by deleting its ``.dlp-blocked`` marker and restoring its permissions.
    """

    name = "block"

    def run(self, ctx: ActionContext) -> ActionResult:
        path: Path = ctx.target
        marker = marker_path(path)
        marker.write_text(
            json.dumps(build_alert_payload(ctx).to_dict(), indent=2, sort_keys=True) + "\n"
        )
        os.chmod(marker, 0o600)
        os.chmod(path, 0o000)
        return ActionResult(self.name, "ok", f"access denied; marker {marker.name}")


class S3Block:
    """Tags the object as blocked, keeping its other tags (put_object_tagging replaces all)."""

    name = "block"

    def __init__(self, client: object) -> None:
        self.client = client

    def run(self, ctx: ActionContext) -> ActionResult:
        obj: S3Object = ctx.target
        current = self.client.get_object_tagging(**obj.location())["TagSet"]
        tags = {tag["Key"]: tag["Value"] for tag in current}
        tags[TAG_STATUS] = STATUS_BLOCKED
        tags[TAG_EVALUATION] = ctx.evaluation_id
        tags[TAG_SEVERITY] = ctx.decision.severity.label if ctx.decision.severity else "unknown"
        self.client.put_object_tagging(
            **obj.location(),
            Tagging={"TagSet": [{"Key": key, "Value": value} for key, value in tags.items()]},
        )
        return ActionResult(self.name, "ok", f"tagged {TAG_STATUS}={STATUS_BLOCKED}")


class S3InPlaceQuarantine(S3Block):
    """Stands in for ``quarantine`` when no quarantine bucket is configured.

    The object cannot be moved, so it is blocked in place instead: tagged and, through the
    bucket policy, unreadable for everyone except the DLP function.
    """

    name = "quarantine"

    def run(self, ctx: ActionContext) -> ActionResult:
        result = super().run(ctx)
        return ActionResult(
            self.name,
            result.status,
            f"no quarantine bucket configured; blocked in place ({result.detail})",
        )
