"""Quarantine: move the file somewhere it cannot be sent from, keeping evidence."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from urllib.parse import urlencode

from .base import ActionContext, ActionResult
from .payload import build_alert_payload
from .targets import STATUS_QUARANTINED, TAG_EVALUATION, TAG_SEVERITY, TAG_STATUS, S3Object

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
MANIFEST_SUFFIX = ".meta.json"
EVIDENCE_SUFFIX = ".incident.json"


def _safe_name(name: str) -> str:
    return _UNSAFE.sub("_", name).lstrip(".")[:120] or "file"


class LocalQuarantine:
    """Moves the file (and its manifest) into a private quarantine folder.

    A small ``.incident.json`` with the masked evidence is written next to the quarantined
    file so a reviewer can decide what to do without opening the data itself.
    """

    name = "quarantine"

    def __init__(self, quarantine_dir: str | Path) -> None:
        self.directory = Path(quarantine_dir)

    def run(self, ctx: ActionContext) -> ActionResult:
        source: Path = ctx.target
        self.directory.mkdir(parents=True, exist_ok=True)
        os.chmod(self.directory, 0o700)

        stamp = ctx.timestamp.replace(":", "").replace("-", "").replace(".", "")
        destination = self.directory / f"{stamp}_{ctx.evaluation_id[:8]}_{_safe_name(source.name)}"
        manifest = source.with_name(source.name + MANIFEST_SUFFIX)

        shutil.move(str(source), destination)
        os.chmod(destination, 0o600)
        if manifest.is_file():
            shutil.move(str(manifest), destination.with_name(destination.name + MANIFEST_SUFFIX))

        evidence = destination.with_name(destination.name + EVIDENCE_SUFFIX)
        evidence.write_text(
            json.dumps(build_alert_payload(ctx).to_dict(), indent=2, sort_keys=True) + "\n"
        )
        os.chmod(evidence, 0o600)
        return ActionResult(self.name, "ok", f"moved to {destination}")


class S3Quarantine:
    """Copies the object into the quarantine bucket, then deletes the original.

    The copy is verified by S3 before the source is removed, so a failed copy never loses
    data. Delete targets the exact version when the event carries one.
    """

    name = "quarantine"

    def __init__(self, client: object, bucket: str) -> None:
        self.client = client
        self.bucket = bucket

    def run(self, ctx: ActionContext) -> ActionResult:
        obj: S3Object = ctx.target
        destination_key = f"{obj.bucket}/{obj.key}"
        severity = ctx.decision.severity.label if ctx.decision.severity else "unknown"
        tagging = urlencode(
            {
                TAG_STATUS: STATUS_QUARANTINED,
                TAG_EVALUATION: ctx.evaluation_id,
                TAG_SEVERITY: severity,
            }
        )
        self.client.copy(
            obj.location(),
            self.bucket,
            destination_key,
            ExtraArgs={"Tagging": tagging, "TaggingDirective": "REPLACE"},
        )
        self.client.delete_object(**obj.location())
        return ActionResult(self.name, "ok", f"moved to s3://{self.bucket}/{destination_key}")
