"""Descriptions of what an action operates on, and the S3 tag vocabulary."""

from __future__ import annotations

from dataclasses import dataclass

# Tags a sender (or an upstream system) sets on an object to describe where it is going.
TAG_DESTINATION = "dlp-destination"  # one category, or several joined with "+"
TAG_RECIPIENT = "dlp-recipient"  # recipient email address, if any

# Tags the DLP engine sets on objects it has acted on.
TAG_STATUS = "dlp-status"  # "blocked" or "quarantined"
TAG_EVALUATION = "dlp-evaluation"
TAG_SEVERITY = "dlp-severity"

STATUS_BLOCKED = "blocked"
STATUS_QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class S3Object:
    bucket: str
    key: str
    version_id: str | None = None
    size: int | None = None
    sequencer: str | None = None
    etag: str | None = None

    @property
    def uri(self) -> str:
        return f"s3://{self.bucket}/{self.key}"

    def location(self) -> dict[str, str]:
        """Keyword arguments identifying this exact object (and version) in S3 calls."""
        args = {"Bucket": self.bucket, "Key": self.key}
        if self.version_id:
            args["VersionId"] = self.version_id
        return args
