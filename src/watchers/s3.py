"""AWS mode event source: S3 ObjectCreated notifications.

The destination of an object is derived from two things, since a real "where is this going"
signal does not exist for data that is already in S3:

* object tags set by the sender: ``dlp-destination`` (one or more categories joined with
  ``+``, because S3 tag values cannot contain commas) and ``dlp-recipient``
* the exposure of the bucket the object landed in: public ACL grants, a public bucket
  policy, and the account's Block Public Access settings
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable, Mapping
from typing import Any
from urllib.parse import unquote_plus

from botocore.exceptions import ClientError

from src.actions.targets import TAG_DESTINATION, TAG_RECIPIENT, S3Object
from src.engine.destination import KNOWN_DESTINATIONS, Destination

logger = logging.getLogger(__name__)

PUBLIC_GRANTEE_URIS = frozenset(
    {
        "http://acs.amazonaws.com/groups/global/AllUsers",
        "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
    }
)
_READABLE_PERMISSIONS = frozenset({"READ", "FULL_CONTROL"})
_MISSING_KEY_CODES = frozenset({"NoSuchKey", "404", "NotFound"})
DESTINATION_TAG_SEPARATOR = "+"


def parse_s3_event(event: Mapping[str, Any]) -> list[S3Object]:
    """Objects created according to an S3 notification. Other record types are ignored."""
    objects: list[S3Object] = []
    for record in event.get("Records") or []:
        if not isinstance(record, Mapping):
            logger.warning("skipping malformed S3 event record")
            continue
        if record.get("eventSource") != "aws:s3":
            continue
        if not str(record.get("eventName", "")).startswith("ObjectCreated:"):
            continue
        try:
            entity = record["s3"]
            raw = entity["object"]
            objects.append(
                S3Object(
                    bucket=entity["bucket"]["name"],
                    key=unquote_plus(raw["key"]),  # S3 sends keys URL-encoded, "+" for space
                    version_id=raw.get("versionId"),
                    size=raw.get("size"),
                    sequencer=raw.get("sequencer"),
                    etag=raw.get("eTag"),
                )
            )
        except (KeyError, TypeError):
            logger.warning("skipping malformed S3 event record")
    return objects


def fetch_object(client: Any, obj: S3Object, max_bytes: int) -> tuple[bytes, bool] | None:
    """Read up to ``max_bytes`` of the object. None if it no longer exists."""
    if obj.size == 0:
        return b"", False
    try:
        response = client.get_object(**obj.location())
    except ClientError as exc:
        if exc.response["Error"]["Code"] in _MISSING_KEY_CODES:
            return None
        raise
    body = response["Body"]
    try:
        data = body.read(max_bytes + 1)
    finally:
        body.close()
    return data[:max_bytes], len(data) > max_bytes


def parse_destination_tag(value: str | None) -> tuple[str, ...]:
    """``external_email+non_corporate_domain`` -> known categories; others are ignored."""
    if not value:
        return ()
    found: list[str] = []
    for part in value.split(DESTINATION_TAG_SEPARATOR):
        category = part.strip()
        if category in KNOWN_DESTINATIONS:
            found.append(category)
        elif category:
            logger.warning("ignoring unknown %s value %r", TAG_DESTINATION, category)
    return tuple(found)


class S3DestinationResolver:
    """Turns object tags and bucket exposure into a ``Destination``."""

    def __init__(
        self,
        client: Any,
        *,
        cache_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.client = client
        self.cache_seconds = cache_seconds
        self.clock = clock
        self._exposure: dict[str, tuple[float, bool | None]] = {}

    def resolve(self, obj: S3Object) -> Destination:
        tags = self._tags(obj)
        return Destination(
            channel="s3",
            recipient=tags.get(TAG_RECIPIENT),
            public=self.bucket_is_public(obj.bucket),
            declared=parse_destination_tag(tags.get(TAG_DESTINATION)),
        )

    def _tags(self, obj: S3Object) -> dict[str, str]:
        try:
            response = self.client.get_object_tagging(**obj.location())
        except ClientError as exc:
            logger.error("cannot read tags of %s: %s", obj.uri, exc.response["Error"]["Code"])
            return {}
        return {tag["Key"]: tag["Value"] for tag in response.get("TagSet", [])}

    def bucket_is_public(self, bucket: str) -> bool | None:
        """True if the bucket is publicly readable, False if not, None if it cannot be told."""
        now = self.clock()
        cached = self._exposure.get(bucket)
        if cached and cached[0] > now:
            return cached[1]
        result = self._check_exposure(bucket)
        self._exposure[bucket] = (now + self.cache_seconds, result)
        return result

    def _check_exposure(self, bucket: str) -> bool | None:
        block = self._public_access_block(bucket)
        ignore_acls = bool(block and block.get("IgnorePublicAcls"))
        restrict_policy = bool(block and block.get("RestrictPublicBuckets"))

        acl_public = False if ignore_acls else self._acl_is_public(bucket)
        policy_public = False if restrict_policy else self._policy_is_public(bucket)
        if acl_public or policy_public:
            return True
        if acl_public is None or policy_public is None:
            return None
        return False

    def _public_access_block(self, bucket: str) -> Mapping[str, bool] | None:
        try:
            response = self.client.get_public_access_block(Bucket=bucket)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "NoSuchPublicAccessBlockConfiguration":
                logger.warning("cannot read public access block of %s: %s", bucket, code)
            return None
        return response.get("PublicAccessBlockConfiguration", {})

    def _acl_is_public(self, bucket: str) -> bool | None:
        try:
            grants = self.client.get_bucket_acl(Bucket=bucket).get("Grants", [])
        except ClientError as exc:
            logger.warning("cannot read ACL of %s: %s", bucket, exc.response["Error"]["Code"])
            return None
        return any(
            grant.get("Grantee", {}).get("URI") in PUBLIC_GRANTEE_URIS
            and grant.get("Permission") in _READABLE_PERMISSIONS
            for grant in grants
        )

    def _policy_is_public(self, bucket: str) -> bool | None:
        try:
            status = self.client.get_bucket_policy_status(Bucket=bucket)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucketPolicy":
                return False
            logger.warning("cannot read policy status of %s: %s", bucket, code)
            return None
        return bool(status.get("PolicyStatus", {}).get("IsPublic"))
