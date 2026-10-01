import logging

import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws

from src.actions.targets import S3Object
from src.watchers.s3 import (
    S3DestinationResolver,
    fetch_object,
    parse_destination_tag,
    parse_s3_event,
)


def record(key="reports/a.csv", name="ObjectCreated:Put", source="aws:s3", **object_fields):
    return {
        "eventSource": source,
        "eventName": name,
        "s3": {"bucket": {"name": "outbound"}, "object": {"key": key, **object_fields}},
    }


class TestParseEvent:
    def test_extracts_object_details(self):
        event = {
            "Records": [
                record(
                    "reports/q1.csv",
                    size=12,
                    versionId="v1",
                    sequencer="0A1B",
                    eTag="abc",
                )
            ]
        }
        (obj,) = parse_s3_event(event)
        assert obj == S3Object("outbound", "reports/q1.csv", "v1", 12, "0A1B", "abc")
        assert obj.uri == "s3://outbound/reports/q1.csv"

    def test_keys_are_url_decoded(self):
        (obj,) = parse_s3_event({"Records": [record("my+file%2B1%20%C3%A9.csv")]})
        assert obj.key == "my file+1 é.csv"

    def test_only_object_created_events_are_returned(self):
        names = ["ObjectCreated:Put", "ObjectCreated:CompleteMultipartUpload", "ObjectCreated:Copy"]
        removed = record(name="ObjectRemoved:Delete")
        tagging = record(name="ObjectTagging:Put")
        events = {"Records": [record(name=n) for n in names] + [removed, tagging]}
        assert len(parse_s3_event(events)) == 3

    def test_other_event_sources_and_garbage_are_ignored(self, caplog):
        events = {"Records": [record(source="aws:sqs"), {"eventSource": "aws:s3"}, {}, "nonsense"]}
        events["Records"][1]["eventName"] = "ObjectCreated:Put"
        with caplog.at_level(logging.WARNING):
            assert parse_s3_event(events) == []
        assert "malformed" in caplog.text

    @pytest.mark.parametrize("event", [{}, {"Records": None}, {"Records": []}])
    def test_empty_events(self, event):
        assert parse_s3_event(event) == []


class TestDestinationTag:
    def test_single_and_multiple_categories(self):
        assert parse_destination_tag("external_email") == ("external_email",)
        assert parse_destination_tag("external_email+non_corporate_domain") == (
            "external_email",
            "non_corporate_domain",
        )

    def test_unknown_values_are_dropped_with_a_warning(self, caplog):
        with caplog.at_level(logging.WARNING):
            assert parse_destination_tag("external_email+mars") == ("external_email",)
        assert "mars" in caplog.text

    @pytest.mark.parametrize("value", [None, "", "+", " "])
    def test_empty_values(self, value):
        assert parse_destination_tag(value) == ()


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3")
        client.create_bucket(Bucket="outbound")
        yield client


class TestFetchObject:
    def test_reads_the_whole_object(self, s3):
        s3.put_object(Bucket="outbound", Key="k", Body=b"hello")
        assert fetch_object(s3, S3Object("outbound", "k"), 100) == (b"hello", False)

    def test_reads_only_up_to_the_limit_and_says_so(self, s3):
        s3.put_object(Bucket="outbound", Key="k", Body=b"x" * 1000)
        data, truncated = fetch_object(s3, S3Object("outbound", "k"), 100)
        assert len(data) == 100 and truncated

    def test_exact_limit_is_not_truncated(self, s3):
        s3.put_object(Bucket="outbound", Key="k", Body=b"x" * 100)
        assert fetch_object(s3, S3Object("outbound", "k"), 100) == (b"x" * 100, False)

    def test_missing_object_returns_none(self, s3):
        assert fetch_object(s3, S3Object("outbound", "nope"), 100) is None

    def test_known_empty_object_is_not_fetched(self):
        class Exploding:
            def get_object(self, **_):
                raise AssertionError("must not be called")

        assert fetch_object(Exploding(), S3Object("b", "k", size=0), 10) == (b"", False)

    def test_specific_versions_are_requested(self, s3):
        s3.put_bucket_versioning(Bucket="outbound", VersioningConfiguration={"Status": "Enabled"})
        first = s3.put_object(Bucket="outbound", Key="k", Body=b"one")["VersionId"]
        s3.put_object(Bucket="outbound", Key="k", Body=b"two")
        data, _ = fetch_object(s3, S3Object("outbound", "k", version_id=first), 10)
        assert data == b"one"

    def test_other_errors_propagate(self):
        class Denied:
            def get_object(self, **_):
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObject")

        with pytest.raises(ClientError):
            fetch_object(Denied(), S3Object("b", "k"), 10)


class FakeS3:
    """Programmable stand-in for the bucket-exposure calls moto does not implement."""

    def __init__(self, acl=None, policy_public=False, block=None, errors=()):
        self.acl, self.policy_public, self.block, self.errors = (
            acl or [],
            policy_public,
            block,
            errors,
        )
        self.calls = []

    def _maybe_fail(self, name, op):
        self.calls.append(op)
        if name in self.errors:
            raise ClientError({"Error": {"Code": "AccessDenied"}}, op)

    def get_bucket_acl(self, Bucket):
        self._maybe_fail("acl", "GetBucketAcl")
        return {"Grants": self.acl}

    def get_bucket_policy_status(self, Bucket):
        self._maybe_fail("policy", "GetBucketPolicyStatus")
        return {"PolicyStatus": {"IsPublic": self.policy_public}}

    def get_public_access_block(self, Bucket):
        self._maybe_fail("block", "GetPublicAccessBlock")
        if self.block is None:
            raise ClientError(
                {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}, "GetPublicAccessBlock"
            )
        return {"PublicAccessBlockConfiguration": self.block}


ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def grant(uri, permission="READ"):
    return {"Grantee": {"Type": "Group", "URI": uri}, "Permission": permission}


class TestBucketExposure:
    def test_private_bucket(self):
        assert S3DestinationResolver(FakeS3()).bucket_is_public("b") is False

    @pytest.mark.parametrize("uri", [ALL_USERS, AUTH_USERS])
    @pytest.mark.parametrize("permission", ["READ", "FULL_CONTROL"])
    def test_public_read_acl(self, uri, permission):
        resolver = S3DestinationResolver(FakeS3(acl=[grant(uri, permission)]))
        assert resolver.bucket_is_public("b") is True

    def test_public_write_only_acl_does_not_expose_reads(self):
        resolver = S3DestinationResolver(FakeS3(acl=[grant(ALL_USERS, "WRITE")]))
        assert resolver.bucket_is_public("b") is False

    def test_acl_for_a_specific_user_is_not_public(self):
        owner = {"Grantee": {"Type": "CanonicalUser", "ID": "abc"}, "Permission": "FULL_CONTROL"}
        assert S3DestinationResolver(FakeS3(acl=[owner])).bucket_is_public("b") is False

    def test_public_bucket_policy(self):
        assert S3DestinationResolver(FakeS3(policy_public=True)).bucket_is_public("b") is True

    def test_ignore_public_acls_neutralises_public_grants(self):
        fake = FakeS3(acl=[grant(ALL_USERS)], block={"IgnorePublicAcls": True})
        assert S3DestinationResolver(fake).bucket_is_public("b") is False

    def test_restrict_public_buckets_neutralises_a_public_policy(self):
        fake = FakeS3(policy_public=True, block={"RestrictPublicBuckets": True})
        assert S3DestinationResolver(fake).bucket_is_public("b") is False

    def test_public_access_block_does_not_hide_the_other_exposure(self):
        fake = FakeS3(acl=[grant(ALL_USERS)], block={"RestrictPublicBuckets": True})
        assert S3DestinationResolver(fake).bucket_is_public("b") is True

    def test_unknown_when_the_checks_are_denied(self, caplog):
        with caplog.at_level(logging.WARNING):
            fake = FakeS3(errors=("acl", "policy"))
            assert S3DestinationResolver(fake).bucket_is_public("b") is None
        assert "AccessDenied" in caplog.text

    def test_a_visible_exposure_wins_over_a_denied_check(self):
        fake = FakeS3(acl=[grant(ALL_USERS)], errors=("policy",))
        assert S3DestinationResolver(fake).bucket_is_public("b") is True

    def test_one_denied_check_and_no_exposure_is_unknown(self):
        assert S3DestinationResolver(FakeS3(errors=("acl",))).bucket_is_public("b") is None

    def test_results_are_cached_for_a_short_time(self):
        now = [100.0]
        fake = FakeS3()
        resolver = S3DestinationResolver(fake, cache_seconds=60, clock=lambda: now[0])
        resolver.bucket_is_public("b")
        calls = len(fake.calls)
        now[0] += 59
        resolver.bucket_is_public("b")
        assert len(fake.calls) == calls
        now[0] += 2
        resolver.bucket_is_public("b")
        assert len(fake.calls) == 2 * calls

    def test_exposure_is_cached_per_bucket(self):
        fake = FakeS3()
        resolver = S3DestinationResolver(fake)
        resolver.bucket_is_public("one")
        resolver.bucket_is_public("two")
        assert len(fake.calls) == 6


class TestResolveWithMoto:
    def test_tags_and_exposure_become_a_destination(self, s3):
        s3.put_object(
            Bucket="outbound",
            Key="a b.csv",
            Body=b"x",
            Tagging="dlp-destination=external_email&dlp-recipient=buyer@vendor.example",
        )
        destination = S3DestinationResolver(s3).resolve(S3Object("outbound", "a b.csv"))
        assert destination.channel == "s3" and destination.public is False
        assert destination.recipient == "buyer@vendor.example"
        assert destination.declared == ("external_email",)
        categories = destination.categories(("corp.example.com",))
        assert categories == {"external_email", "private_s3", "non_corporate_domain"}

    def test_public_acl_bucket_is_detected(self, s3):
        s3.create_bucket(Bucket="open", ACL="public-read")
        s3.put_object(Bucket="open", Key="k", Body=b"x")
        destination = S3DestinationResolver(s3).resolve(S3Object("open", "k"))
        assert destination.public is True
        assert destination.categories() == {"public_s3"}

    def test_public_access_block_overrides_a_public_acl(self, s3):
        s3.create_bucket(Bucket="open", ACL="public-read")
        s3.put_public_access_block(
            Bucket="open",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        s3.put_object(Bucket="open", Key="k", Body=b"x")
        assert S3DestinationResolver(s3).resolve(S3Object("open", "k")).public is False

    def test_unreadable_tags_do_not_stop_the_resolution(self, caplog):
        class NoTags(FakeS3):
            def get_object_tagging(self, **_):
                raise ClientError({"Error": {"Code": "AccessDenied"}}, "GetObjectTagging")

        with caplog.at_level(logging.ERROR):
            destination = S3DestinationResolver(NoTags()).resolve(S3Object("b", "k"))
        assert destination.declared == () and destination.public is False
        assert "cannot read tags" in caplog.text
