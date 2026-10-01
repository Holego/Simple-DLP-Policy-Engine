"""The Lambda entrypoint against moto: S3, DynamoDB, SNS (+SQS to read alerts). No real AWS."""

import importlib.util
import json
import logging
import sys
from types import SimpleNamespace
from urllib.parse import quote_plus

import boto3
import pytest
from moto import mock_aws

from src.storage.dynamodb_store import create_incident_table
from tests.conftest import EXAMPLE_POLICY, REPO_ROOT
from tests.test_actions import WebhookServer

spec = importlib.util.spec_from_file_location("dlp_lambda_handler", REPO_ROOT / "lambda/handler.py")
handler = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = handler  # dataclasses look the module up while it is being executed
spec.loader.exec_module(handler)

SOURCE_BUCKET = "outbound"
QUARANTINE_BUCKET = "quarantine"
TABLE = "dlp-incidents"
EXTERNAL = "dlp-destination=external_email&dlp-recipient=buyer@vendor.example"


def s3_event(*objects, name="ObjectCreated:Put"):
    """An S3 notification; each object is (bucket, key[, sequencer])."""
    records = []
    for index, (bucket, key, *rest) in enumerate(objects):
        sequencer = rest[0] if rest else f"00{index:04d}"
        records.append(
            {
                "eventSource": "aws:s3",
                "eventName": name,
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": quote_plus(key), "sequencer": sequencer},
                },
            }
        )
    return {"Records": records}


class Aws:
    def __init__(self, runtime_env):
        self.s3 = boto3.client("s3")
        self.sns = boto3.client("sns")
        self.sqs = boto3.client("sqs")
        self.ddb = boto3.client("dynamodb")
        self.env = runtime_env
        self._uploads = 0

    def put(self, key, body, tags=None, bucket=SOURCE_BUCKET):
        kwargs = {"Tagging": tags} if tags else {}
        self.s3.put_object(Bucket=bucket, Key=key, Body=body.encode(), **kwargs)
        self._uploads += 1  # S3 gives every upload its own sequencer
        return s3_event((bucket, key, f"SEQ{self._uploads:06d}"))

    def keys(self, bucket):
        listing = self.s3.list_objects_v2(Bucket=bucket)
        return sorted(item["Key"] for item in listing.get("Contents", []))

    def tags(self, bucket, key):
        tagset = self.s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
        return {tag["Key"]: tag["Value"] for tag in tagset}

    def items(self):
        return self.ddb.scan(TableName=TABLE)["Items"]

    def alerts(self):
        messages = self.sqs.receive_message(QueueUrl=self.queue_url, MaxNumberOfMessages=10)
        return [json.loads(m["Body"]) for m in messages.get("Messages", [])]


def build_aws(extra_env=None, with_quarantine=True):
    aws = Aws({})
    aws.s3.create_bucket(Bucket=SOURCE_BUCKET)
    aws.s3.create_bucket(Bucket=QUARANTINE_BUCKET)
    topic_arn = aws.sns.create_topic(Name="dlp-alerts")["TopicArn"]
    aws.queue_url = aws.sqs.create_queue(QueueName="alert-sink")["QueueUrl"]
    queue_arn = aws.sqs.get_queue_attributes(QueueUrl=aws.queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    aws.sns.subscribe(TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn)
    create_incident_table(aws.ddb, TABLE)
    aws.env = {
        "DLP_TABLE_NAME": TABLE,
        "DLP_SNS_TOPIC_ARN": topic_arn,
        "DLP_POLICY_PATH": str(EXAMPLE_POLICY),
        **({"DLP_QUARANTINE_BUCKET": QUARANTINE_BUCKET} if with_quarantine else {}),
        **(extra_env or {}),
    }
    return aws


@pytest.fixture
def aws(monkeypatch):
    with mock_aws():
        environment = build_aws()
        monkeypatch.setattr(handler, "_runtime", handler.build_runtime(environment.env))
        yield environment


def invoke(event):
    return handler.lambda_handler(event, SimpleNamespace(aws_request_id="test"))


class TestQuarantine:
    def test_card_data_to_an_external_recipient_is_quarantined_alerted_and_journaled(
        self, aws, make_card_csv, card_numbers
    ):
        numbers = card_numbers(2)
        event = aws.put("exports/customers.csv", make_card_csv(numbers), tags=EXTERNAL)

        summary = invoke(event)

        assert summary == {"objects": 1, "scanned": 1, "incidents": 1, "skipped": 0}
        # moved, not copied: gone from the source bucket, present in quarantine
        assert aws.keys(SOURCE_BUCKET) == []
        assert aws.keys(QUARANTINE_BUCKET) == ["outbound/exports/customers.csv"]
        body = aws.s3.get_object(Bucket=QUARANTINE_BUCKET, Key="outbound/exports/customers.csv")
        assert numbers[0] in body["Body"].read().decode()
        tags = aws.tags(QUARANTINE_BUCKET, "outbound/exports/customers.csv")
        assert tags["dlp-status"] == "quarantined" and tags["dlp-severity"] == "high"

        # journaled in DynamoDB
        (item,) = aws.items()
        assert item["rule"]["S"] == "card_data_to_external"
        assert item["severity"]["S"] == "high" and item["mode"]["S"] == "aws"
        assert item["source"]["S"] == "s3://outbound/exports/customers.csv"
        results = {
            r["M"]["action"]["S"]: r["M"]["status"]["S"] for r in item["action_results"]["L"]
        }
        assert results == {"quarantine": "ok", "alert": "ok"}
        assert "expires_at" in item  # default one-year retention

        # alerted through SNS
        (alert,) = aws.alerts()
        assert alert["Subject"].startswith("[DLP][HIGH] card_data_to_external")
        assert alert["MessageAttributes"]["severity"]["Value"] == "high"
        message = json.loads(alert["Message"])
        assert message["destination"]["categories"] == [
            "external_email",
            "non_corporate_domain",
            "private_s3",
        ]
        assert message["actions"][0] == {
            "action": "quarantine",
            "status": "ok",
            "detail": "moved to s3://quarantine/outbound/exports/customers.csv",
        }

    def test_without_a_quarantine_bucket_the_object_is_blocked_in_place(
        self, monkeypatch, make_card_csv, card_numbers
    ):
        with mock_aws():
            aws = build_aws(with_quarantine=False)
            monkeypatch.setattr(handler, "_runtime", handler.build_runtime(aws.env))
            invoke(aws.put("a.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL))
            assert aws.keys(SOURCE_BUCKET) == ["a.csv"]
            assert aws.tags(SOURCE_BUCKET, "a.csv")["dlp-status"] == "blocked"
            (item,) = aws.items()
            quarantine = next(
                r["M"] for r in item["action_results"]["L"] if r["M"]["action"]["S"] == "quarantine"
            )
            assert quarantine["status"]["S"] == "ok"
            assert "blocked in place" in quarantine["detail"]["S"]


class TestBlock:
    def test_bulk_card_data_is_tagged_blocked_and_stays_in_place(
        self, aws, make_card_csv, card_numbers
    ):
        invoke(aws.put("dump.csv", make_card_csv(card_numbers(5)), tags=EXTERNAL))

        assert aws.keys(SOURCE_BUCKET) == ["dump.csv"] and aws.keys(QUARANTINE_BUCKET) == []
        tags = aws.tags(SOURCE_BUCKET, "dump.csv")
        assert tags["dlp-status"] == "blocked" and tags["dlp-severity"] == "critical"
        # put_object_tagging replaces the tag set; the sender's tags must survive
        assert tags["dlp-destination"] == "external_email"
        assert tags["dlp-recipient"] == "buyer@vendor.example"

        (alert,) = aws.alerts()
        assert alert["Subject"].startswith("[DLP][CRITICAL] bulk_card_data_to_risky_destination")

    def test_overridden_rules_are_journaled_without_actions(self, aws, make_card_csv, card_numbers):
        invoke(aws.put("dump.csv", make_card_csv(card_numbers(5)), tags=EXTERNAL))
        items = {item["rule"]["S"]: item for item in aws.items()}
        assert set(items) == {"bulk_card_data_to_risky_destination", "card_data_to_external"}
        loser = items["card_data_to_external"]
        assert loser["suppressed_by"]["S"] == "bulk_card_data_to_risky_destination"
        assert loser["action_results"]["L"] == []
        assert len(aws.alerts()) == 1  # one alert per file, not per rule


class TestDestinationSignals:
    def test_card_data_in_a_publicly_readable_bucket_is_a_risk_without_any_tag(
        self, aws, make_card_csv, card_numbers
    ):
        aws.s3.create_bucket(Bucket="open-bucket", ACL="public-read")
        invoke(aws.put("leak.csv", make_card_csv(card_numbers(1)), bucket="open-bucket"))
        assert aws.keys("open-bucket") == []
        assert aws.keys(QUARANTINE_BUCKET) == ["open-bucket/leak.csv"]
        (item,) = aws.items()
        assert "public_s3" in [c["S"] for c in item["destination"]["M"]["categories"]["L"]]

    def test_the_same_data_in_a_private_bucket_without_tags_is_not_flagged(
        self, aws, make_card_csv, card_numbers
    ):
        invoke(aws.put("internal.csv", make_card_csv(card_numbers(3))))
        assert aws.keys(SOURCE_BUCKET) == ["internal.csv"]
        assert aws.items() == [] and aws.alerts() == []

    def test_tag_naming_an_internal_destination_is_allowed(self, aws, make_card_csv, card_numbers):
        invoke(aws.put("a.csv", make_card_csv(card_numbers(3)), tags="dlp-destination=internal"))
        assert aws.items() == []

    def test_recipient_tag_alone_is_not_enough_without_a_destination_category(
        self, aws, make_card_csv, card_numbers
    ):
        # S3 is the channel here, not email, so the recipient only yields a domain category.
        invoke(
            aws.put(
                "a.csv", make_card_csv(card_numbers(1)), tags="dlp-recipient=x@other.example.org"
            )
        )
        (item,) = aws.items()
        categories = [c["S"] for c in item["destination"]["M"]["categories"]["L"]]
        assert "non_corporate_domain" in categories

    def test_trusted_partner_exception_alerts_without_moving_the_object(
        self, aws, make_card_csv, card_numbers
    ):
        tags = "dlp-destination=external_email&dlp-recipient=ap@partner.example.net"
        invoke(aws.put("inv.csv", make_card_csv(card_numbers(1)), tags=tags))
        assert aws.keys(SOURCE_BUCKET) == ["inv.csv"] and aws.keys(QUARANTINE_BUCKET) == []
        winners = [i for i in aws.items() if "S" not in i["suppressed_by"]]
        assert [i["rule"]["S"] for i in winners] == ["trusted_partner_small_transfer"]


class TestCleanAndEdgeCases:
    def test_clean_file_leaves_no_trace(self, aws, fake):
        summary = invoke(aws.put("notes.txt", fake.paragraph(nb_sentences=40), tags=EXTERNAL))
        assert summary["scanned"] == 1 and summary["incidents"] == 0
        assert aws.keys(SOURCE_BUCKET) == ["notes.txt"]
        assert aws.items() == [] and aws.alerts() == []
        assert aws.tags(SOURCE_BUCKET, "notes.txt") == {
            "dlp-destination": "external_email",
            "dlp-recipient": "buyer@vendor.example",
        }

    def test_empty_object(self, aws):
        invoke(aws.put("empty.txt", "", tags=EXTERNAL))
        assert aws.items() == []

    def test_keys_with_spaces_plus_signs_and_unicode(self, aws, make_card_csv, card_numbers):
        key = "Q1 report+final/été summary.csv"
        invoke(aws.put(key, make_card_csv(card_numbers(1)), tags=EXTERNAL))
        assert aws.keys(QUARANTINE_BUCKET) == [f"outbound/{key}"]

    def test_folder_placeholders_are_skipped(self, aws):
        aws.s3.put_object(Bucket=SOURCE_BUCKET, Key="folder/", Body=b"")
        summary = invoke(s3_event((SOURCE_BUCKET, "folder/")))
        assert summary == {"objects": 1, "scanned": 0, "incidents": 0, "skipped": 1}

    def test_an_object_deleted_before_processing_is_skipped(self, aws):
        summary = invoke(s3_event((SOURCE_BUCKET, "already-gone.csv")))
        assert summary["skipped"] == 1 and aws.items() == []

    def test_events_from_the_quarantine_bucket_are_ignored(self, aws, make_card_csv, card_numbers):
        event = aws.put(
            "copy.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL, bucket=QUARANTINE_BUCKET
        )
        assert invoke(event)["skipped"] == 1
        assert aws.items() == [] and aws.keys(QUARANTINE_BUCKET) == ["copy.csv"]

    @pytest.mark.parametrize(
        "event", [{}, {"Records": []}, s3_event((SOURCE_BUCKET, "k"), name="ObjectRemoved:Delete")]
    )
    def test_events_without_created_objects_do_nothing(self, aws, event):
        assert invoke(event) == {"objects": 0, "scanned": 0, "incidents": 0, "skipped": 0}

    def test_large_objects_are_scanned_up_to_the_limit_and_flagged(self, monkeypatch, card_numbers):
        with mock_aws():
            aws = build_aws({"DLP_MAX_SCAN_BYTES": "200"})
            monkeypatch.setattr(handler, "_runtime", handler.build_runtime(aws.env))
            invoke(aws.put("big.txt", card_numbers(1)[0] + "\n" + "z" * 5000, tags=EXTERNAL))
            (item,) = aws.items()
            assert item["file"]["M"]["truncated"]["BOOL"] is True
            assert item["file"]["M"]["name"]["S"] == "big.txt"


class TestIdempotency:
    def test_a_replayed_event_for_a_blocked_object_creates_no_second_incident_or_alert(
        self, aws, make_card_csv, card_numbers
    ):
        event = aws.put("dump.csv", make_card_csv(card_numbers(5)), tags=EXTERNAL)
        invoke(event)
        replay = invoke(event)
        assert replay["skipped"] == 1 and replay["incidents"] == 0  # recognised as a duplicate
        assert len(aws.items()) == 2  # both triggered rules, once
        assert len(aws.alerts()) == 1

    def test_a_replayed_event_for_a_quarantined_object_is_skipped(
        self, aws, make_card_csv, card_numbers
    ):
        event = aws.put("a.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL)
        invoke(event)
        assert invoke(event)["skipped"] == 1
        assert len(aws.items()) == 1 and len(aws.alerts()) == 1

    def test_uploading_the_same_content_again_is_a_new_incident(
        self, aws, make_card_csv, card_numbers
    ):
        content = make_card_csv(card_numbers(1))
        invoke(aws.put("a.csv", content, tags=EXTERNAL))
        assert aws.keys(SOURCE_BUCKET) == []
        invoke(aws.put("a.csv", content, tags=EXTERNAL))  # same key, same bytes, new upload
        assert aws.keys(SOURCE_BUCKET) == []  # enforced again, not mistaken for a replay
        assert len(aws.items()) == 2 and len(aws.alerts()) == 2


class TestBatchesAndFailures:
    def test_several_objects_in_one_event(self, aws, make_card_csv, card_numbers, fake):
        aws.put("a.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL)
        aws.put("b.txt", fake.paragraph(), tags=EXTERNAL)
        aws.put("c.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL)
        summary = invoke(s3_event(*[(SOURCE_BUCKET, k) for k in ("a.csv", "b.txt", "c.csv")]))
        assert summary == {"objects": 3, "scanned": 3, "incidents": 2, "skipped": 0}
        assert aws.keys(SOURCE_BUCKET) == ["b.txt"]

    def test_one_failing_object_does_not_stop_the_others_but_fails_the_invocation(
        self, aws, monkeypatch, make_card_csv, card_numbers, caplog
    ):
        aws.put("good.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL)
        aws.put("bad.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL)
        runtime = handler.get_runtime()
        original = runtime.resolver.resolve

        def flaky(obj):
            if obj.key == "bad.csv":
                raise RuntimeError("tagging service unavailable")
            return original(obj)

        monkeypatch.setattr(runtime.resolver, "resolve", flaky)
        with caplog.at_level(logging.ERROR), pytest.raises(handler.ProcessingError) as excinfo:
            invoke(s3_event((SOURCE_BUCKET, "bad.csv"), (SOURCE_BUCKET, "good.csv")))
        assert "1 of 2 objects failed" in str(excinfo.value) and "s3://outbound/bad.csv" in str(
            excinfo.value
        )
        assert aws.keys(QUARANTINE_BUCKET) == ["outbound/good.csv"]  # processed despite the failure
        assert aws.keys(SOURCE_BUCKET) == ["bad.csv"]  # left untouched for the retry

    def test_a_dynamodb_outage_is_raised_after_the_incident_was_logged(
        self, aws, monkeypatch, make_card_csv, card_numbers, caplog
    ):
        runtime = handler.get_runtime()
        monkeypatch.setattr(
            runtime.pipeline.store,
            "add",
            lambda _: (_ for _ in ()).throw(RuntimeError("throttled")),
        )
        with caplog.at_level(logging.INFO), pytest.raises(handler.ProcessingError):
            invoke(aws.put("a.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL))
        logged = [r.message for r in caplog.records if r.name == "dlp.incident"]
        assert json.loads(logged[0])["rule"] == "card_data_to_external"


class TestPrivacy:
    def test_no_raw_sensitive_value_is_stored_sent_or_logged(
        self, aws, make_card_csv, card_numbers, fake, caplog
    ):
        cards, ssn = card_numbers(5), fake.ssn()
        body = make_card_csv(cards) + f"ssn {ssn}\n"
        with caplog.at_level(logging.INFO):
            invoke(aws.put("dump.csv", body, tags=EXTERNAL))
        everything = json.dumps(aws.items()) + json.dumps(aws.alerts()) + caplog.text
        for secret in [*cards, ssn, "buyer@vendor.example"]:
            assert secret not in everything
        assert "****-****-****-" in everything and "***-**-" in everything


class TestConfiguration:
    def test_missing_settings_fail_loudly(self):
        with pytest.raises(RuntimeError, match="DLP_TABLE_NAME, DLP_SNS_TOPIC_ARN"):
            handler.build_runtime({})

    def test_invalid_policy_fails_at_startup(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules: []\n")
        with mock_aws():
            aws = build_aws({"DLP_POLICY_PATH": str(bad)})
            with pytest.raises(Exception, match="rules"):
                handler.build_runtime(aws.env)

    def test_relative_policy_paths_resolve_next_to_the_handler(self):
        assert handler._policy_path("policies.yaml") == REPO_ROOT / "lambda" / "policies.yaml"
        assert handler._policy_path("/etc/p.yaml").as_posix() == "/etc/p.yaml"

    def test_webhook_is_added_to_the_alert_channels(self, monkeypatch, make_card_csv, card_numbers):
        with WebhookServer() as server, mock_aws():
            aws = build_aws({"DLP_WEBHOOK_URL": server.url})
            monkeypatch.setattr(handler, "_runtime", handler.build_runtime(aws.env))
            invoke(aws.put("a.csv", make_card_csv(card_numbers(1)), tags=EXTERNAL))
            assert len(aws.alerts()) == 1  # SNS still delivered
        assert server.requests[0]["body"]["severity"] == "high"

    def test_the_runtime_is_built_once_and_reused(self, monkeypatch):
        calls = []
        monkeypatch.setattr(handler, "_runtime", None)
        monkeypatch.setattr(handler, "build_runtime", lambda: calls.append(1) or object())
        first, second = handler.get_runtime(), handler.get_runtime()
        assert first is second and len(calls) == 1
        handler.reset_runtime()
        assert handler._runtime is None
