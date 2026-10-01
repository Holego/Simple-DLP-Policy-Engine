import json
import threading
from dataclasses import replace
from datetime import timedelta

import boto3
import pytest
from moto import mock_aws

from src.incident import timestamp_before, utc_timestamp
from src.storage import SqliteIncidentStore, parse_duration
from src.storage.dynamodb_store import (
    SEVERITY_INDEX,
    TTL_ATTRIBUTE,
    DynamoDbIncidentStore,
    create_incident_table,
)
from tests.conftest import make_incident


class TestParseDuration:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("30s", timedelta(seconds=30)),
            ("15m", timedelta(minutes=15)),
            ("12h", timedelta(hours=12)),
            ("7d", timedelta(days=7)),
            ("2w", timedelta(weeks=2)),
            (" 7D ", timedelta(days=7)),
        ],
    )
    def test_valid(self, text, expected):
        assert parse_duration(text) == expected

    @pytest.mark.parametrize("text", ["", "7", "d", "7days", "-1d", "1.5h", "7 d x"])
    def test_invalid(self, text):
        with pytest.raises(ValueError, match="invalid duration"):
            parse_duration(text)


class StoreContract:
    """Behaviour every incident store must have; subclasses provide ``store``."""

    def seed(self, store):
        base = [
            ("1", "high", "2026-01-05T00:00:00.000Z", "card_data_to_external"),
            ("2", "critical", "2026-01-04T00:00:00.000Z", "bulk_cards"),
            ("3", "high", "2026-01-03T00:00:00.000Z", "ssn_rule"),
            ("4", "low", "2026-01-02T00:00:00.000Z", "card_data_to_external"),
            ("5", "medium", "2026-01-01T00:00:00.000Z", "emails"),
        ]
        for number, severity, timestamp, rule in base:
            store.add(
                make_incident(
                    incident_id=number * 32,
                    severity=severity,
                    timestamp=timestamp,
                    rule=rule,
                )
            )

    def test_add_then_exists(self, store):
        incident = make_incident()
        assert not store.exists(incident.incident_id)
        assert store.add(incident) is True
        assert store.exists(incident.incident_id)

    def test_duplicate_ids_are_rejected_and_do_not_overwrite(self, store):
        assert store.add(make_incident(rule="first"))
        assert store.add(make_incident(rule="second")) is False
        (stored,) = store.query()
        assert stored["rule"] == "first"

    def test_incident_round_trips(self, store):
        incident = make_incident()
        store.add(incident)
        assert store.query() == [incident.to_dict()]

    def test_query_returns_newest_first(self, store):
        self.seed(store)
        assert [i["incident_id"][0] for i in store.query()] == list("12345")

    def test_filter_by_one_or_several_severities(self, store):
        self.seed(store)
        assert {i["severity"] for i in store.query(severities=["high"])} == {"high"}
        found = store.query(severities=["high", "critical"])
        assert [i["incident_id"][0] for i in found] == ["1", "2", "3"]

    def test_filter_by_start_time_is_inclusive(self, store):
        self.seed(store)
        found = store.query(since="2026-01-03T00:00:00.000Z")
        assert [i["incident_id"][0] for i in found] == ["1", "2", "3"]

    def test_filter_by_rule(self, store):
        self.seed(store)
        found = store.query(rule="card_data_to_external")
        assert [i["incident_id"][0] for i in found] == ["1", "4"]

    def test_filters_combine(self, store):
        self.seed(store)
        found = store.query(
            severities=["high"], since="2026-01-04T00:00:00.000Z", rule="card_data_to_external"
        )
        assert [i["incident_id"][0] for i in found] == ["1"]

    def test_limit_keeps_the_newest(self, store):
        self.seed(store)
        assert [i["incident_id"][0] for i in store.query(limit=2)] == ["1", "2"]

    def test_empty_result(self, store):
        self.seed(store)
        assert store.query(severities=["high"], since="2030-01-01T00:00:00.000Z") == []

    def test_last_seven_days_query(self, store):
        store.add(
            make_incident(incident_id="a" * 32, timestamp=timestamp_before(timedelta(days=2)))
        )
        store.add(
            make_incident(incident_id="b" * 32, timestamp=timestamp_before(timedelta(days=9)))
        )
        since = timestamp_before(parse_duration("7d"))
        assert [i["incident_id"][0] for i in store.query(severities=["high"], since=since)] == ["a"]


class TestSqliteStore(StoreContract):
    @pytest.fixture
    def store(self, tmp_path):
        return SqliteIncidentStore(tmp_path / "db" / "incidents.db")

    def test_creates_parent_directories_and_persists(self, tmp_path):
        path = tmp_path / "nested" / "dir" / "incidents.db"
        SqliteIncidentStore(path).add(make_incident())
        assert SqliteIncidentStore(path).exists(make_incident().incident_id)

    def test_concurrent_writers(self, store):
        def write(start):
            for offset in range(25):
                store.add(make_incident(incident_id=f"{start + offset:032d}"))

        threads = [threading.Thread(target=write, args=(n * 100,)) for n in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(store.query(limit=1000)) == 100

    def test_queries_are_parameterised(self, store):
        store.add(make_incident())
        assert store.query(rule="x' OR '1'='1") == []
        assert store.query(severities=["high') OR 1=1 --"]) == []

    def test_stores_one_json_document_per_incident(self, store):
        store.add(make_incident())
        import sqlite3

        with sqlite3.connect(store.path) as conn:
            (payload,) = conn.execute("SELECT payload FROM incidents").fetchone()
        assert json.loads(payload)["rule"] == "card_data_to_external"


class TestDynamoDbStore(StoreContract):
    TABLE = "dlp-incidents"

    @pytest.fixture
    def aws(self):
        with mock_aws():
            client = boto3.client("dynamodb")
            create_incident_table(client, self.TABLE)
            yield client

    @pytest.fixture
    def store(self, aws):
        return DynamoDbIncidentStore.from_table_name(self.TABLE)

    def test_queries_use_the_severity_index(self, aws, store):
        self.seed(store)
        description = aws.describe_table(TableName=self.TABLE)["Table"]
        assert description["GlobalSecondaryIndexes"][0]["IndexName"] == SEVERITY_INDEX
        assert len(store.query(severities=["high"])) == 2

    def test_items_are_native_dynamodb_maps_not_blobs(self, aws, store):
        store.add(make_incident())
        item = aws.scan(TableName=self.TABLE)["Items"][0]
        assert "M" in item["destination"] and "L" in item["findings"]
        assert item["severity"] == {"S": "high"}

    def test_integers_survive_the_decimal_round_trip(self, store):
        store.add(make_incident(priority=90))
        (found,) = store.query()
        assert found["priority"] == 90 and isinstance(found["priority"], int)
        assert found["file"]["size"] == 10

    def test_retention_sets_a_ttl_that_is_hidden_from_queries(self, aws, store):
        store.retention_days = 30
        incident = make_incident(timestamp=utc_timestamp())
        store.add(incident)
        item = aws.scan(TableName=self.TABLE)["Items"][0]
        ttl = int(item[TTL_ATTRIBUTE]["N"])
        assert abs(ttl - (int(timestamp_epoch(incident.timestamp)) + 30 * 86400)) <= 1
        assert TTL_ATTRIBUTE not in store.query()[0]

    def test_no_ttl_without_retention(self, aws, store):
        store.add(make_incident())
        assert TTL_ATTRIBUTE not in aws.scan(TableName=self.TABLE)["Items"][0]

    def test_rule_filter_still_fills_the_limit(self, store):
        for index in range(30):
            rule = "target" if index % 10 == 0 else "other"
            store.add(
                make_incident(
                    incident_id=f"{index:032d}",
                    rule=rule,
                    timestamp=f"2026-01-01T00:00:{index:02d}.000Z",
                )
            )
        found = store.query(severities=["high"], rule="target", limit=3)
        assert [i["rule"] for i in found] == ["target"] * 3

    def test_unexpected_errors_are_not_swallowed(self, store):
        store.table = boto3.resource("dynamodb").Table("does-not-exist")
        with pytest.raises(Exception, match="ResourceNotFound"):
            store.add(replace(make_incident(), incident_id="z" * 32))


def timestamp_epoch(timestamp: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
