import json
import logging
from datetime import datetime, timezone

import pytest

from src.actions import ActionExecutor, ActionResult, AlertAction
from src.actions.base import ActionContext
from src.detectors import Scanner
from src.engine import Destination, PolicyEngine
from src.incident import describe_actions
from src.pipeline import DlpPipeline
from src.storage import SqliteIncidentStore
from tests.conftest import EXAMPLE_POLICY

EXTERNAL = Destination(channel="email", recipient="someone@other.example.org")
FIXED_NOW = datetime(2026, 3, 1, 12, 0, 0, tzinfo=timezone.utc)


class Handler:
    def __init__(self, name, fail=False):
        self.name, self.fail, self.contexts = name, fail, []

    def run(self, ctx: ActionContext):
        self.contexts.append(ctx)
        if self.fail:
            raise OSError("boom")
        return ActionResult(self.name, "ok", f"{self.name} done")


class Notifier:
    name = "fake"

    def __init__(self):
        self.payloads = []

    def send(self, payload):
        self.payloads.append(payload)


@pytest.fixture
def parts(tmp_path):
    handlers = {name: Handler(name) for name in ("quarantine", "block")}
    notifier = Notifier()
    handlers["alert"] = AlertAction([notifier])
    store = SqliteIncidentStore(tmp_path / "db.sqlite")
    pipeline = DlpPipeline(
        mode="local",
        scanner=Scanner(),
        engine=PolicyEngine.from_file(EXAMPLE_POLICY),
        executor=ActionExecutor(handlers.values()),
        store=store,
        clock=lambda: FIXED_NOW,
    )
    return pipeline, handlers, notifier, store


def run(pipeline, data, destination=EXTERNAL, event_key="1", target="target"):
    return pipeline.process(
        data.encode() if isinstance(data, str) else data,
        source="/outbox/report.csv",
        destination=destination,
        target=target,
        event_key=event_key,
        file_info={"name": "report.csv", "size": len(data)},
    )


def test_clean_file_has_no_side_effects(parts, fake):
    pipeline, handlers, notifier, store = parts
    result = run(pipeline, fake.paragraph(nb_sentences=20))
    assert not result.decision.triggered and result.incidents == ()
    assert notifier.payloads == [] and handlers["quarantine"].contexts == []
    assert store.query() == []


def test_sensitive_data_to_a_safe_destination_is_ignored(parts, card_numbers):
    pipeline, _, notifier, store = parts
    internal = Destination(channel="email", recipient="a@corp.example.com")
    result = run(pipeline, "\n".join(card_numbers(6)), destination=internal)
    assert result.total_findings == 6 and not result.decision.triggered
    assert notifier.payloads == [] and store.query() == []


def test_matching_file_runs_actions_and_journals_the_incident(parts, card_numbers):
    pipeline, handlers, notifier, store = parts
    result = run(pipeline, f"card {card_numbers(1)[0]}")

    assert [r.action for r in result.action_results] == ["quarantine", "alert"]
    assert len(handlers["quarantine"].contexts) == 1 and handlers["block"].contexts == []
    (payload,) = notifier.payloads
    assert [r["action"] for r in payload.actions] == ["quarantine"]  # alert sees the outcome

    (incident,) = store.query()
    assert incident["rule"] == "card_data_to_external"
    assert incident["severity"] == "high"
    assert incident["timestamp"] == "2026-03-01T12:00:00.000Z"
    assert incident["mode"] == "local" and incident["source"] == "/outbox/report.csv"
    assert incident["declared_actions"] == ["alert", "quarantine"]
    assert incident["effective_actions"] == ["quarantine", "alert"]
    assert describe_actions(incident) == "quarantine:ok, alert:ok"
    assert incident["destination"]["categories"] == ["external_email", "non_corporate_domain"]
    assert incident["destination"]["recipient"] == "s***@other.example.org"
    assert incident["findings"][0]["type"] == "credit_card"
    assert incident["file"]["name"] == "report.csv" and len(incident["file"]["sha256"]) == 64


def test_no_raw_sensitive_value_reaches_any_output(parts, card_numbers, fake, caplog):
    pipeline, _, notifier, store = parts
    cards, ssn = card_numbers(5), fake.ssn()
    secrets = [*cards, ssn, "someone@other.example.org"]
    with caplog.at_level(logging.INFO):
        run(pipeline, "\n".join([*cards, f"ssn {ssn}"]))
    outputs = [
        json.dumps(store.query()),
        caplog.text,
        *[p.text() for p in notifier.payloads],
        *[json.dumps(p.to_dict()) for p in notifier.payloads],
    ]
    for output in outputs:
        assert not any(secret in output for secret in secrets)
    assert "****-****-****-" in json.dumps(store.query())


def test_each_triggered_rule_gets_its_own_incident_and_suppressed_ones_have_no_actions(
    parts, card_numbers
):
    pipeline, handlers, _, store = parts
    run(pipeline, "\n".join(card_numbers(4)))

    incidents = {i["rule"]: i for i in store.query()}
    assert set(incidents) == {"bulk_card_data_to_risky_destination", "card_data_to_external"}

    winner = incidents["bulk_card_data_to_risky_destination"]
    assert winner["severity"] == "critical" and winner["suppressed_by"] is None
    assert [r["action"] for r in winner["action_results"]] == ["block", "alert"]

    loser = incidents["card_data_to_external"]
    assert loser["suppressed_by"] == "bulk_card_data_to_risky_destination"
    assert loser["action_results"] == []
    assert loser["effective_actions"] == ["block", "alert"]
    assert describe_actions(loser) == "none (suppressed)"

    assert handlers["block"].contexts and not handlers["quarantine"].contexts


def test_incident_findings_list_only_the_types_that_matched(parts, card_numbers, fake):
    pipeline, _, _, store = parts
    run(pipeline, "\n".join([card_numbers(1)[0], *[fake.email() for _ in range(5)]]))
    (incident,) = store.query()
    assert [f["type"] for f in incident["findings"]] == ["credit_card"]


def test_masked_samples_are_capped(parts, card_numbers):
    pipeline, _, _, store = parts
    run(pipeline, "\n".join(card_numbers(3)))
    (incident,) = store.query(rule="card_data_to_external")
    assert incident["findings"][0]["count"] == 3
    assert len(incident["findings"][0]["samples"]) == 3


def test_a_replayed_event_is_skipped(parts, card_numbers):
    pipeline, handlers, notifier, store = parts
    data = card_numbers(1)[0]
    first = run(pipeline, data, event_key="seq-1")
    again = run(pipeline, data, event_key="seq-1")
    assert not first.duplicate and again.duplicate
    assert len(handlers["quarantine"].contexts) == 1 and len(notifier.payloads) == 1
    assert len(store.query()) == 1


def test_a_new_event_with_identical_content_is_enforced_again(parts, card_numbers):
    pipeline, handlers, _, store = parts
    data = card_numbers(1)[0]
    run(pipeline, data, event_key="seq-1")
    run(pipeline, data, event_key="seq-2")
    assert len(handlers["quarantine"].contexts) == 2
    assert len(store.query()) == 2


def test_a_failed_action_is_recorded_and_the_alert_reports_it(tmp_path, card_numbers):
    notifier = Notifier()
    store = SqliteIncidentStore(tmp_path / "db.sqlite")
    pipeline = DlpPipeline(
        mode="local",
        scanner=Scanner(),
        engine=PolicyEngine.from_file(EXAMPLE_POLICY),
        executor=ActionExecutor([Handler("quarantine", fail=True), AlertAction([notifier])]),
        store=store,
    )
    run(pipeline, card_numbers(1)[0])
    (incident,) = store.query()
    statuses = {r["action"]: r["status"] for r in incident["action_results"]}
    assert statuses == {"quarantine": "failed", "alert": "ok"}
    assert "OSError: boom" in incident["action_results"][0]["detail"]
    assert "quarantine (failed)" in notifier.payloads[0].text()


def test_store_failure_still_logs_every_incident_then_raises(parts, card_numbers, caplog):
    pipeline, _, _, store = parts

    class BrokenStore:
        def exists(self, _):
            return False

        def add(self, _):
            raise RuntimeError("database unavailable")

    pipeline.store = BrokenStore()
    with caplog.at_level(logging.INFO), pytest.raises(RuntimeError, match="database unavailable"):
        run(pipeline, "\n".join(card_numbers(4)))
    logged = [r.message for r in caplog.records if r.name == "dlp.incident"]
    assert len(logged) == 2
    assert {json.loads(line)["rule"] for line in logged} == {
        "bulk_card_data_to_risky_destination",
        "card_data_to_external",
    }


def test_incident_log_lines_are_json(parts, card_numbers, caplog):
    pipeline, *_ = parts
    with caplog.at_level(logging.INFO, logger="dlp.incident"):
        run(pipeline, card_numbers(1)[0])
    (record,) = [r for r in caplog.records if r.name == "dlp.incident"]
    assert json.loads(record.message)["rule"] == "card_data_to_external"


def test_inspect_is_a_side_effect_free_dry_run(parts, card_numbers):
    pipeline, handlers, notifier, store = parts
    result = pipeline.inspect(card_numbers(1)[0].encode(), EXTERNAL)
    assert result.decision.triggered and result.incidents == ()
    assert handlers["quarantine"].contexts == [] and notifier.payloads == [] and store.query() == []


def test_file_info_is_passed_through_to_the_incident(parts, card_numbers):
    pipeline, _, _, store = parts
    pipeline.process(
        card_numbers(1)[0].encode(),
        source="s",
        destination=EXTERNAL,
        target=None,
        event_key="k",
        file_info={"name": "n", "truncated": True},
    )
    assert store.query()[0]["file"]["truncated"] is True
