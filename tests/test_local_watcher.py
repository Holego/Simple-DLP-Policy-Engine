"""Integration tests for the local mode with a real filesystem watcher."""

import json
import logging
import os
import time
from pathlib import Path

import pytest

from src.engine import PolicyEngine
from src.storage import SqliteIncidentStore
from src.watchers.local import (
    LocalFileProcessor,
    LocalWatcher,
    build_local_pipeline,
    should_ignore,
)
from tests.conftest import EXAMPLE_POLICY
from tests.test_actions import WebhookServer

SETTLE = 0.3


def wait_for(predicate, timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


class Env:
    def __init__(self, tmp_path: Path, webhook_url: str | None = None, **watcher_options):
        self.outbox = tmp_path / "outbox"
        self.quarantine = tmp_path / "quarantine"
        self.outbox.mkdir(exist_ok=True)
        self.store = SqliteIncidentStore(tmp_path / "incidents.db")
        pipeline = build_local_pipeline(
            engine=PolicyEngine.from_file(EXAMPLE_POLICY),
            quarantine_dir=self.quarantine,
            store=self.store,
            webhook_url=webhook_url,
        )
        processor = LocalFileProcessor(pipeline, self.outbox, quarantine_dir=self.quarantine)
        self.watcher = LocalWatcher(processor, settle_seconds=SETTLE, **watcher_options)

    def put(self, relative: str, content: str, manifest: dict | None = None) -> Path:
        path = self.outbox / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if manifest is not None:
            path.with_name(path.name + ".meta.json").write_text(json.dumps(manifest))
        path.write_text(content)
        return path

    def settle(self):
        assert self.watcher.wait_idle(timeout=15), "watcher did not become idle"

    def incidents(self, **kwargs):
        return self.store.query(**kwargs)

    def quarantined(self):
        if not self.quarantine.exists():
            return []
        return [p for p in self.quarantine.iterdir() if not p.name.endswith(".json")]


@pytest.fixture
def env(tmp_path):
    environment = Env(tmp_path)
    environment.watcher.start()
    yield environment
    environment.watcher.stop()


def test_card_data_to_external_email_is_alerted_quarantined_and_journaled(
    env, make_card_csv, card_numbers, caplog
):
    numbers = card_numbers(2)
    with caplog.at_level(logging.WARNING, logger="dlp.alerts"):
        file = env.put("external_email/customers.csv", make_card_csv(numbers))
        assert wait_for(lambda: env.incidents())
        env.settle()

    # quarantined: gone from the outbox, present in quarantine with evidence next to it
    assert not file.exists()
    (moved,) = env.quarantined()
    assert moved.name.endswith("customers.csv") and moved.read_text().count(numbers[0]) == 1
    assert (moved.parent / (moved.name + ".incident.json")).exists()

    # alerted on the console/log
    alert = [r.getMessage() for r in caplog.records if r.name == "dlp.alerts"]
    assert len(alert) == 1
    assert "[DLP][HIGH] card_data_to_external" in alert[0] and "quarantine" in alert[0]

    # journaled, masked
    (incident,) = env.incidents()
    assert incident["rule"] == "card_data_to_external" and incident["mode"] == "local"
    assert incident["source"] == str(file)
    assert [r["action"] for r in incident["action_results"]] == ["quarantine", "alert"]
    assert incident["findings"][0]["count"] == 2
    dumped = json.dumps(incident) + alert[0]
    assert not any(number in dumped for number in numbers)
    assert all(sample.startswith("****-") for sample in incident["findings"][0]["samples"])


def test_clean_file_to_an_external_destination_is_left_alone(env, fake):
    file = env.put("external_email/notes.txt", fake.paragraph(nb_sentences=30))
    env.settle()
    assert file.exists() and env.incidents() == [] and env.quarantined() == []


def test_sensitive_data_to_an_internal_destination_is_allowed(env, make_card_csv, card_numbers):
    file = env.put("internal/report.csv", make_card_csv(card_numbers(10)))
    env.settle()
    assert file.exists() and env.incidents() == []


def test_sidecar_manifest_supplies_the_destination(env, make_card_csv, card_numbers):
    env.put(
        "report.csv",
        make_card_csv(card_numbers(1)),
        manifest={"channel": "email", "recipient": "buyer@other.example.org"},
    )
    assert wait_for(lambda: env.incidents())
    env.settle()
    (incident,) = env.incidents()
    assert incident["destination"]["domain"] == "other.example.org"
    assert "external_email" in incident["destination"]["categories"]
    assert len(env.quarantined()) == 1
    assert not (env.outbox / "report.csv.meta.json").exists()  # manifest travels with the file


def test_trusted_partner_is_alert_only_and_the_file_stays(env, make_card_csv, card_numbers):
    file = env.put(
        "r.csv",
        make_card_csv(card_numbers(2)),
        manifest={"channel": "email", "recipient": "ap@partner.example.net"},
    )
    assert wait_for(lambda: env.incidents())
    env.settle()
    assert file.exists() and env.quarantined() == []
    winner = [i for i in env.incidents() if not i["suppressed_by"]]
    assert [i["rule"] for i in winner] == ["trusted_partner_small_transfer"]
    assert [i for i in env.incidents() if i["suppressed_by"] == "trusted_partner_small_transfer"]


def test_bulk_card_data_is_blocked_in_place(env, make_card_csv, card_numbers):
    file = env.put("public_s3/dump.csv", make_card_csv(card_numbers(5)))
    assert wait_for(lambda: env.incidents())
    env.settle()
    assert file.exists() and file.stat().st_mode & 0o777 == 0
    assert (env.outbox / "public_s3" / "dump.csv.dlp-blocked").exists()
    (winner,) = [i for i in env.incidents() if not i["suppressed_by"]]
    assert winner["severity"] == "critical"
    assert [r["action"] for r in winner["action_results"]] == ["block", "alert"]
    # the marker and the chmod must not cause the file to be processed again
    time.sleep(SETTLE * 2)
    env.settle()
    assert len(env.incidents()) == 2


def test_modifying_a_file_triggers_a_new_scan(env, make_card_csv, card_numbers, fake):
    file = env.put("external_email/draft.txt", fake.paragraph())
    env.settle()
    assert env.incidents() == []
    file.write_text(make_card_csv(card_numbers(1)))
    assert wait_for(lambda: env.incidents())
    env.settle()
    assert len(env.quarantined()) == 1


def test_files_still_being_written_are_scanned_only_once_complete(env, card_numbers):
    """Reading too early would see one card, quarantine the file and lose the other five."""
    cards = card_numbers(6)
    path = env.outbox / "external_email" / "slow.csv"
    path.parent.mkdir()
    with path.open("w") as handle:
        handle.write(f"{cards[0]}\n")
        handle.flush()
        time.sleep(SETTLE / 3)  # shorter than the settle time: must not be scanned yet
        handle.write("\n".join(cards[1:]) + "\n")
    assert wait_for(lambda: env.incidents())
    env.settle()
    (winner,) = [i for i in env.incidents() if not i["suppressed_by"]]
    assert winner["rule"] == "bulk_card_data_to_risky_destination"
    assert winner["findings"][0]["count"] == 6
    assert env.quarantined() == []  # blocked in place, never moved while still being written


def test_files_present_at_startup_are_scanned(tmp_path, make_card_csv, card_numbers):
    environment = Env(tmp_path)
    file = environment.put("external_email/old.csv", make_card_csv(card_numbers(1)))
    with environment.watcher:
        assert wait_for(lambda: environment.incidents())
        environment.settle()
    assert not file.exists()


def test_a_restart_does_not_repeat_alerts_for_files_left_in_place(
    tmp_path, make_card_csv, card_numbers, caplog
):
    first = Env(tmp_path)
    first.put(
        "r.csv",
        make_card_csv(card_numbers(1)),
        manifest={"channel": "email", "recipient": "ap@partner.example.net"},
    )
    with first.watcher:
        assert wait_for(lambda: first.incidents())
        first.settle()
    before = len(first.incidents())
    caplog.clear()

    restarted = Env(tmp_path)  # same folders and the same incident database
    with caplog.at_level(logging.WARNING, logger="dlp.alerts"), restarted.watcher:
        restarted.settle()
    assert len(restarted.incidents()) == before
    assert not [r for r in caplog.records if r.name == "dlp.alerts"]


def test_symlinks_are_never_followed(tmp_path, env, make_card_csv, card_numbers):
    outside = tmp_path / "secret.csv"
    outside.write_text(make_card_csv(card_numbers(5)))
    link = env.outbox / "external_email" / "innocent.csv"
    link.parent.mkdir()
    link.symlink_to(outside)
    link.with_name("innocent.csv.meta.json").write_text('{"destination": "external_email"}')
    env.settle()
    time.sleep(SETTLE * 2)
    env.settle()
    assert env.incidents() == []
    assert outside.exists() and link.is_symlink()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_named_pipes_do_not_block_the_watcher(env):
    os.mkfifo(env.outbox / "pipe")
    env.settle()
    assert env.watcher._worker.is_alive()


def test_manifests_markers_and_temp_files_are_not_payloads(env, make_card_csv, card_numbers):
    content = make_card_csv(card_numbers(3))
    for name in ("metadata.json", "x.csv.tmp", ".hidden", "y.part", "z.csv~", "k.dlp-blocked"):
        env.put(f"external_email/{name}", content)
    env.settle()
    time.sleep(SETTLE * 2)
    env.settle()
    assert env.incidents() == [] and env.quarantined() == []


def test_quarantine_inside_the_watched_tree_is_not_rescanned(tmp_path, make_card_csv, card_numbers):
    environment = Env(tmp_path)
    nested = environment.outbox / "_quarantine"
    environment.quarantine = nested
    pipeline = build_local_pipeline(
        engine=PolicyEngine.from_file(EXAMPLE_POLICY),
        quarantine_dir=nested,
        store=environment.store,
    )
    processor = LocalFileProcessor(pipeline, environment.outbox, quarantine_dir=nested)
    environment.watcher = LocalWatcher(processor, settle_seconds=SETTLE)
    with environment.watcher:
        environment.put("external_email/a.csv", make_card_csv(card_numbers(1)))
        assert wait_for(lambda: environment.incidents())
        environment.settle()
        time.sleep(SETTLE * 2)
        environment.settle()
    assert len(environment.incidents()) == 1


def test_a_file_that_vanishes_before_processing_is_ignored(env, make_card_csv, card_numbers):
    file = env.put("external_email/gone.csv", make_card_csv(card_numbers(1)))
    file.unlink()
    env.settle()
    assert env.incidents() == []
    assert env.watcher._worker.is_alive()


def test_content_beyond_the_scan_limit_is_not_inspected(tmp_path, card_numbers):
    environment = Env(tmp_path)
    environment.watcher.processor.max_scan_bytes = 200
    with environment.watcher:
        environment.put("external_email/big.txt", "z" * 1000 + f"\n{card_numbers(1)[0]}\n")
        environment.settle()
    assert environment.incidents() == []


def test_truncated_scans_are_flagged_in_the_incident(tmp_path, card_numbers):
    environment = Env(tmp_path)
    environment.watcher.processor.max_scan_bytes = 200
    with environment.watcher:
        environment.put("external_email/big.txt", f"{card_numbers(1)[0]}\n" + "z" * 5000)
        assert wait_for(lambda: environment.incidents())
        environment.settle()
    (incident,) = environment.incidents()
    assert incident["file"]["truncated"] is True and incident["file"]["size"] > 200


def test_webhook_receives_the_alert(tmp_path, make_card_csv, card_numbers):
    with WebhookServer() as server:
        environment = Env(tmp_path, webhook_url=server.url)
        with environment.watcher:
            environment.put("external_email/c.csv", make_card_csv(card_numbers(1)))
            assert wait_for(lambda: server.requests)
            environment.settle()
    (request,) = server.requests
    assert request["body"]["severity"] == "high"
    assert request["body"]["destination"]["categories"] == ["external_email"]
    (incident,) = environment.incidents()
    assert {r["action"]: r["status"] for r in incident["action_results"]} == {
        "quarantine": "ok",
        "alert": "ok",
    }


def test_a_broken_webhook_does_not_prevent_enforcement(tmp_path, make_card_csv, card_numbers):
    environment = Env(tmp_path, webhook_url="http://127.0.0.1:1/hook")
    with environment.watcher:
        environment.put("external_email/c.csv", make_card_csv(card_numbers(1)))
        assert wait_for(lambda: environment.incidents())
        environment.settle()
    assert len(environment.quarantined()) == 1
    (incident,) = environment.incidents()
    statuses = {r["action"]: r["status"] for r in incident["action_results"]}
    assert statuses == {"quarantine": "ok", "alert": "partial"}


def test_polling_observer_works_too(tmp_path, make_card_csv, card_numbers):
    environment = Env(tmp_path, use_polling=True, poll_interval=0.2)
    with environment.watcher:
        environment.put("external_email/c.csv", make_card_csv(card_numbers(1)))
        assert wait_for(lambda: environment.incidents())
        environment.settle()
    assert len(environment.quarantined()) == 1


@pytest.mark.parametrize(
    ("name", "ignored"),
    [
        ("report.csv", False),
        ("metadata.json", True),
        ("report.csv.meta.json", True),
        ("report.csv.dlp-blocked", True),
        ("report.csv.incident.json", True),
        (".DS_Store", True),
        ("upload.crdownload", True),
        ("notes.txt~", True),
        ("data.json", False),
    ],
)
def test_ignore_rules(name, ignored):
    assert should_ignore(Path("/outbox") / name) is ignored
