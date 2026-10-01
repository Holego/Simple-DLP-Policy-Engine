import json
import os
import signal
import subprocess
import sys
import time
from datetime import timedelta

import boto3
import pytest
from click.testing import CliRunner
from moto import mock_aws

import cli as cli_module
from src.incident import timestamp_before
from src.storage import SqliteIncidentStore
from src.storage.dynamodb_store import DynamoDbIncidentStore, create_incident_table
from tests.conftest import EXAMPLE_POLICY, REPO_ROOT, make_incident


@pytest.fixture
def runner(monkeypatch):
    # A developer's own .env must never leak into the tests (it could hold a real webhook).
    monkeypatch.setattr(cli_module, "load_dotenv", None)
    return CliRunner()


def invoke(runner, *args, **kwargs):
    return runner.invoke(cli_module.cli, [str(a) for a in args], **kwargs)


class TestPolicyValidate:
    def test_valid_policy_lists_the_rules_by_priority(self, runner):
        result = invoke(runner, "policy", "validate", EXAMPLE_POLICY)
        assert result.exit_code == 0
        assert "OK" in result.stdout and "6 rules (6 enabled)" in result.stdout
        lines = [line for line in result.stdout.splitlines() if "->" in line]
        priorities = [int(line.split()[0]) for line in lines]
        assert priorities == sorted(priorities, reverse=True)
        assert "bulk_card_data_to_risky_destination  -> alert, block" in result.stdout

    def test_invalid_policy_exits_with_2_and_lists_every_problem(self, runner, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(
            "rules:\n"
            "  - rule: a\n    severity: urgent\n    action: [alrt]\n"
            "    condition: {contains: [passport]}\n"
        )
        result = invoke(runner, "policy", "validate", bad)
        assert result.exit_code == 2
        assert "INVALID" in result.stderr
        for fragment in ("severity", "did you mean 'alert'", "unknown data type 'passport'"):
            assert fragment in result.stderr

    def test_warnings_go_to_stderr(self, runner, tmp_path):
        policy = tmp_path / "p.yaml"
        policy.write_text(
            "rules:\n  - rule: r\n    severity: low\n    condition: {contains: [ssn]}\n"
            "    action: [quarantine, block]\n"
        )
        result = invoke(runner, "policy", "validate", policy)
        assert result.exit_code == 0 and "warning:" in result.stderr

    def test_missing_file(self, runner, tmp_path):
        result = invoke(runner, "policy", "validate", tmp_path / "nope.yaml")
        assert result.exit_code == 2 and "cannot read policy file" in result.stderr


class TestPolicyTest:
    @pytest.fixture
    def card_file(self, tmp_path, make_card_csv, card_numbers):
        path = tmp_path / "report.csv"
        path.write_text(make_card_csv(card_numbers(2)))
        return path

    def test_text_report(self, runner, card_file):
        result = invoke(
            runner, "policy", "test", "--policy", EXAMPLE_POLICY, "--file", card_file,
            "--destination", "external_email",
        )  # fmt: skip
        assert result.exit_code == 0
        assert "credit_card x2 (****-****-****-" in result.stdout
        assert "* card_data_to_external [high, priority 30] -> alert, quarantine" in result.stdout
        assert "result:      quarantine, alert" in result.stdout

    def test_overridden_rules_are_marked(self, runner, tmp_path, make_card_csv, card_numbers):
        path = tmp_path / "bulk.csv"
        path.write_text(make_card_csv(card_numbers(5)))
        result = invoke(
            runner, "policy", "test", "--policy", EXAMPLE_POLICY, "--file", path,
            "--channel", "email", "--recipient", "x@other.example.org",
        )  # fmt: skip
        assert "- card_data_to_external" in result.stdout
        assert "(overridden by bulk_card_data_to_risky_destination)" in result.stdout
        assert "result:      block, alert" in result.stdout

    def test_json_report_contains_only_masked_values(self, runner, card_file):
        result = invoke(
            runner, "policy", "test", "--policy", EXAMPLE_POLICY, "--file", card_file,
            "--destination", "public_s3", "--format", "json",
        )  # fmt: skip
        data = json.loads(result.stdout)
        assert data["actions"] == ["quarantine", "alert"]
        assert data["matches"][0]["rule"] == "card_data_to_external"
        raw = [line.split(",")[1] for line in card_file.read_text().splitlines()[1:]]
        assert not any(number in result.stdout for number in raw)

    def test_no_match_says_so(self, runner, card_file):
        result = invoke(
            runner, "policy", "test", "--policy", EXAMPLE_POLICY, "--file", card_file,
            "--destination", "internal",
        )  # fmt: skip
        assert "no rule matched" in result.stdout

    def test_unknown_destination_category_is_rejected(self, runner, card_file):
        result = invoke(
            runner, "policy", "test", "--policy", EXAMPLE_POLICY, "--file", card_file,
            "--destination", "mars",
        )  # fmt: skip
        assert result.exit_code == 2 and "mars" in result.stderr

    def test_invalid_policy_is_reported(self, runner, tmp_path, card_file):
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules: []\n")
        result = invoke(runner, "policy", "test", "--policy", bad, "--file", card_file)
        assert result.exit_code == 2 and "Invalid policy" in result.stderr

    def test_nothing_is_moved_or_recorded(self, runner, card_file, tmp_path):
        invoke(
            runner, "policy", "test", "--policy", EXAMPLE_POLICY, "--file", card_file,
            "--destination", "external_email",
        )  # fmt: skip
        assert card_file.exists() and not (tmp_path / "quarantine").exists()


class TestIncidentLogQuery:
    @pytest.fixture
    def db(self, tmp_path):
        path = tmp_path / "incidents.db"
        store = SqliteIncidentStore(path)
        entries = [
            ("1", "high", timedelta(days=1), "card_data_to_external"),
            ("2", "critical", timedelta(days=2), "bulk_cards"),
            ("3", "high", timedelta(days=10), "card_data_to_external"),
            ("4", "low", timedelta(hours=1), "trusted_partner_small_transfer"),
        ]
        for number, severity, age, rule in entries:
            store.add(
                make_incident(
                    incident_id=number * 32,
                    severity=severity,
                    rule=rule,
                    timestamp=timestamp_before(age),
                    source=f"/outbox/file{number}.csv",
                )
            )
        return path

    def query(self, runner, db, *args):
        return invoke(runner, "incident-log", "query", "--db", db, *args)

    def test_severity_high_in_the_last_seven_days(self, runner, db):
        result = self.query(runner, db, "--severity", "high", "--last", "7d")
        assert result.exit_code == 0
        assert "file1.csv" in result.stdout and "file3.csv" not in result.stdout
        assert "critical" not in result.stdout and "1 incident(s)" in result.stdout

    def test_table_has_a_header_and_masked_findings_summary(self, runner, db):
        result = self.query(runner, db)
        header, first = result.stdout.splitlines()[:2]
        assert header.startswith("TIMESTAMP (UTC)") and "SEVERITY" in header
        assert "credit_cardx1" in first and "quarantine:ok" in first

    def test_newest_first(self, runner, db):
        sources = [line.split()[-1] for line in self.query(runner, db).stdout.splitlines()[1:5]]
        assert sources == [
            "/outbox/file4.csv",
            "/outbox/file1.csv",
            "/outbox/file2.csv",
            "/outbox/file3.csv",
        ]

    def test_severity_may_repeat_and_is_case_insensitive(self, runner, db):
        result = self.query(
            runner, db, "--severity", "HIGH", "--severity", "critical", "--format", "json"
        )
        assert {i["severity"] for i in json.loads(result.stdout)} == {"high", "critical"}

    def test_rule_limit_and_json(self, runner, db):
        result = self.query(
            runner, db, "--rule", "card_data_to_external", "--limit", "1", "--format", "json"
        )
        (incident,) = json.loads(result.stdout)
        assert incident["incident_id"] == "1" * 32

    def test_underscore_alias(self, runner, db):
        result = invoke(runner, "incident_log", "query", "--db", db, "--severity", "low")
        assert result.exit_code == 0 and "file4.csv" in result.stdout

    def test_no_match(self, runner, db):
        result = self.query(runner, db, "--severity", "medium")
        assert result.exit_code == 0 and "no incidents match" in result.stdout

    def test_invalid_duration_and_severity(self, runner, db):
        assert "invalid duration" in self.query(runner, db, "--last", "soon").stderr
        assert self.query(runner, db, "--severity", "urgent").exit_code == 2

    def test_missing_database(self, runner, tmp_path):
        result = self.query(runner, tmp_path / "none.db")
        assert result.exit_code == 1 and "no incident database" in result.stderr

    def test_database_path_from_the_environment(self, runner, db, monkeypatch):
        monkeypatch.setenv("DLP_DB_PATH", str(db))
        result = invoke(runner, "incident-log", "query", "--severity", "critical")
        assert "file2.csv" in result.stdout

    def test_dynamodb_backend(self, runner):
        with mock_aws():
            create_incident_table(boto3.client("dynamodb"), "incidents")
            store = DynamoDbIncidentStore.from_table_name("incidents")
            store.add(make_incident(timestamp=timestamp_before(timedelta(days=1))))
            store.add(
                make_incident(
                    incident_id="b" * 32,
                    severity="low",
                    timestamp=timestamp_before(timedelta(days=1)),
                )
            )
            result = invoke(
                runner, "incident-log", "query", "--backend", "dynamodb", "--table", "incidents",
                "--severity", "high", "--last", "7d", "--format", "json",
            )  # fmt: skip
        assert result.exit_code == 0, result.output
        assert [i["severity"] for i in json.loads(result.stdout)] == ["high"]

    def test_dynamodb_backend_needs_a_table(self, runner):
        result = invoke(runner, "incident-log", "query", "--backend", "dynamodb")
        assert result.exit_code == 2 and "--table" in result.stderr


class TestWatchStart:
    def test_invalid_policy_stops_before_watching(self, runner, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("rules: []\n")
        result = invoke(runner, "watch", "start", "--policy", bad, "--watch-dir", tmp_path / "o")
        assert result.exit_code == 2 and "Invalid policy" in result.stderr

    def test_invalid_webhook_url_is_rejected(self, runner, tmp_path):
        result = invoke(
            runner, "watch", "start", "--policy", EXAMPLE_POLICY, "--watch-dir", tmp_path / "o",
            "--db", tmp_path / "db", "--webhook-url", "http://example.org/hook",
        )  # fmt: skip
        assert result.exit_code == 1 and "invalid webhook URL" in result.stderr

    def test_end_to_end_in_a_real_process(self, tmp_path, make_card_csv, card_numbers):
        outbox, quarantine = tmp_path / "outbox", tmp_path / "quarantine"
        db, log = tmp_path / "incidents.db", tmp_path / "incidents.jsonl"
        env = {k: v for k, v in os.environ.items() if not k.startswith("DLP_")}
        process = subprocess.Popen(
            [
                sys.executable, str(REPO_ROOT / "cli.py"), "watch", "start",
                "--watch-dir", str(outbox), "--policy", str(EXAMPLE_POLICY),
                "--quarantine-dir", str(quarantine), "--db", str(db),
                "--log-file", str(log), "--settle-seconds", "0.2",
            ],
            cwd=tmp_path, env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )  # fmt: skip
        try:
            deadline = time.monotonic() + 15
            while not outbox.exists() and time.monotonic() < deadline:
                time.sleep(0.05)
            target = outbox / "external_email"
            target.mkdir()
            (target / "customers.csv").write_text(make_card_csv(card_numbers(2)))
            while (
                not (db.exists() and SqliteIncidentStore(db).query())
                and time.monotonic() < deadline
            ):
                time.sleep(0.1)
        finally:
            process.send_signal(signal.SIGINT)
            output, _ = process.communicate(timeout=20)

        assert process.returncode == 0, output
        assert "ALERT [DLP][HIGH] card_data_to_external" in output
        assert "stopping..." in output
        (incident,) = SqliteIncidentStore(db).query()
        assert incident["rule"] == "card_data_to_external"
        logged = [json.loads(line) for line in log.read_text().splitlines()]
        assert [entry["incident_id"] for entry in logged] == [incident["incident_id"]]
        assert any(path.name.endswith("customers.csv") for path in quarantine.iterdir())
        assert not (target / "customers.csv").exists()
