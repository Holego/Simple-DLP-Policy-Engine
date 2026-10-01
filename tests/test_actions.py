import json
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from src.actions import (
    ActionContext,
    ActionExecutor,
    ActionResult,
    AlertAction,
    LocalBlock,
    LocalQuarantine,
    WebhookNotifier,
    build_alert_payload,
    is_blocked,
)
from src.actions.notifiers import SnsNotifier, detect_webhook_kind, validate_webhook_url
from src.detectors import Finding, summarize
from src.engine import Destination, PolicyEngine
from tests.conftest import EXAMPLE_POLICY

RAW_CARD = "4111111111111111"  # never stored anywhere: findings are built pre-masked


def make_ctx(
    target, *, recipient="someone@other.example.org", cards=1, evaluation_id="ab12cd34ef56"
):
    findings = [
        Finding("credit_card", "****-****-****-1111", i * 20, i * 20 + 16) for i in range(cards)
    ]
    destination = Destination(channel="email", recipient=recipient)
    decision = PolicyEngine.from_file(EXAMPLE_POLICY).evaluate(findings, destination)
    return ActionContext(
        mode="local",
        source=str(target),
        target=target,
        destination=destination,
        decision=decision,
        summaries=summarize(findings),
        evaluation_id=evaluation_id,
        timestamp="2026-01-01T10:00:00.000Z",
        file_info={"name": Path(str(target)).name, "size": 42},
    )


class Recorder:
    def __init__(self, name, status="ok", error=None, calls=None):
        self.name, self.status, self.error = name, status, error
        self.calls = calls if calls is not None else []

    def run(self, ctx):
        self.calls.append((self.name, [r.action for r in ctx.results]))
        if self.error:
            raise self.error
        return ActionResult(self.name, self.status)


class FakeNotifier:
    def __init__(self, name, fail=False):
        self.name, self.fail, self.sent = name, fail, []

    def send(self, payload):
        if self.fail:
            raise RuntimeError(f"{self.name} down")
        self.sent.append(payload)


class TestExecutor:
    def test_runs_disposition_before_alert_and_passes_earlier_results_on(self, tmp_path):
        ctx = make_ctx(tmp_path / "f.csv")
        calls: list = []
        executor = ActionExecutor(
            [Recorder("alert", calls=calls), Recorder("quarantine", calls=calls)]
        )
        results = executor.execute(ctx)
        assert [r.action for r in results] == ["quarantine", "alert"]
        assert calls == [("quarantine", []), ("alert", ["quarantine"])]

    def test_a_failing_handler_does_not_stop_the_others(self, tmp_path):
        ctx = make_ctx(tmp_path / "f.csv")
        executor = ActionExecutor(
            [Recorder("quarantine", error=OSError("disk full")), Recorder("alert")]
        )
        results = executor.execute(ctx)
        assert [(r.action, r.status) for r in results] == [
            ("quarantine", "failed"),
            ("alert", "ok"),
        ]
        assert "OSError: disk full" in results[0].detail

    def test_missing_handler_is_reported_as_skipped(self, tmp_path):
        results = ActionExecutor([Recorder("alert")]).execute(make_ctx(tmp_path / "f.csv"))
        assert (results[0].action, results[0].status) == ("quarantine", "skipped")


class TestLocalQuarantine:
    def test_moves_file_and_manifest_and_writes_masked_evidence(self, tmp_path):
        source = tmp_path / "out" / "export.csv"
        source.parent.mkdir()
        source.write_text("data")
        manifest = source.with_name("export.csv.meta.json")
        manifest.write_text("{}")
        quarantine = tmp_path / "q"

        result = LocalQuarantine(quarantine).run(make_ctx(source))

        assert result.status == "ok"
        assert not source.exists() and not manifest.exists()
        (moved,) = [p for p in quarantine.iterdir() if p.name.endswith("export.csv")]
        assert moved.read_text() == "data"
        assert (quarantine / (moved.name + ".meta.json")).exists()
        evidence = json.loads((quarantine / (moved.name + ".incident.json")).read_text())
        assert evidence["severity"] == "high"
        assert evidence["findings"][0]["samples"] == ["****-****-****-1111"]
        assert RAW_CARD not in json.dumps(evidence)

    def test_quarantine_is_private(self, tmp_path):
        source = tmp_path / "f.txt"
        source.write_text("x")
        LocalQuarantine(tmp_path / "q").run(make_ctx(source))
        assert (tmp_path / "q").stat().st_mode & 0o777 == 0o700
        for entry in (tmp_path / "q").iterdir():
            assert entry.stat().st_mode & 0o777 == 0o600

    def test_unsafe_file_names_are_sanitised(self, tmp_path):
        source = tmp_path / "..evil name;$(rm -rf).csv"
        source.write_text("x")
        LocalQuarantine(tmp_path / "q").run(make_ctx(source))
        (moved,) = [p for p in (tmp_path / "q").iterdir() if p.suffix == ".csv"]
        assert moved.parent == tmp_path / "q"
        assert all(ch.isalnum() or ch in "._-" for ch in moved.name)

    def test_same_name_from_different_events_does_not_collide(self, tmp_path):
        quarantine = LocalQuarantine(tmp_path / "q")
        for evaluation_id in ("11111111aaaa", "22222222bbbb"):
            source = tmp_path / "same.csv"
            source.write_text(evaluation_id)
            quarantine.run(make_ctx(source, evaluation_id=evaluation_id))
        assert len([p for p in (tmp_path / "q").iterdir() if p.suffix == ".csv"]) == 2

    def test_missing_source_raises_so_the_executor_can_record_a_failure(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            LocalQuarantine(tmp_path / "q").run(make_ctx(tmp_path / "gone.csv"))


class TestLocalBlock:
    def test_withdraws_access_and_leaves_a_marker(self, tmp_path):
        source = tmp_path / "f.csv"
        source.write_text("x")
        result = LocalBlock().run(make_ctx(source, cards=4))
        assert result.status == "ok"
        assert source.exists() and source.stat().st_mode & 0o777 == 0
        assert is_blocked(source)
        marker = json.loads(source.with_name("f.csv.dlp-blocked").read_text())
        assert marker["severity"] == "critical"

    def test_unblocked_files_are_not_reported_as_blocked(self, tmp_path):
        (tmp_path / "f.csv").write_text("x")
        assert not is_blocked(tmp_path / "f.csv")


class TestAlertAction:
    def test_every_notifier_receives_the_same_payload(self, tmp_path):
        first, second = FakeNotifier("a"), FakeNotifier("b")
        ctx = make_ctx(tmp_path / "f.csv")
        result = AlertAction([first, second]).run(ctx)
        assert result.status == "ok" and result.detail == "a:ok, b:ok"
        assert first.sent == second.sent and len(first.sent) == 1

    def test_one_failing_channel_gives_a_partial_result(self, tmp_path):
        good, bad = FakeNotifier("good"), FakeNotifier("bad", fail=True)
        result = AlertAction([bad, good]).run(make_ctx(tmp_path / "f.csv"))
        assert result.status == "partial"
        assert "bad:failed (bad down)" in result.detail and good.sent

    def test_all_channels_failing_is_a_failure(self, tmp_path):
        result = AlertAction([FakeNotifier("x", fail=True)]).run(make_ctx(tmp_path / "f.csv"))
        assert result.status == "failed"

    def test_alert_reports_the_outcome_of_the_disposition(self, tmp_path):
        ctx = make_ctx(tmp_path / "f.csv")
        ctx.results.append(ActionResult("quarantine", "failed", "disk full"))
        text = build_alert_payload(ctx).text()
        assert "enforcement: quarantine (failed)" in text

    def test_alert_only_decisions_say_that_nothing_was_enforced(self, tmp_path):
        ctx = make_ctx(tmp_path / "f.csv", recipient="ap@partner.example.net", cards=2)
        assert "enforcement: none (alert only)" in build_alert_payload(ctx).text()


class TestAlertPayload:
    def test_text_contains_context_but_only_masked_values(self, tmp_path):
        ctx = make_ctx(tmp_path / "f.csv", cards=2)
        text = build_alert_payload(ctx).text()
        assert text.startswith("[DLP][HIGH] card_data_to_external")
        assert "external_email" in text and "credit_card x2" in text
        assert "****-****-****-1111" in text and RAW_CARD not in text

    def test_overridden_rules_are_listed_separately(self, tmp_path):
        ctx = make_ctx(tmp_path / "f.csv", cards=4)
        payload = build_alert_payload(ctx)
        assert payload.title() == "[DLP][CRITICAL] bulk_card_data_to_risky_destination"
        assert "also matched (overridden by priority): card_data_to_external" in payload.text()

    def test_recipient_is_masked_in_the_payload(self, tmp_path):
        payload = build_alert_payload(
            make_ctx(tmp_path / "f.csv", recipient="jane@other.example.org")
        )
        assert payload.destination["recipient"] == "j***@other.example.org"

    def test_sns_subject_is_ascii_single_line_and_short(self, tmp_path):
        payload = build_alert_payload(make_ctx(tmp_path / "f.csv"))
        rules = ({"name": "r\u00e9gle\n" + "x" * 200, "severity": "high", "suppressed_by": None},)
        subject = replace(payload, rules=rules).subject()
        assert len(subject) == 100 and subject.isascii() and "\n" not in subject
        assert subject.startswith("[DLP][HIGH] r?gle")


class WebhookServer:
    def __init__(self, status=200, location=None):
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append(
                    {"path": self.path, "body": json.loads(body), "headers": dict(self.headers)}
                )
                self.send_response(status)
                if location:
                    self.send_header("Location", location)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}/hook/SECRET-TOKEN"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


class TestWebhookNotifier:
    @pytest.fixture
    def payload(self, tmp_path):
        return build_alert_payload(make_ctx(tmp_path / "f.csv"))

    def test_generic_body_is_the_full_payload(self, payload):
        with WebhookServer() as server:
            WebhookNotifier(server.url, kind="generic").send(payload)
        (request,) = server.requests
        assert request["body"]["severity"] == "high"
        assert request["body"]["rules"][0]["name"] == "card_data_to_external"
        assert request["headers"]["Content-Type"] == "application/json"

    def test_slack_body_uses_the_text_field(self, payload):
        with WebhookServer() as server:
            WebhookNotifier(server.url, kind="slack").send(payload)
        assert server.requests[0]["body"] == {"text": payload.text()}

    def test_discord_body_uses_content_and_respects_the_length_limit(self, payload):
        notifier = WebhookNotifier("http://127.0.0.1:1/x", kind="discord")
        body = notifier.build_body(payload)
        assert set(body) == {"content"} and len(body["content"]) <= 1900

    def test_http_errors_are_reported_without_leaking_the_url(self, payload):
        with WebhookServer(status=500) as server, pytest.raises(RuntimeError) as excinfo:
            WebhookNotifier(server.url).send(payload)
        assert "HTTP 500" in str(excinfo.value) and "SECRET-TOKEN" not in str(excinfo.value)

    def test_redirects_are_not_followed(self, payload):
        redirecting = WebhookServer(status=302, location="http://127.0.0.1:1/elsewhere")
        with redirecting as server, pytest.raises(RuntimeError, match="HTTP 302"):
            WebhookNotifier(server.url).send(payload)

    def test_unreachable_endpoint_raises_a_clean_error(self, payload):
        with pytest.raises(RuntimeError) as excinfo:
            WebhookNotifier("http://127.0.0.1:1/hook/SECRET-TOKEN", timeout=1).send(payload)
        assert "unreachable" in str(excinfo.value) and "SECRET-TOKEN" not in str(excinfo.value)

    @pytest.mark.parametrize(
        ("url", "kind"),
        [
            ("https://hooks.slack.com/services/T/B/x", "slack"),
            ("https://discord.com/api/webhooks/1/x", "discord"),
            ("https://example.org/hook", "generic"),
        ],
    )
    def test_kind_is_detected_from_the_host(self, url, kind):
        assert detect_webhook_kind(url) == kind
        assert WebhookNotifier(url).kind == kind

    @pytest.mark.parametrize(
        "url",
        [
            "http://example.org/hook",
            "ftp://example.org/hook",
            "https://user:pw@example.org/hook",
            "not a url",
            "",
        ],
    )
    def test_unsafe_urls_are_rejected(self, url):
        with pytest.raises(ValueError):
            validate_webhook_url(url)

    def test_alert_action_survives_a_dead_webhook(self, tmp_path):
        notifier = WebhookNotifier("http://127.0.0.1:1/x", timeout=1)
        result = AlertAction([notifier]).run(make_ctx(tmp_path / "f.csv"))
        assert result.status == "failed" and "webhook:failed" in result.detail


def test_sns_notifier_publishes_json_with_severity_attribute(tmp_path):
    class FakeSns:
        def publish(self, **kwargs):
            self.kwargs = kwargs

    client = FakeSns()
    payload = build_alert_payload(make_ctx(tmp_path / "f.csv"))
    SnsNotifier(client, "arn:aws:sns:us-east-1:111111111111:t").send(payload)
    assert client.kwargs["TopicArn"].endswith(":t")
    assert json.loads(client.kwargs["Message"])["severity"] == "high"
    assert client.kwargs["MessageAttributes"]["severity"]["StringValue"] == "high"
