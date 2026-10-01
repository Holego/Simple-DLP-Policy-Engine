"""The seed scenarios must do what their descriptions promise, or the demo would lie."""

import importlib.util
import sys

import boto3
import pytest
from moto import mock_aws

from src.actions.targets import S3Object
from src.detectors import Scanner
from src.engine import PolicyEngine
from src.watchers.manifest import LocalDestinationResolver
from src.watchers.s3 import S3DestinationResolver
from tests.conftest import EXAMPLE_POLICY, REPO_ROOT

spec = importlib.util.spec_from_file_location("seed", REPO_ROOT / "scripts" / "seed_test_files.py")
seed = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = seed
spec.loader.exec_module(seed)

SCENARIO_IDS = [scenario.name for scenario in seed.SCENARIOS]


@pytest.fixture(scope="module")
def engine():
    return PolicyEngine.from_file(EXAMPLE_POLICY)


def local_path(out, scenario):
    return (
        (out / scenario.folder / scenario.filename) if scenario.folder else out / scenario.filename
    )


@pytest.mark.parametrize("scenario", seed.SCENARIOS, ids=SCENARIO_IDS)
def test_local_scenarios_produce_the_documented_outcome(tmp_path, engine, scenario):
    out = tmp_path / "outbox"
    seed.write_local(out, seed=7)
    path = local_path(out, scenario)

    destination = LocalDestinationResolver(out).resolve(path)
    findings = Scanner().scan_bytes(path.read_bytes())
    decision = engine.evaluate(findings, destination)

    winners = tuple(match.rule.name for match in decision.winning)
    assert winners == scenario.expected_rules
    assert decision.actions == scenario.expected_actions


@pytest.mark.parametrize("scenario", seed.SCENARIOS, ids=SCENARIO_IDS)
def test_s3_scenarios_produce_the_documented_outcome(engine, scenario):
    with mock_aws():
        s3 = boto3.client("s3")
        s3.create_bucket(Bucket="demo")
        seed.upload_s3("demo", seed=7, prefix="demo/", endpoint_url=None)
        key = f"demo/{scenario.filename}"
        body = s3.get_object(Bucket="demo", Key=key)["Body"].read()

        destination = S3DestinationResolver(s3).resolve(S3Object("demo", key))
        decision = engine.evaluate(Scanner().scan_bytes(body), destination)

    assert tuple(m.rule.name for m in decision.winning) == scenario.s3_rules
    assert decision.actions == scenario.s3_actions


def test_generation_is_deterministic_per_seed(tmp_path):
    first, second, other = tmp_path / "a", tmp_path / "b", tmp_path / "c"
    seed.write_local(first, seed=1)
    seed.write_local(second, seed=1)
    seed.write_local(other, seed=2)
    name = "customers_q1.csv"
    assert (first / name).read_text() == (second / name).read_text()
    assert (first / name).read_text() != (other / name).read_text()


def test_manifests_are_written_before_their_files(tmp_path, monkeypatch):
    order = []
    original = type(tmp_path).write_text

    def spy(self, *args, **kwargs):
        order.append(self.name)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(type(tmp_path), "write_text", spy)
    seed.write_local(tmp_path / "out", seed=1)
    assert order.index("customers_q1.csv.meta.json") < order.index("customers_q1.csv")


def test_near_miss_scenario_really_contains_lookalike_data(tmp_path):
    seed.write_local(tmp_path, seed=3)
    text = (tmp_path / "reconciliation.txt").read_text()
    assert "000-12-3456" in text and "ORD-" in text
    assert Scanner().scan_text(text) == []


def test_command_line_entry_points(tmp_path, capsys):
    assert seed.main(["list"]) == 0
    assert "customer_export_to_vendor" in capsys.readouterr().out
    assert seed.main(["local", "--out", str(tmp_path / "o"), "--seed", "5"]) == 0
    assert (tmp_path / "o" / "public_s3" / "card_dump.csv").exists()
    assert "wrote 9 files" in capsys.readouterr().out
