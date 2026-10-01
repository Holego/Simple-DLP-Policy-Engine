"""Shared fixtures and helpers. All sensitive-looking data is synthetic."""

from __future__ import annotations

import os
import random
import textwrap
from pathlib import Path

import pytest
from faker import Faker

from src.detectors import luhn_valid

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE_POLICY = REPO_ROOT / "config" / "policies.example.yaml"

# Card brands whose number format the detector claims to support.
SUPPORTED_CARD_TYPES = ("visa16", "visa13", "visa19", "mastercard", "amex", "discover", "diners")


@pytest.fixture(scope="session")
def fake() -> Faker:
    faker = Faker("en_US")
    Faker.seed(20240601)
    return faker


@pytest.fixture
def card_numbers(fake: Faker):
    """Factory returning ``n`` synthetic, Luhn-valid card numbers from the supported brands."""

    def make(n: int = 1) -> list[str]:
        return [
            fake.credit_card_number(card_type=SUPPORTED_CARD_TYPES[i % len(SUPPORTED_CARD_TYPES)])
            for i in range(n)
        ]

    return make


def break_luhn(number: str) -> str:
    """Change the check digit so the number fails the Luhn test."""
    assert luhn_valid(number)
    return number[:-1] + str((int(number[-1]) + 1) % 10)


@pytest.fixture
def invalid_card_number(card_numbers) -> str:
    return break_luhn(card_numbers(1)[0])


def card_csv(numbers: list[str], fake: Faker) -> str:
    """A small CSV export with one card per row."""
    rows = ["name,card_number,expires"]
    rows += [f"{fake.name()},{number},{fake.credit_card_expire()}" for number in numbers]
    return "\n".join(rows) + "\n"


@pytest.fixture
def make_card_csv(fake: Faker):
    return lambda numbers: card_csv(numbers, fake)


@pytest.fixture
def policy_text() -> str:
    """A compact policy used by most pipeline-level tests."""
    return textwrap.dedent(
        """
        version: 1
        settings:
          corporate_domains: [corp.example.com]
        rules:
          - rule: card_data_to_external
            severity: high
            condition:
              contains: [credit_card, ssn]
              destination: [external_email, public_s3, non_corporate_domain]
            action: [alert, quarantine]
        """
    )


@pytest.fixture
def policy_file(tmp_path: Path, policy_text: str) -> Path:
    path = tmp_path / "policies.yaml"
    path.write_text(policy_text)
    return path


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch):
    """Keep real credentials, endpoints and DLP settings out of every test."""
    for name in list(os.environ):
        if name.startswith("DLP_") or name in {"AWS_ENDPOINT_URL", "AWS_PROFILE"}:
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture
def rng() -> random.Random:
    return random.Random(7)
