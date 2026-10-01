#!/usr/bin/env python3
"""Generate synthetic files that exercise the example policy, locally or in S3.

Everything is produced with Faker; no real card numbers or personal data are used.

    python scripts/seed_test_files.py list
    python scripts/seed_test_files.py local --out ./outbox
    python scripts/seed_test_files.py s3 --bucket dlp-dev-outbound-123456789012

Each scenario carries the outcome config/policies.example.yaml should produce, and the test
suite checks that the generated data really does. Local files are written together with the
destination manifest; S3 objects get the matching ``dlp-destination`` / ``dlp-recipient`` tags.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlencode

from faker import Faker

CARD_TYPES = ("visa16", "mastercard", "amex", "discover", "visa13")
EXTERNAL_DOMAIN = "vendor.example.org"
PARTNER_DOMAIN = "partner.example.net"


@dataclass(frozen=True)
class Scenario:
    name: str
    filename: str
    build: Callable[[Faker], str]
    description: str
    # Where the file is headed: a folder under the outbox named after a destination category,
    # and/or a manifest (written next to the file / used for S3 tags).
    folder: str = ""
    manifest: dict[str, object] = field(default_factory=dict)
    # What config/policies.example.yaml should do with it.
    expected_rules: tuple[str, ...] = ()
    expected_actions: tuple[str, ...] = ()
    # Only when the outcome in S3 differs from the local one.
    s3_expected_rules: tuple[str, ...] | None = None
    s3_expected_actions: tuple[str, ...] | None = None
    s3_note: str = ""

    @property
    def s3_rules(self) -> tuple[str, ...]:
        return self.expected_rules if self.s3_expected_rules is None else self.s3_expected_rules

    @property
    def s3_actions(self) -> tuple[str, ...]:
        return (
            self.expected_actions if self.s3_expected_actions is None else self.s3_expected_actions
        )


def cards(fake: Faker, count: int) -> list[str]:
    return [
        fake.credit_card_number(card_type=CARD_TYPES[i % len(CARD_TYPES)]) for i in range(count)
    ]


def card_export(fake: Faker, count: int) -> str:
    lines = ["customer,card_number,expires"]
    lines += [
        f"{fake.name()},{number},{fake.credit_card_expire()}" for number in cards(fake, count)
    ]
    return "\n".join(lines) + "\n"


def ssn_export(fake: Faker, count: int) -> str:
    lines = ["employee,ssn,department"]
    lines += [f"{fake.name()},{fake.ssn()},{fake.job()}" for _ in range(count)]
    return "\n".join(lines) + "\n"


def email_list(fake: Faker, count: int) -> str:
    return "name,email\n" + "\n".join(f"{fake.name()},{fake.email()}" for _ in range(count)) + "\n"


def near_misses(fake: Faker) -> str:
    """Data that looks sensitive but fails validation: no detector should fire."""
    broken_cards = []
    for number in cards(fake, 3):
        broken_cards.append(number[:-1] + str((int(number[-1]) + 1) % 10))  # bad check digit
    invalid_ssns = ["000-12-3456", "666-45-6789", "912-34-5678", "123-00-4567", "123-45-0000"]
    order_ids = [f"ORD-{fake.random_number(digits=12, fix_len=True)}" for _ in range(3)]
    return (
        "Reconciliation notes\n"
        + "\n".join(f"declined attempt {n}" for n in broken_cards)
        + "\n"
        + "\n".join(f"form reference {s}" for s in invalid_ssns)
        + "\n"
        + "\n".join(order_ids)
        + "\n"
    )


def hr_onboarding(fake: Faker) -> str:
    return (
        f"Onboarding for {fake.name()}\n"
        f"Social security number: {fake.ssn()}\n"
        f"Reimbursement card: {cards(fake, 1)[0]}\n"
    )


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        name="customer_export_to_vendor",
        filename="customers_q1.csv",
        build=lambda fake: card_export(fake, 3),
        description="3 card numbers emailed to an outside recipient",
        manifest={"channel": "email", "recipient": f"orders@{EXTERNAL_DOMAIN}"},
        expected_rules=("card_data_to_external",),
        expected_actions=("quarantine", "alert"),
    ),
    Scenario(
        name="card_dump_to_public_bucket",
        filename="card_dump.csv",
        build=lambda fake: card_export(fake, 6),
        description="6 card numbers uploaded to a public S3 bucket (bulk, so blocked)",
        folder="public_s3",
        expected_rules=("bulk_card_data_to_risky_destination",),
        expected_actions=("block", "alert"),
    ),
    Scenario(
        name="payroll_to_cloud_storage",
        filename="payroll.csv",
        build=lambda fake: ssn_export(fake, 4),
        description="SSNs copied to consumer cloud storage",
        folder="cloud_storage",
        expected_rules=("ssn_to_cloud_or_removable_media",),
        expected_actions=("quarantine", "alert"),
    ),
    Scenario(
        name="invoice_to_trusted_partner",
        filename="invoice_batch.txt",
        build=lambda fake: card_export(fake, 2),
        description="2 card numbers to a trusted partner: the exception rule only alerts",
        manifest={"channel": "email", "recipient": f"ap@{PARTNER_DOMAIN}"},
        expected_rules=("trusted_partner_small_transfer",),
        expected_actions=("alert",),
    ),
    Scenario(
        name="newsletter_list_export",
        filename="subscribers.csv",
        build=lambda fake: email_list(fake, 60),
        description="60 email addresses sent outside the company",
        manifest={"channel": "email", "recipient": f"marketing@{EXTERNAL_DOMAIN}"},
        expected_rules=("bulk_email_list_export",),
        expected_actions=("alert",),
    ),
    Scenario(
        name="onboarding_without_destination",
        filename="onboarding.txt",
        build=hr_onboarding,
        description="card + SSN with no destination information (fail closed: alert)",
        expected_rules=("identity_bundle_unknown_destination",),
        expected_actions=("alert",),
        s3_expected_rules=(),
        s3_expected_actions=(),
        s3_note="in S3 the bucket is known to be private, so the destination is not unknown",
    ),
    Scenario(
        name="internal_audit_export",
        filename="audit_cards.csv",
        build=lambda fake: card_export(fake, 8),
        description="8 card numbers that stay inside the company: allowed",
        folder="internal",
    ),
    Scenario(
        name="meeting_notes_to_vendor",
        filename="meeting_notes.txt",
        build=lambda fake: "\n\n".join(fake.paragraph(nb_sentences=6) for _ in range(5)) + "\n",
        description="plain text to an outside recipient: nothing sensitive, allowed",
        manifest={"channel": "email", "recipient": f"team@{EXTERNAL_DOMAIN}"},
    ),
    Scenario(
        name="near_misses_to_vendor",
        filename="reconciliation.txt",
        build=near_misses,
        description="Luhn-invalid cards, impossible SSNs and order ids: validation rejects them",
        manifest={"channel": "email", "recipient": f"billing@{EXTERNAL_DOMAIN}"},
    ),
)


def new_faker(seed: int) -> Faker:
    fake = Faker("en_US")
    fake.seed_instance(seed)
    return fake


def destination_category(scenario: Scenario) -> str | None:
    return scenario.folder or None


def write_local(out: Path, seed: int) -> list[Path]:
    """Write every scenario under ``out``; manifests are written before their files."""
    fake = new_faker(seed)
    written: list[Path] = []
    for scenario in SCENARIOS:
        directory = out / scenario.folder if scenario.folder else out
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / scenario.filename
        if scenario.manifest:
            path.with_name(path.name + ".meta.json").write_text(
                json.dumps(scenario.manifest, indent=2) + "\n"
            )
        path.write_text(scenario.build(fake))
        written.append(path)
    return written


def s3_tags(scenario: Scenario) -> dict[str, str]:
    tags: dict[str, str] = {}
    category = destination_category(scenario)
    if category:
        tags["dlp-destination"] = category
    elif scenario.manifest.get("channel") == "email":
        tags["dlp-destination"] = "external_email"
    if recipient := scenario.manifest.get("recipient"):
        tags["dlp-recipient"] = str(recipient)
    return tags


def upload_s3(bucket: str, seed: int, prefix: str, endpoint_url: str | None) -> list[str]:
    import boto3

    client = boto3.client("s3", endpoint_url=endpoint_url)
    fake = new_faker(seed)
    keys: list[str] = []
    for scenario in SCENARIOS:
        key = f"{prefix}{scenario.filename}"
        client.put_object(
            Bucket=bucket,
            Key=key,
            Body=scenario.build(fake).encode(),
            Tagging=urlencode(s3_tags(scenario)),
        )
        keys.append(key)
    return keys


def print_scenarios() -> None:
    for scenario in SCENARIOS:
        outcome = ", ".join(scenario.expected_actions) or "allowed, no incident"
        rules = ", ".join(scenario.expected_rules) or "-"
        print(f"{scenario.name}")
        print(f"    {scenario.description}")
        print(f"    rule: {rules}")
        print(f"    outcome: {outcome}")
        if scenario.s3_note:
            print(f"    in S3: {scenario.s3_note}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="describe the scenarios and their expected outcome")

    local = sub.add_parser("local", help="write files into a watched outbox folder")
    local.add_argument("--out", type=Path, default=Path("outbox"))
    local.add_argument("--seed", type=int, default=42)

    s3 = sub.add_parser("s3", help="upload objects with destination tags to a bucket")
    s3.add_argument("--bucket", required=True)
    s3.add_argument("--prefix", default="demo/")
    s3.add_argument("--endpoint-url", help="e.g. http://localhost:4566 for LocalStack")
    s3.add_argument("--seed", type=int, default=42)

    args = parser.parse_args(argv)
    if args.command == "list":
        print_scenarios()
    elif args.command == "local":
        paths = write_local(args.out, args.seed)
        print(f"wrote {len(paths)} files to {args.out}")
        print_scenarios()
    else:
        keys = upload_s3(args.bucket, args.seed, args.prefix, args.endpoint_url)
        print(f"uploaded {len(keys)} objects to s3://{args.bucket}/{args.prefix}")
        print_scenarios()
    return 0


if __name__ == "__main__":
    sys.exit(main())
