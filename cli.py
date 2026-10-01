#!/usr/bin/env python3
"""Command line interface of the DLP policy engine.

    python cli.py policy validate config/policies.example.yaml
    python cli.py policy test --policy config/policies.example.yaml --file report.csv \\
        --destination external_email
    python cli.py incident-log query --severity high --last 7d
    python cli.py incident-log query --backend dynamodb --table dlp-dev-incidents --last 24h
    python cli.py watch start --watch-dir ./outbox
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading
from datetime import timedelta
from pathlib import Path
from typing import Any

import click

try:  # optional: read settings from a .env file in the working directory
    from dotenv import find_dotenv, load_dotenv
except ImportError:  # pragma: no cover - python-dotenv is in requirements.txt
    find_dotenv = load_dotenv = None

from src.detectors import Scanner, summarize
from src.engine import (
    KNOWN_DESTINATIONS,
    Destination,
    PolicyEngine,
    PolicyValidationError,
    load_policy_file,
)
from src.engine.models import SEVERITY_LABELS
from src.incident import describe_actions, timestamp_before
from src.settings import LocalSettings
from src.storage import DEFAULT_QUERY_LIMIT, SqliteIncidentStore, parse_duration

CONTEXT_SETTINGS = {"help_option_names": ["-h", "--help"], "max_content_width": 100}


# -- helpers -------------------------------------------------------------------------------


def load_engine(path: Path) -> PolicyEngine:
    try:
        return PolicyEngine(load_policy_file(path))
    except PolicyValidationError as exc:
        click.echo(f"Invalid policy {path}:", err=True)
        for error in exc.errors:
            click.echo(f"  - {error}", err=True)
        raise SystemExit(2) from None


def configure_logging(verbose: bool, log_file: Path | None) -> None:
    """Console: alerts and warnings. File: one JSON incident per line."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    alerts = logging.getLogger("dlp.alerts")
    alerts.propagate = False
    alerts.handlers.clear()
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(asctime)s ALERT %(message)s", "%H:%M:%S"))
    alerts.addHandler(console)

    incidents = logging.getLogger("dlp.incident")
    incidents.propagate = verbose
    incidents.handlers.clear()
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        incidents.addHandler(handler)
        incidents.setLevel(logging.INFO)


def _shorten(text: str, width: int) -> str:
    return text if len(text) <= width else "..." + text[-(width - 3) :]


def _finding_text(incident: dict[str, Any]) -> str:
    return ", ".join(f"{f['type']}x{f['count']}" for f in incident.get("findings", []))


def format_table(incidents: list[dict[str, Any]]) -> str:
    headers = ("TIMESTAMP (UTC)", "SEVERITY", "RULE", "ACTIONS", "FINDINGS", "SOURCE")
    rows = [
        (
            incident["timestamp"],
            incident["severity"],
            incident["rule"],
            describe_actions(incident),
            _finding_text(incident),
            _shorten(incident["source"], 60),
        )
        for incident in incidents
    ]
    widths = [max(len(str(item)) for item in column) for column in zip(headers, *rows, strict=True)]
    lines = ["  ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)).rstrip()]
    lines += [
        "  ".join(str(c).ljust(w) for c, w in zip(row, widths, strict=True)).rstrip()
        for row in rows
    ]
    return "\n".join(lines)


# -- root ----------------------------------------------------------------------------------


@click.group(context_settings=CONTEXT_SETTINGS)
def cli() -> None:
    """Simple DLP policy engine: validate policies, watch folders, query incidents."""
    if load_dotenv and find_dotenv:
        load_dotenv(find_dotenv(usecwd=True))


# -- policy --------------------------------------------------------------------------------


@cli.group(context_settings=CONTEXT_SETTINGS)
def policy() -> None:
    """Work with policy files."""


@policy.command("validate", context_settings=CONTEXT_SETTINGS)
@click.argument("path", type=click.Path(dir_okay=False, path_type=Path))
def policy_validate(path: Path) -> None:
    """Check a policy file and list its rules. Exits with status 2 if it is invalid."""
    try:
        config = load_policy_file(path)
    except PolicyValidationError as exc:
        click.echo(f"INVALID  {path}", err=True)
        for error in exc.errors:
            click.echo(f"  - {error}", err=True)
        raise SystemExit(2) from None

    enabled = sum(rule.enabled for rule in config.rules)
    click.echo(f"OK  {path}: {len(config.rules)} rules ({enabled} enabled)")
    click.echo(f"conflict resolution: {config.settings.conflict_resolution}")
    for rule in sorted(config.rules, key=lambda r: -r.priority):
        state = "" if rule.enabled else "  [disabled]"
        click.echo(
            f"  {rule.priority:>4}  {rule.severity.label:<8}  {rule.name}  "
            f"-> {', '.join(rule.actions)}{state}"
        )
    for warning in config.warnings:
        click.echo(f"warning: {warning}", err=True)


@policy.command("test", context_settings=CONTEXT_SETTINGS)
@click.option(
    "--policy", "policy_path", required=True, type=click.Path(exists=True, path_type=Path)
)
@click.option(
    "--file",
    "file_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
)
@click.option(
    "--destination",
    "categories",
    multiple=True,
    type=click.Choice(sorted(KNOWN_DESTINATIONS)),
    help="Destination category; may be repeated.",
)
@click.option(
    "--channel", default="unknown", help="email, s3, cloud_storage, removable_media, internal"
)
@click.option("--recipient", help="Recipient email address (derives domain categories).")
@click.option("--public/--private", "public", default=None, help="S3 bucket exposure.")
@click.option("--format", "output", type=click.Choice(["text", "json"]), default="text")
def policy_test(
    policy_path: Path,
    file_path: Path,
    categories: tuple[str, ...],
    channel: str,
    recipient: str | None,
    public: bool | None,
    output: str,
) -> None:
    """Dry run: show what the policy would do with FILE. Nothing is moved or recorded."""
    engine = load_engine(policy_path)
    data = file_path.read_bytes()
    findings = Scanner().scan_bytes(data)
    destination = Destination(
        channel=channel, recipient=recipient, public=public, declared=tuple(categories)
    )
    decision = engine.evaluate(findings, destination)
    summaries = summarize(findings)

    if output == "json":
        click.echo(
            json.dumps(
                {
                    "file": str(file_path),
                    "findings": [s.to_dict() for s in summaries.values()],
                    "destination": sorted(decision.categories),
                    "matches": [
                        {
                            "rule": m.rule.name,
                            "severity": m.rule.severity.label,
                            "priority": m.rule.priority,
                            "suppressed_by": m.suppressed_by,
                        }
                        for m in decision.matches
                    ],
                    "actions": list(decision.actions),
                },
                indent=2,
            )
        )
        return

    click.echo(f"file:        {file_path} ({len(data)} bytes)")
    found = "; ".join(f"{s.type} x{s.count} ({', '.join(s.samples)})" for s in summaries.values())
    click.echo(f"findings:    {found or 'none'}")
    click.echo(f"destination: {', '.join(sorted(decision.categories))}")
    if not decision.triggered:
        click.echo("result:      no rule matched, nothing would happen")
        return
    click.echo("matched rules:")
    for match in decision.matches:
        note = f"  (overridden by {match.suppressed_by})" if match.suppressed else ""
        click.echo(
            f"  {'-' if match.suppressed else '*'} {match.rule.name} "
            f"[{match.rule.severity.label}, priority {match.rule.priority}] "
            f"-> {', '.join(match.rule.actions)}{note}"
        )
    click.echo(f"result:      {', '.join(decision.actions) or 'no action'}")


# -- incident log --------------------------------------------------------------------------


@cli.group("incident-log", context_settings=CONTEXT_SETTINGS)
def incident_log() -> None:
    """Query the incident journal (SQLite locally, DynamoDB in AWS)."""


# The same commands under the underscore spelling, hidden from --help.
cli.add_command(
    click.Group("incident_log", commands=incident_log.commands, hidden=True), "incident_log"
)


@incident_log.command("query", context_settings=CONTEXT_SETTINGS)
@click.option(
    "--backend", type=click.Choice(["sqlite", "dynamodb"]), default="sqlite", show_default=True
)
@click.option(
    "--db",
    "db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    envvar="DLP_DB_PATH",
    default="data/incidents.db",
    show_default=True,
    help="SQLite database file.",
)
@click.option("--table", "table_name", envvar="DLP_TABLE_NAME", help="DynamoDB table name.")
@click.option(
    "--severity",
    "severities",
    multiple=True,
    type=click.Choice(SEVERITY_LABELS, case_sensitive=False),
    help="Only this severity; may be repeated.",
)
@click.option("--last", "last", help="Only incidents from the last period, e.g. 30m, 12h, 7d, 2w.")
@click.option("--rule", help="Only incidents of this rule.")
@click.option("--limit", default=DEFAULT_QUERY_LIMIT, show_default=True, type=click.IntRange(min=1))
@click.option(
    "--format", "output", type=click.Choice(["table", "json"]), default="table", show_default=True
)
def incident_log_query(
    backend: str,
    db_path: Path,
    table_name: str | None,
    severities: tuple[str, ...],
    last: str | None,
    rule: str | None,
    limit: int,
    output: str,
) -> None:
    """List incidents, newest first. Findings are shown masked, never in full."""
    since: str | None = None
    if last:
        try:
            delta: timedelta = parse_duration(last)
        except ValueError as exc:
            raise click.BadParameter(str(exc), param_hint="--last") from None
        since = timestamp_before(delta)

    if backend == "dynamodb":
        if not table_name:
            raise click.UsageError(
                "--table (or DLP_TABLE_NAME) is required for the dynamodb backend"
            )
        from src.storage.dynamodb_store import DynamoDbIncidentStore

        store: Any = DynamoDbIncidentStore.from_table_name(table_name)
    else:
        if not Path(db_path).exists():
            raise click.ClickException(f"no incident database at {db_path}")
        store = SqliteIncidentStore(db_path)

    incidents = store.query(
        severities=[s.lower() for s in severities] or None, since=since, rule=rule, limit=limit
    )
    if output == "json":
        click.echo(json.dumps(incidents, indent=2))
    elif incidents:
        click.echo(format_table(incidents))
        click.echo(f"\n{len(incidents)} incident(s)")
    else:
        click.echo("no incidents match")


# -- watch ---------------------------------------------------------------------------------


@cli.group(context_settings=CONTEXT_SETTINGS)
def watch() -> None:
    """Run the local folder watcher."""


@watch.command("start", context_settings=CONTEXT_SETTINGS)
@click.option(
    "--watch-dir",
    type=click.Path(file_okay=False, path_type=Path),
    help="Folder that simulates the outgoing gateway.",
)
@click.option(
    "--policy", "policy_path", type=click.Path(dir_okay=False, path_type=Path), help="Policy file."
)
@click.option("--quarantine-dir", type=click.Path(file_okay=False, path_type=Path))
@click.option(
    "--db",
    "db_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="SQLite incident database.",
)
@click.option(
    "--log-file",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Append every incident as a JSON line.",
)
@click.option("--webhook-url", help="Slack/Discord/generic incoming webhook for alerts.")
@click.option(
    "--poll",
    is_flag=True,
    help="Poll instead of using filesystem events (network drives, containers).",
)
@click.option(
    "--settle-seconds",
    default=0.5,
    show_default=True,
    type=click.FloatRange(min=0.0),
    help="Wait this long after the last change before scanning a file.",
)
@click.option(
    "--no-initial-scan", is_flag=True, help="Ignore files that are already in the folder."
)
@click.option("-v", "--verbose", is_flag=True)
def watch_start(
    watch_dir: Path | None,
    policy_path: Path | None,
    quarantine_dir: Path | None,
    db_path: Path | None,
    log_file: Path | None,
    webhook_url: str | None,
    poll: bool,
    settle_seconds: float,
    no_initial_scan: bool,
    verbose: bool,
) -> None:
    """Watch a folder and apply the policy to every file that appears or changes."""
    from src.watchers.local import LocalFileProcessor, LocalWatcher, build_local_pipeline

    settings = LocalSettings.from_env()
    watch_dir = watch_dir or settings.watch_dir
    policy_path = policy_path or settings.policy_path
    quarantine_dir = quarantine_dir or settings.quarantine_dir
    db_path = db_path or settings.db_path
    log_file = log_file or settings.log_file
    webhook_url = webhook_url or settings.webhook_url

    configure_logging(verbose, log_file)
    engine = load_engine(policy_path)
    try:
        pipeline = build_local_pipeline(
            engine=engine,
            quarantine_dir=quarantine_dir,
            store=SqliteIncidentStore(db_path),
            webhook_url=webhook_url,
        )
    except ValueError as exc:
        raise click.ClickException(f"invalid webhook URL: {exc}") from None
    processor = LocalFileProcessor(
        pipeline, watch_dir, quarantine_dir=quarantine_dir, max_scan_bytes=settings.max_scan_bytes
    )
    watcher = LocalWatcher(processor, settle_seconds=settle_seconds, use_polling=poll)

    click.echo(f"policy:      {policy_path} ({len(engine.rules)} rules)")
    click.echo(f"watching:    {watch_dir.resolve()}")
    click.echo(f"quarantine:  {quarantine_dir.resolve()}")
    click.echo(f"incidents:   {db_path}" + (f" (+ JSON lines in {log_file})" if log_file else ""))
    click.echo(f"webhook:     {'configured' if webhook_url else 'not configured'}")
    click.echo("press Ctrl-C to stop")

    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, lambda *_: stop.set())
    watcher.start(scan_existing=not no_initial_scan)
    try:
        stop.wait()
    finally:
        click.echo("stopping...")
        watcher.wait_idle(timeout=10)
        watcher.stop()


if __name__ == "__main__":
    cli()
