from pathlib import Path

import pytest

from src.detectors.scanner import DEFAULT_MAX_SCAN_BYTES
from src.settings import LambdaSettings, LocalSettings

REQUIRED = {"DLP_TABLE_NAME": "incidents", "DLP_SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:1:alerts"}


class TestLocalSettings:
    def test_defaults(self):
        settings = LocalSettings.from_env({})
        assert settings.policy_path == Path("config/policies.yaml")
        assert settings.watch_dir == Path("outbox")
        assert settings.quarantine_dir == Path("quarantine")
        assert settings.db_path == Path("data/incidents.db")
        assert settings.log_file is None and settings.webhook_url is None
        assert settings.max_scan_bytes == DEFAULT_MAX_SCAN_BYTES

    def test_environment_overrides(self):
        settings = LocalSettings.from_env(
            {
                "DLP_POLICY_PATH": "/etc/dlp/p.yaml",
                "DLP_WATCH_DIR": "/srv/out",
                "DLP_QUARANTINE_DIR": "/srv/q",
                "DLP_DB_PATH": "/var/db/i.db",
                "DLP_LOG_FILE": "/var/log/i.jsonl",
                "DLP_WEBHOOK_URL": " https://hooks.example.org/x ",
                "DLP_MAX_SCAN_BYTES": "1024",
            }
        )
        assert settings.policy_path == Path("/etc/dlp/p.yaml")
        assert settings.log_file == Path("/var/log/i.jsonl")
        assert settings.webhook_url == "https://hooks.example.org/x"
        assert settings.max_scan_bytes == 1024

    def test_blank_values_fall_back_to_defaults(self):
        settings = LocalSettings.from_env({"DLP_WATCH_DIR": "  ", "DLP_WEBHOOK_URL": ""})
        assert settings.watch_dir == Path("outbox") and settings.webhook_url is None

    def test_invalid_numbers_are_reported_by_name(self):
        with pytest.raises(ValueError, match="DLP_MAX_SCAN_BYTES must be an integer"):
            LocalSettings.from_env({"DLP_MAX_SCAN_BYTES": "lots"})


class TestLambdaSettings:
    def test_only_the_table_and_the_topic_are_required(self):
        settings = LambdaSettings.from_env(REQUIRED)
        assert settings.table_name == "incidents"
        assert settings.policy_path == "policies.yaml"  # the policy packaged with the function
        assert settings.quarantine_bucket is None and settings.webhook_url is None
        assert settings.max_scan_bytes == DEFAULT_MAX_SCAN_BYTES
        assert settings.retention_days == 365

    def test_every_setting_can_be_overridden(self):
        settings = LambdaSettings.from_env(
            {
                **REQUIRED,
                "DLP_QUARANTINE_BUCKET": "quarantine",
                "DLP_POLICY_PATH": "other.yaml",
                "DLP_WEBHOOK_URL": "https://hooks.example.org/x",
                "DLP_MAX_SCAN_BYTES": "512",
                "DLP_RETENTION_DAYS": "30",
            }
        )
        assert settings.quarantine_bucket == "quarantine"
        assert settings.policy_path == "other.yaml"
        assert (settings.max_scan_bytes, settings.retention_days) == (512, 30)

    @pytest.mark.parametrize("missing", sorted(REQUIRED))
    def test_missing_required_settings_are_named(self, missing):
        env = {k: v for k, v in REQUIRED.items() if k != missing}
        with pytest.raises(RuntimeError, match=missing):
            LambdaSettings.from_env(env)

    def test_blank_required_settings_count_as_missing(self):
        with pytest.raises(RuntimeError, match="DLP_TABLE_NAME"):
            LambdaSettings.from_env({**REQUIRED, "DLP_TABLE_NAME": "   "})

    def test_retention_zero_means_keep_forever(self):
        assert LambdaSettings.from_env({**REQUIRED, "DLP_RETENTION_DAYS": "0"}).retention_days == 0
