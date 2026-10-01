import json
import logging

import pytest

from src.watchers.manifest import (
    LocalDestinationResolver,
    ManifestError,
    load_manifest,
    parse_manifest,
)


@pytest.fixture
def root(tmp_path):
    outbox = tmp_path / "outbox"
    outbox.mkdir()
    return outbox


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) if not isinstance(data, str) else data)
    return path


class TestParseManifest:
    def test_full_manifest(self):
        destination = parse_manifest(
            {
                "channel": "email",
                "recipient": "a@vendor.example",
                "destination": ["external_email", "non_corporate_domain"],
            }
        )
        assert destination.channel == "email"
        assert destination.declared == ("external_email", "non_corporate_domain")

    def test_destination_may_be_a_single_string(self):
        assert parse_manifest({"destination": "public_s3"}).declared == ("public_s3",)

    def test_empty_manifest_is_unknown(self):
        assert parse_manifest({}).categories() == {"unknown"}

    @pytest.mark.parametrize(
        ("data", "message"),
        [
            ([], "JSON object"),
            ({"destnation": "public_s3"}, "unknown manifest field"),
            ({"channel": "carrier-pigeon"}, "channel"),
            ({"destination": "mars"}, "destination"),
            ({"destination": ["public_s3", 5]}, "destination"),
            ({"destination": 5}, "destination"),
            ({"recipient": "not-an-email"}, "email address"),
            ({"recipient": 5}, "recipient must be a string"),
            ({"public": "yes"}, "public"),
        ],
    )
    def test_invalid_manifests(self, data, message):
        with pytest.raises(ManifestError, match=message):
            parse_manifest(data)

    def test_load_rejects_broken_json_and_huge_files(self, tmp_path):
        broken = write(tmp_path / "a.json", "{not json")
        with pytest.raises(ManifestError, match="cannot read"):
            load_manifest(broken)
        huge = write(tmp_path / "b.json", '{"recipient": "' + "a" * 70_000 + '@x.example"}')
        with pytest.raises(ManifestError, match="larger than"):
            load_manifest(huge)


class TestResolver:
    def test_sidecar_manifest(self, root):
        file = write(root / "report.csv", "x")
        write(root / "report.csv.meta.json", {"destination": "public_s3"})
        assert LocalDestinationResolver(root).resolve(file).declared == ("public_s3",)

    def test_directory_manifest(self, root):
        file = write(root / "batch" / "report.csv", "x")
        write(root / "batch" / "metadata.json", {"destination": "cloud_storage"})
        assert LocalDestinationResolver(root).resolve(file).declared == ("cloud_storage",)

    def test_nearest_ancestor_manifest_wins(self, root):
        file = write(root / "a" / "b" / "report.csv", "x")
        write(root / "metadata.json", {"destination": "internal"})
        write(root / "a" / "metadata.json", {"destination": "public_s3"})
        assert LocalDestinationResolver(root).resolve(file).declared == ("public_s3",)

    def test_root_manifest_applies_to_everything_below(self, root):
        file = write(root / "a" / "b" / "report.csv", "x")
        write(root / "metadata.json", {"destination": "internal"})
        assert LocalDestinationResolver(root).resolve(file).declared == ("internal",)

    def test_sidecar_beats_directory_manifest_and_folder_name(self, root):
        file = write(root / "external_email" / "r.csv", "x")
        write(root / "external_email" / "metadata.json", {"destination": "cloud_storage"})
        write(root / "external_email" / "r.csv.meta.json", {"destination": "internal"})
        assert LocalDestinationResolver(root).resolve(file).declared == ("internal",)

    def test_folder_name_is_used_without_manifests(self, root):
        file = write(root / "external_email" / "r.csv", "x")
        assert LocalDestinationResolver(root).resolve(file).declared == ("external_email",)

    def test_deepest_matching_folder_wins(self, root):
        file = write(root / "internal" / "public_s3" / "r.csv", "x")
        assert LocalDestinationResolver(root).resolve(file).declared == ("public_s3",)

    def test_plain_folders_and_the_root_itself_are_unknown(self, root):
        resolver = LocalDestinationResolver(root)
        assert resolver.resolve(write(root / "misc" / "r.csv", "x")).categories() == {"unknown"}
        assert resolver.resolve(write(root / "r.csv", "x")).categories() == {"unknown"}

    def test_a_folder_literally_named_unknown_is_not_special(self, root):
        file = write(root / "unknown" / "r.csv", "x")
        assert LocalDestinationResolver(root).resolve(file).declared == ()

    def test_invalid_manifest_is_skipped_with_a_warning(self, root, caplog):
        file = write(root / "external_email" / "r.csv", "x")
        write(root / "r.csv.meta.json", "{broken")
        write(root / "external_email" / "r.csv.meta.json", {"destnation": "x"})
        with caplog.at_level(logging.WARNING):
            destination = LocalDestinationResolver(root).resolve(file)
        assert destination.declared == ("external_email",)  # fell back to the folder name
        assert "ignoring invalid manifest" in caplog.text

    def test_manifest_outside_the_root_is_not_consulted(self, root, tmp_path):
        write(tmp_path / "metadata.json", {"destination": "public_s3"})
        file = write(root / "r.csv", "x")
        assert LocalDestinationResolver(root).resolve(file).categories() == {"unknown"}

    def test_relative_paths_are_resolved(self, root, monkeypatch):
        write(root / "external_email" / "r.csv", "x")
        monkeypatch.chdir(root.parent)
        from pathlib import Path

        found = LocalDestinationResolver(Path("outbox")).resolve(
            Path("outbox/external_email/r.csv")
        )
        assert found.declared == ("external_email",)
