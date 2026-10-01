import ast
import hashlib
import importlib.util
import sys
import zipfile

import pytest

from tests.conftest import EXAMPLE_POLICY, REPO_ROOT

spec = importlib.util.spec_from_file_location("build_lambda", REPO_ROOT / "scripts/build_lambda.py")
build_lambda = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = build_lambda
spec.loader.exec_module(build_lambda)

ALLOWED_THIRD_PARTY = {"boto3", "botocore", "yaml"}


@pytest.fixture
def package(tmp_path):
    output = tmp_path / "lambda.zip"
    build_lambda.build(output, EXAMPLE_POLICY, install_deps=False)
    return output


def test_package_layout(package):
    names = set(zipfile.ZipFile(package).namelist())
    assert {"handler.py", "policies.yaml", "src/pipeline.py", "src/watchers/s3.py"} <= names
    assert "src/engine/engine.py" in names and "src/storage/dynamodb_store.py" in names


def test_local_mode_modules_and_dev_files_are_excluded(package):
    names = zipfile.ZipFile(package).namelist()
    assert "src/watchers/local.py" not in names and "src/watchers/manifest.py" not in names
    assert not any(n.startswith(("tests/", "scripts/", "infra/")) for n in names)
    assert not any("__pycache__" in n or n.endswith(".pyc") for n in names)


def test_shipped_policy_is_the_given_file(package):
    shipped = zipfile.ZipFile(package).read("policies.yaml")
    assert shipped == EXAMPLE_POLICY.read_bytes()


def test_package_only_imports_what_the_lambda_runtime_provides(package):
    """watchdog, click, Faker and friends are not in the zip, so nothing may import them."""
    archive = zipfile.ZipFile(package)
    local_modules = {"src", "handler"}
    for name in archive.namelist():
        if not name.endswith(".py"):
            continue
        tree = ast.parse(archive.read(name))
        for node in ast.walk(tree):
            modules = []
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                modules = [node.module]
            for module in modules:
                top = module.split(".")[0]
                allowed = top in sys.stdlib_module_names or top in local_modules
                assert allowed or top in ALLOWED_THIRD_PARTY, f"{name} imports {module}"


def test_build_is_reproducible(tmp_path):
    first, second = tmp_path / "a.zip", tmp_path / "b.zip"
    build_lambda.build(first, EXAMPLE_POLICY, install_deps=False)
    build_lambda.build(second, EXAMPLE_POLICY, install_deps=False)
    assert (
        hashlib.sha256(first.read_bytes()).digest() == hashlib.sha256(second.read_bytes()).digest()
    )


def test_archive_entries_have_safe_modes_and_fixed_timestamps(package):
    for info in zipfile.ZipFile(package).infolist():
        assert info.date_time == (2020, 1, 1, 0, 0, 0)
        assert (info.external_attr >> 16) & 0o777 in (0o644, 0o755)


def test_an_invalid_policy_is_refused_before_anything_is_written(tmp_path, capsys):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - rule: x\n")
    output = tmp_path / "out.zip"
    assert build_lambda.main(["--policy", str(bad), "--output", str(output), "--skip-deps"]) == 2
    assert not output.exists()
    assert "invalid policy" in capsys.readouterr().err


def test_command_line_builds_with_default_policy(tmp_path, capsys):
    output = tmp_path / "x" / "lambda.zip"
    assert build_lambda.main(["--output", str(output), "--skip-deps"]) == 0
    assert output.exists() and "built" in capsys.readouterr().out
