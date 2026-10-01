#!/usr/bin/env python3
"""Build build/lambda.zip, the deployment package for the detector function.

The package contains the handler, the ``src`` package (without the local-watcher modules),
the policy file as ``policies.yaml`` and the third-party dependencies from
``lambda/requirements.txt`` fetched as Linux wheels, so it can be built on any OS.
boto3 is not included; the Lambda Python runtime provides it.

The archive is reproducible (sorted entries, fixed timestamps): building twice from the same
inputs gives the same bytes, so Terraform does not redeploy the function needlessly.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.engine import PolicyValidationError, load_policy_file  # noqa: E402

DEFAULT_OUTPUT = ROOT / "build" / "lambda.zip"
# Needed only by the local mode (and it pulls in watchdog), so they stay out of the package.
EXCLUDED_SOURCES = frozenset({"src/watchers/local.py", "src/watchers/manifest.py"})
FIXED_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
LAMBDA_PYTHON = "3.12"
LAMBDA_PLATFORM = "manylinux2014_x86_64"


def default_policy() -> Path:
    custom = ROOT / "config" / "policies.yaml"
    return custom if custom.exists() else ROOT / "config" / "policies.example.yaml"


def stage_sources(stage: Path, policy: Path) -> None:
    shutil.copy2(ROOT / "lambda" / "handler.py", stage / "handler.py")
    shutil.copy2(policy, stage / "policies.yaml")
    for source in sorted((ROOT / "src").rglob("*.py")):
        relative = source.relative_to(ROOT).as_posix()
        if relative in EXCLUDED_SOURCES:
            continue
        target = stage / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def install_dependencies(stage: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--quiet",
        "--disable-pip-version-check",
        "--target",
        str(stage),
        "--platform",
        LAMBDA_PLATFORM,
        "--implementation",
        "cp",
        "--python-version",
        LAMBDA_PYTHON,
        "--only-binary=:all:",
        "--requirement",
        str(ROOT / "lambda" / "requirements.txt"),
    ]
    subprocess.run(command, check=True)
    for cache in stage.rglob("__pycache__"):
        shutil.rmtree(cache)


def write_archive(stage: Path, output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    files = sorted(path for path in stage.rglob("*") if path.is_file())
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            info = zipfile.ZipInfo(path.relative_to(stage).as_posix(), FIXED_TIMESTAMP)
            executable = path.stat().st_mode & 0o111
            info.external_attr = (0o755 if executable else 0o644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    return len(files)


def build(output: Path, policy: Path, install_deps: bool = True) -> Path:
    load_policy_file(policy)  # refuse to package a policy the function could not load
    with tempfile.TemporaryDirectory(prefix="dlp-lambda-") as tmp:
        stage = Path(tmp)
        stage_sources(stage, policy)
        if install_deps:
            install_dependencies(stage)
        count = write_archive(stage, output)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    size_kb = output.stat().st_size / 1024
    print(f"built {output} ({count} files, {size_kb:.0f} KiB, sha256 {digest[:16]})")
    print(f"policy: {policy}")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="policy file to ship (default: config/policies.yaml, else the example)",
    )
    parser.add_argument(
        "--skip-deps",
        action="store_true",
        help="do not download dependencies (offline builds; the package then lacks PyYAML)",
    )
    args = parser.parse_args(argv)
    policy = args.policy or default_policy()
    try:
        build(args.output, policy, install_deps=not args.skip_deps)
    except PolicyValidationError as exc:
        print(f"invalid policy {policy}:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as exc:
        print(f"dependency download failed (exit {exc.returncode})", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
