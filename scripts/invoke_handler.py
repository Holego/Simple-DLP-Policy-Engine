#!/usr/bin/env python3
"""Run the real Lambda handler on your machine against existing S3 objects.

Handy with LocalStack (or real AWS) when you do not want to run Lambda containers: the code
and the AWS resources are the deployed ones, only the trigger is replaced by this script.

    export AWS_ENDPOINT_URL=http://localhost:4566    # LocalStack; omit for real AWS
    python scripts/invoke_handler.py --function dlp-dev-detector --bucket B --prefix demo/

The DLP_* settings are read from the deployed function (``--function``), or from the
environment when the flag is omitted. The policy is read from ``--policy`` instead of the
copy packaged in the function.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
from pathlib import Path
from urllib.parse import quote_plus

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def load_handler():
    spec = importlib.util.spec_from_file_location("dlp_lambda_handler", ROOT / "lambda/handler.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def s3_event(bucket: str, keys: list[str]) -> dict:
    """The notification S3 would send: one ObjectCreated record per key."""
    return {
        "Records": [
            {
                "eventSource": "aws:s3",
                "eventName": "ObjectCreated:Put",
                "s3": {
                    "bucket": {"name": bucket},
                    "object": {"key": quote_plus(key), "sequencer": f"manual-{index:06d}"},
                },
            }
            for index, key in enumerate(keys)
        ]
    }


def function_environment(function: str) -> dict[str, str]:
    import boto3

    configuration = boto3.client("lambda").get_function_configuration(FunctionName=function)
    return dict(configuration.get("Environment", {}).get("Variables", {}))


def list_keys(bucket: str, prefix: str) -> list[str]:
    import boto3

    paginator = boto3.client("s3").get_paginator("list_objects_v2")
    pages = paginator.paginate(Bucket=bucket, Prefix=prefix)
    return [item["Key"] for page in pages for item in page.get("Contents", [])]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--key", action="append", default=[], help="object key; may be repeated")
    parser.add_argument("--prefix", help="process every object under this prefix")
    parser.add_argument("--function", help="read DLP_* settings from this deployed function")
    parser.add_argument("--policy", type=Path, default=ROOT / "config" / "policies.example.yaml")
    args = parser.parse_args(argv)

    keys = list(args.key) + (list_keys(args.bucket, args.prefix) if args.prefix is not None else [])
    if not keys:
        parser.error("no objects: pass --key and/or --prefix")

    if args.function:
        os.environ.update(function_environment(args.function))
    os.environ["DLP_POLICY_PATH"] = str(args.policy.resolve())

    handler = load_handler()
    print(f"processing {len(keys)} object(s) from s3://{args.bucket}", file=sys.stderr)
    summary = handler.lambda_handler(s3_event(args.bucket, keys), None)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
