PYTHON ?= python3
TF_DIR := infra/terraform

.PHONY: help install test lint format package seed watch tf-fmt tf-validate tf-init localstack-up localstack-down clean

help:
	@echo "install        install runtime and dev dependencies"
	@echo "test           run the test suite"
	@echo "lint           ruff check + format check"
	@echo "format         apply ruff formatting"
	@echo "package        build build/lambda.zip for Terraform"
	@echo "seed           write synthetic test files into ./outbox"
	@echo "watch          start the local watcher on ./outbox"
	@echo "tf-fmt         terraform fmt -check"
	@echo "tf-validate    terraform init -backend=false && validate"
	@echo "localstack-up  start LocalStack (docker compose)"

install:
	$(PYTHON) -m pip install -r requirements-dev.txt

test:
	$(PYTHON) -m pytest

lint:
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .

format:
	$(PYTHON) -m ruff check --fix .
	$(PYTHON) -m ruff format .

package:
	$(PYTHON) scripts/build_lambda.py

seed:
	$(PYTHON) scripts/seed_test_files.py local --out ./outbox

watch:
	$(PYTHON) cli.py watch start --watch-dir ./outbox --policy config/policies.example.yaml --log-file data/incidents.jsonl

tf-fmt:
	terraform -chdir=$(TF_DIR) fmt -check -recursive

tf-init:
	terraform -chdir=$(TF_DIR) init

tf-validate:
	terraform -chdir=$(TF_DIR) init -backend=false
	terraform -chdir=$(TF_DIR) validate

localstack-up:
	docker compose up -d localstack

localstack-down:
	docker compose down

clean:
	rm -rf build .pytest_cache .ruff_cache outbox quarantine data
