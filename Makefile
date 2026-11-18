# VulnForge Lab — developer commands
# WARNING: the lab is intentionally vulnerable. Run only on an isolated host.

PYTHON ?= python3
COMPOSE ?= docker compose
BASE_URL ?= http://127.0.0.1:8000
LAB_CONTROL ?= http://127.0.0.1:9100

.PHONY: help install up up-full down reset truth catalog test smoke controls score logs ps

help:
	@echo "make install     One-shot installer (auto-detects missing packages)"
	@echo "make up          Start the core profile"
	@echo "make up-full     Start every profile (all services)"
	@echo "make down        Stop the stack"
	@echo "make reset       Reset databases, uploads and events"
	@echo "make truth       Regenerate lab/truth/vulns.json and controls.json"
	@echo "make catalog     Regenerate the English and Turkish vulnerability catalog"
	@echo "make test        Run smoke + control suites"
	@echo "make score       Score tests/fixtures/sample_findings.json"

install:
	./docker_install.sh --profile full

up:
	$(COMPOSE) --profile core up -d --build

up-full:
	$(COMPOSE) --profile full up -d --build

down:
	$(COMPOSE) --profile full down

reset:
	curl -fsS -X POST $(LAB_CONTROL)/__lab/reset
	@echo

truth:
	$(PYTHON) lab/tools/extract_truth.py --root . --validate

catalog: truth
	$(PYTHON) lab/tools/generate_catalog.py --lang en
	$(PYTHON) lab/tools/generate_catalog.py --lang tr

test:
	$(PYTHON) tests/run_tests.py --mode all --base-url $(BASE_URL) --lab-control $(LAB_CONTROL)

smoke:
	$(PYTHON) tests/run_tests.py --mode smoke --base-url $(BASE_URL) --lab-control $(LAB_CONTROL)

controls:
	$(PYTHON) tests/run_tests.py --mode controls --base-url $(BASE_URL) --lab-control $(LAB_CONTROL)

score:
	$(PYTHON) scorer/scorer.py \
		--findings tests/fixtures/sample_findings.json \
		--truth-dir lab/truth \
		--out-dir scorer/out \
		--scanner-name sample

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps
