# Olopa — one entry point for the builds, stacks and suites that
# docs/engineering-onboarding.md describes in prose.
#
# The test targets mirror .github/workflows/ci.yml command for command, so a
# green `make test-ci` is a green CI run. `make test` is the subset that needs
# neither Rust nightly nor bpf-linker, which is what most work actually needs.
#
# Run `make` on its own for the annotated target list.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

ROOT := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

OILC_MANIFEST    := oilc/Cargo.toml
AGENT_MANIFEST   := agent/Cargo.toml
INGEST_MANIFEST  := app/ingest_server/Cargo.toml

CONTROL_PLANE := app/control_plane
GATEWAY       := app/secure_connect_gateway
WEB           := app/control_plane/web
DESKTOP       := app/command
DESIGN        := app/design
OLOPA_MVP_DOCKER_CONTEXT ?= default
MVP_COMPOSE   := docker --context $(OLOPA_MVP_DOCKER_CONTEXT) compose -f docker-compose.yml -f docker-compose.mvp.yml

OLOPA_MVP_CONTROL_URL ?= http://127.0.0.1:8100
OLOPA_MVP_INGEST_URL  ?= http://127.0.0.1:8000
OLOPA_MVP_CONTROL_TOKEN ?= olopa-local-admin
OLOPA_MVP_INGEST_TOKEN  ?= olopa-local-ingest

# The control-plane compiler tests shell out to oilc. Pointing them at the
# release binary keeps them off the `cargo run` path — same as CI does.
OILC_BINARY := $(ROOT)/oilc/target/release/oilc

# Every Python target depends on $(VENV), so this is always populated by the
# time a recipe expands it — do not make it conditional on the venv existing
# today, or a fresh clone runs the suites against the system interpreter.
VENV   := $(CONTROL_PLANE)/.venv
PYTHON := $(ROOT)/$(VENV)/bin/python

.DEFAULT_GOAL := help

## ---------------------------------------------------------------- help

.PHONY: help
help: ## List the available targets
	@printf '\033[1mOlopa\033[0m — make <target>\n\n'
	@awk 'BEGIN { FS = ":.*## " } \
		/^## -+ / { sub(/^## -+ /, ""); printf "\n\033[1m%s\033[0m\n", $$0; next } \
		/^[a-zA-Z0-9_-]+:.*## / { printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2 }' \
		$(MAKEFILE_LIST)
	@printf '\n'

## ---------------------------------------------------------------- stack

.PHONY: up down logs
up: ## Start the local stack (clickhouse, surrealdb, ingest, control plane, keycloak, caddy)
	docker compose up -d

down: ## Stop the local stack, keeping volumes
	docker compose down

logs: ## Follow the local stack logs
	docker compose logs -f

## ---------------------------------------------------------------- mvp

.PHONY: mvp-up mvp-down mvp-logs mvp-smoke mvp-agent
mvp-up: oilc-build ## Build and start the authenticated single-host MVP
	OLOPA_MVP_CONTROL_TOKEN="$(OLOPA_MVP_CONTROL_TOKEN)" \
	OLOPA_MVP_INGEST_TOKEN="$(OLOPA_MVP_INGEST_TOKEN)" \
	$(MVP_COMPOSE) up -d --build clickhouse surrealdb olopa-ingest control-plane
	@printf 'Olopa MVP: %s\n' "$(OLOPA_MVP_CONTROL_URL)"
	@printf 'Console dev token: %s (tenant: default)\n' "$(OLOPA_MVP_CONTROL_TOKEN)"
	@printf 'Verify with: make mvp-smoke\n'

mvp-down: ## Stop the MVP while retaining its data volumes
	$(MVP_COMPOSE) down

mvp-logs: ## Follow MVP service logs
	$(MVP_COMPOSE) logs -f olopa-ingest control-plane

mvp-smoke: ## Prove compiler -> ingest -> authenticated console API
	OLOPA_MVP_CONTROL_URL="$(OLOPA_MVP_CONTROL_URL)" \
	OLOPA_MVP_INGEST_URL="$(OLOPA_MVP_INGEST_URL)" \
	OLOPA_MVP_CONTROL_TOKEN="$(OLOPA_MVP_CONTROL_TOKEN)" \
	OLOPA_MVP_INGEST_TOKEN="$(OLOPA_MVP_INGEST_TOKEN)" \
	python3 scripts/mvp_smoke.py

mvp-agent: oilc-build agent-build ## Run the privileged Linux sensor against the MVP
	OLOPA_MVP_INGEST_TOKEN="$(OLOPA_MVP_INGEST_TOKEN)" ./agent/run.sh "$(or $(IFACE),lo)"

## ---------------------------------------------------------------- build

.PHONY: build oilc-build agent-build ingest-build
build: oilc-build ingest-build ui-build ## Build oilc, the ingest server and both UI surfaces

oilc-build: ## Build the oilc rule compiler (release)
	cargo build --release --manifest-path $(OILC_MANIFEST)

agent-build: ## Build the agent (needs Rust nightly + bpf-linker for the eBPF crate)
	cargo build --manifest-path $(AGENT_MANIFEST) -p olopa

ingest-build: ## Build the ingest server
	cargo build --release --manifest-path $(INGEST_MANIFEST)

## ---------------------------------------------------------------- ui

# Both surfaces read their palette from app/design/tokens.css, so a colour
# change means rebuilding both. See app/design/README.md.

.PHONY: ui-build ui-lint web-build web-dev web-lint desktop-build desktop-dev desktop-lint desktop-bundle
ui-build: web-build desktop-build ## Build both UI surfaces against the shared design tokens

ui-lint: web-lint desktop-lint ## Typecheck both UI surfaces

web-build: $(WEB)/node_modules ## Build the fleet console into control_server/webdist
	cd $(WEB) && npm run build

web-dev: $(WEB)/node_modules ## Run the console dev server on :5173 (proxies /api to :8100)
	cd $(WEB) && npm run dev

web-lint: $(WEB)/node_modules ## Typecheck the console
	cd $(WEB) && npm run lint

desktop-build: $(DESKTOP)/node_modules ## Build the desktop workstation frontend
	cd $(DESKTOP) && npm run build

desktop-dev: $(DESKTOP)/node_modules ## Run the desktop frontend dev server on :1420
	cd $(DESKTOP) && npm run dev

desktop-lint: $(DESKTOP)/node_modules ## Typecheck the desktop workstation
	cd $(DESKTOP) && npm run lint

desktop-bundle: $(DESKTOP)/node_modules ## Build the packaged Tauri desktop app
	cd $(DESKTOP) && npm run tauri build

# npm ci touches the directory, so its mtime is a sound staleness marker.
$(WEB)/node_modules: $(WEB)/package-lock.json
	cd $(WEB) && npm ci

$(DESKTOP)/node_modules: $(DESKTOP)/package-lock.json
	cd $(DESKTOP) && npm ci

## ---------------------------------------------------------------- test

.PHONY: test test-ci oilc-test agent-test sql-guard-smoke ingest-test control-plane-test gateway-test e2e-test
test: oilc-test ingest-test control-plane-test gateway-test ui-lint ## Everything that needs no nightly toolchain or BPF-capable host

test-ci: test agent-test ## The five CI jobs (adds the agent suite: nightly + bpf-linker)

oilc-test: ## Run the oilc suite
	cargo test --manifest-path $(OILC_MANIFEST)

agent-test: ## Run the agent suite (userspace only, but the eBPF crate still builds)
	cargo test --manifest-path $(AGENT_MANIFEST) -p olopa

sql-guard-smoke: ## Prove blocked SQL never reaches the real client function
	python3 scripts/sql_guard_smoke.py

ingest-test: ## Run the ingest server suite
	cargo test --manifest-path $(INGEST_MANIFEST)

control-plane-test: $(VENV) oilc-build ## Run the control plane suite against the release oilc
	cd $(CONTROL_PLANE) && OILC_BINARY_PATH=$(OILC_BINARY) $(PYTHON) -m pytest -q

gateway-test: $(VENV) ## Run the Secure Connect gateway reconciler suite
	cd $(GATEWAY) && $(PYTHON) -m pytest -q

e2e-test: ## Run the ignored rule -> runtime -> sender -> ingest test (binds a port, spawns ingest)
	cargo test --manifest-path $(AGENT_MANIFEST) -p olopa \
		agent::tests::e2e_rule_to_runtime_to_sender_to_ingest_runtime -- --ignored --exact

## ---------------------------------------------------------------- dev

.PHONY: venv control-plane-dev agent-run
venv: $(VENV) ## Create app/control_plane/.venv and install requirements

$(VENV): $(CONTROL_PLANE)/requirements.txt
	python3 -m venv $(VENV)
	$(VENV)/bin/pip install -q -r $(CONTROL_PLANE)/requirements.txt
	@touch $(VENV)

control-plane-dev: $(VENV) ## Run the control plane on :8100 with reload
	cd $(CONTROL_PLANE) && $(PYTHON) -m uvicorn control_server.main:app --port 8100 --reload

agent-run: ## Compile the showcase rule and run the agent on $(IFACE) (default lo, needs sudo)
	./agent/run.sh $(or $(IFACE),lo)

## ---------------------------------------------------------------- clean

.PHONY: clean clean-rust
clean: ## Remove UI build output (node_modules and Rust targets are left alone)
	rm -rf $(CONTROL_PLANE)/control_server/webdist $(DESKTOP)/dist
	rm -f $(WEB)/*.tsbuildinfo $(DESKTOP)/*.tsbuildinfo

clean-rust: ## cargo clean every workspace — a full rebuild follows
	cargo clean --manifest-path $(OILC_MANIFEST)
	cargo clean --manifest-path $(AGENT_MANIFEST)
	cargo clean --manifest-path $(INGEST_MANIFEST)
