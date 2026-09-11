# GuardRail developer tasks. Backend Go code lives in ./backend.
# Usage: `make help` lists targets.

SHELL := /bin/bash
BACKEND_DIR := backend
VERSION ?= $(shell cat VERSION 2>/dev/null || git describe --tags --always --dirty 2>/dev/null || echo dev)
MIGRATIONS := $(BACKEND_DIR)/migrations

# Built from .env when it exists, so `make migrate` uses the password bootstrap
# generated rather than a guess that only ever worked on a hand-made database.
# Override on the command line for anything else.
-include .env

# Deliberately NOT a bare `export`.
#
# `export` with no arguments exports every variable make knows about, which
# after the include above means the vault KEK, the JWT signing key, both
# database passwords and the bootstrap admin password entered the environment of
# every child process of every target — `go test`, `golangci-lint`, anything a
# recipe shells out to, and anything those spawn in turn.
#
# Nothing here needs it. POSTGRES_DSN below is a make variable, substituted into
# the recipe text by make itself, and `docker compose` reads .env from the
# project directory on its own. So the include still does its job and the
# secrets stay in make's own memory.
# How a HOST-side client reaches the database.
#
# Once install.sh has issued a certificate, pg_hba requires TLS on anything
# arriving over the network — and the published port arrives that way, forwarded
# from the bridge — so sslmode=disable here would be refused outright rather than
# merely unencrypted. GUARDRAIL_PG_SSLPARAMS from .env cannot be reused: its
# sslrootcert names a path inside the API container. The host path is spelled out
# instead, and the certificate carries IP:127.0.0.1 and DNS:localhost, so
# verify-full really verifies.
#
# Both forms are derived from GUARDRAIL_PG_SSL rather than read from
# GUARDRAIL_PG_SSLPARAMS, even though .env has exactly that string. install.sh
# has to QUOTE that value — it contains an &, and a shell sourcing .env would
# otherwise background the assignment and leave it unset — and make's
# `-include` strips nothing, so reading it here would splice literal quotes into
# the middle of a DSN. GUARDRAIL_PG_SSL is a bare on/off and safe to read.
PG_SSLPARAMS ?= $(if $(filter on,$(GUARDRAIL_PG_SSL)),sslmode=verify-full&sslrootcert=$(CURDIR)/deploy/postgres/tls/server.crt,sslmode=disable)
# The same decision for a client running INSIDE the compose network, where the
# certificate is at the path the API sees.
PG_SSLPARAMS_CONTAINER ?= $(if $(filter on,$(GUARDRAIL_PG_SSL)),sslmode=verify-full&sslrootcert=/etc/guardrail/pgtls/server.crt,sslmode=disable)
POSTGRES_DSN ?= postgres://$(or $(POSTGRES_USER),guardrail):$(POSTGRES_PASSWORD)@localhost:$(or $(POSTGRES_PORT),5432)/$(or $(POSTGRES_DB),guardrail)?$(PG_SSLPARAMS)

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## Resolve Go module dependencies (writes go.sum)
	cd $(BACKEND_DIR) && go mod tidy

.PHONY: vendor
vendor: ## Refresh backend/vendor (committed; lets the image build offline / behind a proxy)
	cd $(BACKEND_DIR) && go mod tidy && go mod vendor
	@echo "vendor refreshed — commit backend/vendor along with go.mod/go.sum"

.PHONY: build
build: ## Build the API binary
	cd $(BACKEND_DIR) && CGO_ENABLED=0 go build -trimpath \
		-ldflags "-s -w -X main.version=$(VERSION)" -o ../bin/guardrail ./cmd/guardrail

# Only `install-native` needs these: the compose API image installs its own
# Chromium, and nothing on the host is consulted for it.
.PHONY: deps
deps: ## Install host packages for install-native (Chromium, openssl). Starts nothing.
	@bash scripts/install-deps.sh

.PHONY: install
install: ## Fresh server -> running GuardRail (idempotent; safe to re-run)
	@bash scripts/bootstrap.sh

.PHONY: install-native
install-native: ## Same, but run the API as a host process (reaches LAN devices)
	@bash scripts/bootstrap.sh --native

.PHONY: run
run: ## Run the full stack via docker compose
	docker compose up --build

.PHONY: down
down: ## Stop the stack
	docker compose down

.PHONY: test
test: ## Run unit tests with race detector + coverage
	cd $(BACKEND_DIR) && go test -race -covermode=atomic -coverprofile=coverage.out ./...
	cd $(BACKEND_DIR) && go tool cover -func=coverage.out | tail -n 1

.PHONY: test-integration
test-integration: ## Run integration tests (requires docker; build tag=integration)
	cd $(BACKEND_DIR) && go test -race -tags=integration ./test/...

.PHONY: lint
lint: ## Run golangci-lint
	cd $(BACKEND_DIR) && golangci-lint run ./...

.PHONY: vuln
vuln: ## Run govulncheck
	cd $(BACKEND_DIR) && govulncheck ./...

# Run through compose so the migration set, the tool version and the DSN are the
# same ones a real deploy uses, and nothing has to be installed locally.
.PHONY: migrate
migrate: ## Apply database migrations (up)
	docker compose run --rm migrate

.PHONY: migrate-down
migrate-down: ## Roll back one migration
	docker compose run --rm migrate -path=/migrations \
		-database "postgres://$(or $(POSTGRES_USER),guardrail):$(POSTGRES_PASSWORD)@postgres:5432/$(or $(POSTGRES_DB),guardrail)?$(PG_SSLPARAMS_CONTAINER)" \
		down 1

.PHONY: seed
seed: ## Load seed data (permissions, system roles, default org)
	docker compose run --rm seed

.PHONY: clean
release: ## Cut a release: make release BUMP=minor (or major|patch|X.Y.Z)
	@scripts/release.sh $(or $(BUMP),patch)

version-check: ## Verify VERSION, the installer default and the CHANGELOG agree
	@scripts/release.sh --check

clean: ## Remove build artifacts
	rm -rf bin $(BACKEND_DIR)/coverage.out
