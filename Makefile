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
export
POSTGRES_DSN ?= postgres://$(or $(POSTGRES_USER),guardrail):$(POSTGRES_PASSWORD)@localhost:$(or $(POSTGRES_PORT),5432)/$(or $(POSTGRES_DB),guardrail)?sslmode=disable

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(firstword $(MAKEFILE_LIST)) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: tidy
tidy: ## Resolve Go module dependencies (writes go.sum)
	cd $(BACKEND_DIR) && go mod tidy

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
		-database "postgres://$(or $(POSTGRES_USER),guardrail):$(POSTGRES_PASSWORD)@postgres:5432/$(or $(POSTGRES_DB),guardrail)?sslmode=disable" \
		down 1

.PHONY: seed
seed: ## Load seed data (permissions, system roles, default org)
	docker compose run --rm seed

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin $(BACKEND_DIR)/coverage.out
