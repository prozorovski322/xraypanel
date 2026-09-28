SHELL := /bin/sh

BIN_DIR := bin
PANEL_BIN := $(BIN_DIR)/panel
NODE_BIN := $(BIN_DIR)/nodeagent
BACKUP_BIN := $(BIN_DIR)/backup

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

COMPOSE_DEV := docker compose -f docker-compose.dev.yml

# Loaded by targets that need configuration. Everything reads the same .env the
# panel does, so a make target cannot drift from how the binary actually runs.
ifneq (,$(wildcard .env))
include .env
export
endif

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z0-9_-]+:.*##/ {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ------------------------------------------------------------------ toolchain

.PHONY: tools
tools: ## Install the developer tools
	go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
	@echo
	@echo "golangci-lint is not installed from here: its module path and config"
	@echo "schema changed between v1 and v2, so pinning it in one place (CI) and"
	@echo "installing it per the upstream instructions avoids a silent mismatch."
	@echo "See https://golangci-lint.run/welcome/install/"
	@echo
	@echo "goose is not needed either: migrations are embedded in the binary,"
	@echo "so use 'make migrate' rather than a separate CLI."

# ---------------------------------------------------------------------- build

.PHONY: build
build: build-panel build-node build-backup ## Build every binary

.PHONY: build-panel
build-panel: ## Build the panel binary
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(PANEL_BIN) ./cmd/panel

.PHONY: build-node
build-node: ## Build the node agent binary
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(NODE_BIN) ./cmd/nodeagent

.PHONY: build-backup
build-backup: ## Build the backup tool
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BACKUP_BIN) ./cmd/backup

# The version of xray a node image carries. Pinned, because two nodes built a week apart
# running different cores is a difference in traffic accounting and handshake behaviour
# that is very hard to attribute after the fact.
XRAY_VERSION ?= v26.3.27

.PHONY: node-image
node-image: ## Build the node image (agent as PID 1, xray as its child)
	docker build -f deploy/node.Dockerfile \
		--build-arg XRAY_VERSION=$(XRAY_VERSION) \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		-t xraypanel-node:$(XRAY_VERSION) \
		-t xraypanel-node:latest .

# The production images. deploy/docker-compose.yml expects them under IMAGE_REGISTRY with
# the XRAYPANEL_VERSION tag; releases are built and pushed by .github/workflows/release.yml.
IMAGE_REGISTRY ?= ghcr.io/prozorovski322

.PHONY: images
images: ## Build the panel, web and backup images for deploy/docker-compose.yml
	for image in panel web backup; do \
		docker build -f deploy/$$image.Dockerfile \
			--build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) \
			-t $(IMAGE_REGISTRY)/$$image:$(VERSION) . || exit 1; \
	done

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BIN_DIR) coverage.out coverage.html

# ----------------------------------------------------------------- test, lint

# The race detector needs cgo, which needs a C toolchain. A stock Windows box has
# none, so the flag degrades instead of breaking the target for that developer. CI
# runs on Linux and always has it, which is where the guarantee actually lives.
ifeq ($(shell command -v gcc >/dev/null 2>&1 && echo yes),yes)
RACE := -race
else
RACE :=
endif

.PHONY: test
test: ## Run unit tests (with -race where a C toolchain is available)
	@if [ -z "$(RACE)" ]; then \
		echo "note: no C compiler found, running without -race (CI runs with it)"; \
	fi
	go test $(RACE) -shuffle=on ./...

.PHONY: test-integration
test-integration: ## Run integration tests (needs TEST_DATABASE_URL)
	@if [ -z "$(TEST_DATABASE_URL)" ]; then \
		echo "TEST_DATABASE_URL is not set; the suite would skip every test."; \
		echo "Point it at a throwaway database, for example:"; \
		echo "  TEST_DATABASE_URL=postgres://panel:panel@127.0.0.1:5432/panel_test?sslmode=disable make test-integration"; \
		exit 1; \
	fi
	go test $(RACE) -tags=integration -count=1 -shuffle=on -timeout 15m ./test/integration/...

.PHONY: cover
cover: ## Run tests and open an HTML coverage report
	go test $(RACE) -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "report written to coverage.html"

.PHONY: lint
lint: ## Run golangci-lint if it is installed, otherwise fall back to go vet
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found, running go vet instead (see 'make tools')"; \
		go vet ./...; \
	fi

.PHONY: fmt
fmt: ## Format the code
	gofmt -s -w .
	go mod tidy

.PHONY: check
check: fmt-check vet lint test ## Everything CI runs

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@unformatted=$$(gofmt -s -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "these files are not gofmt-clean:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

.PHONY: vet
vet: ## Run go vet
	go vet ./...

# ------------------------------------------------------------------ database

.PHONY: dev-up
dev-up: ## Start the development Postgres
	$(COMPOSE_DEV) up -d
	@echo "waiting for postgres to accept connections..."
	@until $(COMPOSE_DEV) exec -T postgres pg_isready -U panel -d panel >/dev/null 2>&1; do sleep 1; done
	@echo "postgres is ready"

.PHONY: dev-down
dev-down: ## Stop the development Postgres, keeping data
	$(COMPOSE_DEV) down

.PHONY: dev-reset
dev-reset: ## Destroy the development database and recreate it from scratch
	$(COMPOSE_DEV) down -v
	$(MAKE) dev-up
	$(MAKE) migrate

.PHONY: migrate
migrate: ## Apply pending migrations
	go run ./cmd/panel migrate

.PHONY: migrate-status
migrate-status: ## Show migration status
	go run ./cmd/panel migrate-status

.PHONY: sqlc
sqlc: ## Regenerate the database access layer
	sqlc generate

# ------------------------------------------------------------------- protocol

# Pinned here rather than expected on PATH. The generator is then pinned the same way
# a library is pinned in go.mod, so the committed output cannot change with whatever a
# developer happens to have installed. buf brings its own compiler, so protoc is not
# needed; the plugin versions live in buf.gen.yaml.
BUF_VERSION := v1.73.0
BUF := go run github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)

# Where generated protocol code lands: the panel-to-node protocol, and the transcribed
# subset of the core's own API the agent reconciles through (ADR-065).
PROTO_OUT := internal/nodectl internal/xray/app internal/xray/common internal/xray/proxy

.PHONY: proto
proto: ## Regenerate the protocol code from api/proto
	$(BUF) lint
	$(BUF) generate
	@echo
	@echo "generated code is committed; review the diff:"
	@echo "  git diff $(PROTO_OUT)"

.PHONY: proto-check
proto-check: ## Fail if the committed protocol code is not what the schema generates
	$(BUF) lint
	$(BUF) generate
	@if [ -n "$$(git status --porcelain $(PROTO_OUT))" ]; then \
		echo "generated protocol code is out of date; run 'make proto' and commit the result:"; \
		git status --porcelain $(PROTO_OUT); \
		exit 1; \
	fi

# ------------------------------------------------------------------ admin UI

# npm rather than pnpm: it ships with Node, so the UI needs no tool beyond the runtime.
NPM ?= npm

.PHONY: ui-install
ui-install: ## Install the admin UI's dependencies from the lockfile
	cd frontend && PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 $(NPM) ci

.PHONY: ui-api
ui-api: ## Regenerate the admin UI's API types from api/openapi.yaml
	cd frontend && $(NPM) run api

.PHONY: ui-dev
ui-dev: ## Run the admin UI dev server, proxying the API to a panel on :8080
	cd frontend && $(NPM) run dev

.PHONY: ui-build
ui-build: ## Type-check and build the admin UI into frontend/dist
	cd frontend && $(NPM) run build

# --------------------------------------------------------------------- run

.PHONY: run
run: ## Run the panel from source
	go run ./cmd/panel serve
