# CVAP make targets. See CLAUDE.md for the short list.
#
# safety and corpus-check are deliberate failing stubs. A safety gate that
# silently passes is worse than one that fails, because the first is trusted.

.PHONY: help build test lint vet fmt tidy ci \
        up down lab-up lab-down \
        migrate-up migrate-down migrate-new migrate-verify rls-test \
        proto proto-tools proto-gen proto-lint proto-breaking proto-verify \
        secret-logging secret-logging-test \
        safety corpus-check frontmatter licences gitignore-test scope-guard-test \
        contract-guard-test

# golang-migrate, pinned by digest rather than tag so the tool cannot change
# under a running project (ADR-025: consume commodity infrastructure).
MIGRATE_IMAGE := migrate/migrate@sha256:f21c436af23c282f4516b00ba3e93bccf5c5fe5cd52530fd5c319a936998f539
MIGRATIONS_DIR := migrations

# Protobuf toolchain, pinned. Local plugins rather than buf.build remote ones,
# so generating the contract is not a network call to a third party (ADR-025).
BUF_VERSION := v1.47.2
PROTOC_GEN_GO_VERSION := v1.36.6
PROTOC_GEN_GO_GRPC_VERSION := v1.5.1

# What `buf breaking` compares against. ADR-022 is additive-only within a major
# version and this is what enforces it mechanically rather than by review.
# Locally that is the last commit; in CI it is the branch being merged into,
# because a break that is already committed locally compares clean against
# itself.
PROTO_BASELINE ?= .git#ref=HEAD

# Loaded from .env when present so make migrate-up works without exporting by
# hand. Copy .env.example to .env first.
ifneq (,$(wildcard .env))
include .env
export
endif

help:
	@grep -hE '^[a-z][a-zA-Z0-9_-]*:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## ---------- build and check ----------

build: ## Build all binaries
	go build ./...

test: ## Run tests with the race detector
	go test ./... -race

vet: ## go vet
	go vet ./...

lint: ## golangci-lint
	golangci-lint run

fmt: ## Format and tidy
	gofmt -l -w .
	go mod tidy

tidy: fmt

ci: build vet test lint proto frontmatter gitignore-test scope-guard-test \
    contract-guard-test secret-logging secret-logging-test ## Everything CI runs, locally

## ---------- wire contract ----------

# proto/ is frozen (ADR-022). These three targets are what make that mechanical:
# lint holds the shape, breaking holds the additive-only rule, and verify holds
# the committed bindings to the .proto files they came from.
proto: proto-lint proto-breaking proto-verify ## Lint, breaking-check and verify the wire contract

proto-tools: ## Install the pinned protobuf toolchain into $(GOPATH)/bin
	go install github.com/bufbuild/buf/cmd/buf@$(BUF_VERSION)
	go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

proto-gen: ## Regenerate the Go bindings in gen/
	@command -v buf >/dev/null || { echo "buf not on PATH -- run: make proto-tools"; exit 1; }
	buf generate

proto-lint: ## Lint the wire contract
	@command -v buf >/dev/null || { echo "buf not on PATH -- run: make proto-tools"; exit 1; }
	buf lint

# The gate ADR-022 rests on. No field removal, no renumbering, no type change,
# ever, within a major version -- because scan points in customer networks run
# months-old builds and cannot be told to upgrade first.
proto-breaking: ## Check the contract is additive-only against $(PROTO_BASELINE)
	@command -v buf >/dev/null || { echo "buf not on PATH -- run: make proto-tools"; exit 1; }
	@out=$$(buf breaking --against '$(PROTO_BASELINE)' 2>&1); status=$$?; \
	if [ $$status -eq 0 ]; then \
		echo "buf breaking: clean against $(PROTO_BASELINE)"; \
	elif echo "$$out" | grep -q 'had no .proto files'; then \
		echo "buf breaking: NO BASELINE in $(PROTO_BASELINE) -- nothing to compare against."; \
		echo "Expected only at the commit that establishes the contract. If you see this"; \
		echo "afterwards, the baseline ref is wrong and the additive-only gate is not running."; \
	else \
		echo "$$out"; exit $$status; \
	fi

# gen/ is committed, so it can drift from proto/ silently. This is what stops a
# hand-edited .pb.go, and what stops a .proto change landing without the
# bindings that go with it.
proto-verify: ## Assert gen/ matches proto/
	@command -v buf >/dev/null || { echo "buf not on PATH -- run: make proto-tools"; exit 1; }
	@tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	buf generate --output "$$tmp"; \
	if ! diff -r -q gen "$$tmp/gen" >/dev/null 2>&1; then \
		echo "gen/ does not match proto/. Run: make proto-gen"; \
		diff -r gen "$$tmp/gen" | head -40; \
		exit 1; \
	fi; \
	echo "gen/ matches proto/"

## ---------- dev stack ----------

up: ## Start the dev stack (postgres, minio)
	docker compose up -d --wait

down: ## Stop the dev stack, keep volumes
	docker compose down

## ---------- scan lab ----------

lab-up: ## Start the isolated scan lab
	docker compose -f lab/compose.yml up -d --wait

lab-down: ## Stop the scan lab and drop its volumes
	docker compose -f lab/compose.yml down -v

## ---------- migrations ----------

migrate-up: ## Apply all migrations
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy .env.example to .env."; exit 1; }
	@if [ -z "$$(ls -A $(MIGRATIONS_DIR)/*.sql 2>/dev/null)" ]; then \
		echo "No migrations yet — nothing to apply. Schema lands in session 4."; \
	else \
		docker run --rm --network host \
			-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
			$(MIGRATE_IMAGE) \
			-path=/migrations -database "$(DATABASE_URL)" up; \
	fi

migrate-down: ## Roll back the most recent migration
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy .env.example to .env."; exit 1; }
	docker run --rm --network host \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) \
		-path=/migrations -database "$(DATABASE_URL)" down 1

migrate-verify: ## Apply every migration, roll it all back, apply again
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy .env.example to .env."; exit 1; }
	@echo "==> up"
	@docker run --rm --network host \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) \
		-path=/migrations -database "$(DATABASE_URL)" up
	@echo "==> down (all)"
	@docker run --rm --network host \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) \
		-path=/migrations -database "$(DATABASE_URL)" down -all
	@echo "==> up again"
	@docker run --rm --network host \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) \
		-path=/migrations -database "$(DATABASE_URL)" up
	@echo "up / down / up all succeeded"

rls-test: ## Prove tenant isolation as cvap_app: reads, unset context, writes, composite FK
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy .env.example to .env."; exit 1; }
	@docker run --rm --network host \
		-v "$(CURDIR)/internal/store/testdata:/testdata:ro" \
		-e PGOPTIONS=--client-min-messages=notice \
		postgres:16-alpine \
		psql "$(DATABASE_URL)" -v ON_ERROR_STOP=1 -f /testdata/rls_test.sql

migrate-new: ## Scaffold a migration pair: make migrate-new NAME=snake_case
	@test -n "$(NAME)" || { echo "usage: make migrate-new NAME=snake_case"; exit 1; }
	@echo "$(NAME)" | grep -Eq '^[a-z][a-z0-9_]*$$' || { echo "NAME must be snake_case: $(NAME)"; exit 1; }
	@mkdir -p $(MIGRATIONS_DIR)
	@n=$$(ls $(MIGRATIONS_DIR) 2>/dev/null | grep -oE '^[0-9]{4}' | sort -n | tail -1); \
	next=$$(printf '%04d' $$(( 10#$${n:-0} + 1 ))); \
	up="$(MIGRATIONS_DIR)/$${next}_$(NAME).up.sql"; \
	down="$(MIGRATIONS_DIR)/$${next}_$(NAME).down.sql"; \
	test ! -e "$$up" || { echo "$$up already exists"; exit 1; }; \
	printf -- '-- %s\n--\n-- Every tenant-scoped table gets tenant_id, its own RLS policy and a\n-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).\n-- Partitioning likewise belongs in the creating migration (ADR-016).\n-- Run schema-auditor before merging.\n\n' "$${next}_$(NAME)" > "$$up"; \
	printf -- '-- Down migration for %s\n\n' "$${next}_$(NAME)" > "$$down"; \
	echo "created $$up"; \
	echo "created $$down"

## ---------- gates ----------

safety: ## Scope-enforcement gate (NOT IMPLEMENTED — week 8)
	@echo "NOT IMPLEMENTED — week 8. Scope-enforcement gate, docs/execution-plan.md 6.3."
	@echo ""
	@echo "Runs scans in a network namespace with egress capture and asserts that no"
	@echo "packet ever leaves toward an address outside the configured scope."
	@echo ""
	@echo "Asserts enforcement at exactly TWO sites: Core (planning) and the scan point"
	@echo "runtime (send path). Never in an engine — engines receive resolved,"
	@echo "pre-authorised targets and may not construct new ones. Anything discovered"
	@echo "mid-scan returns to the runtime for authorisation. See ADR-024, ADR-027."
	@echo ""
	@echo "Cases: exclusion overlapping an allow, CIDR boundary arithmetic, hostname"
	@echo "resolving out of scope, redirect to an out-of-scope host, IPv6 forms of"
	@echo "excluded IPv4 addresses, scope changed mid-scan."
	@exit 1

corpus-check: ## Golden corpus diff (NOT IMPLEMENTED — week 8)
	@echo "NOT IMPLEMENTED — week 8. Golden corpus diff, docs/execution-plan.md 6.2."
	@echo ""
	@echo "Diffs every discovery run against the hand-labelled expected result for the"
	@echo "lab targets. Failing thresholds: host recall >= 99%, port recall >= 98%,"
	@echo "service identification >= 90%, finding FP <= 2%, FN <= 5%, merge correctness"
	@echo "100% on labelled scenarios."
	@exit 1

frontmatter: ## Validate .claude agent and skill frontmatter
	python3 .github/scripts/check_frontmatter.py

gitignore-test: ## Assert .gitignore still covers what it must
	python3 .github/scripts/check_gitignore.py

scope-guard-test: ## Test the lab scope guard against its case table
	python3 .claude/hooks/test_lab_scope_guard.py

contract-guard-test: ## Test the frozen-contract guard against its case table
	python3 .claude/hooks/test_protect_contracts.py

# An enrollment token is a bearer credential for a fleet identity and credential
# material is the customer's estate. Both sit in plain fields on messages an
# implementer debugging a stream reaches for first, and the key-based redactor in
# internal/logging cannot see them because generated types render every field
# through String(). Left as a contract comment this gets violated and nobody
# notices, so it is a gate.
secret-logging: ## Fail if a secret-bearing protobuf type reaches a logging call
	python3 .github/scripts/check_secret_logging.py

secret-logging-test: ## Test the secret-logging gate against its case table
	python3 .github/scripts/test_check_secret_logging.py

licences: ## Fail on GPL/AGPL dependencies (ADR-025)
	python3 .github/scripts/check_licences.py
