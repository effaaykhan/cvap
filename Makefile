# CVAP make targets. See CLAUDE.md for the short list.
#
# safety and corpus-check are deliberate failing stubs. A safety gate that
# silently passes is worse than one that fails, because the first is trusted.

.PHONY: help build test lint vet fmt tidy ci \
        up down lab-up lab-down \
        migrate-up migrate-down migrate-new \
        safety corpus-check frontmatter licences gitignore-test scope-guard-test

# golang-migrate, pinned by digest rather than tag so the tool cannot change
# under a running project (ADR-025: consume commodity infrastructure).
MIGRATE_IMAGE := migrate/migrate@sha256:f21c436af23c282f4516b00ba3e93bccf5c5fe5cd52530fd5c319a936998f539
MIGRATIONS_DIR := migrations

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

ci: build vet test lint frontmatter gitignore-test scope-guard-test ## Everything CI runs, locally

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

licences: ## Fail on GPL/AGPL dependencies (ADR-025)
	python3 .github/scripts/check_licences.py
