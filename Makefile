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
        env-check app-role store-test e2e dev-ca gosec mutate \
        contract-guard-test fmt-check tidy-check govulncheck db-gates db-reachable

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
# hand. Copy env.example to .env first.
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

# test runs with the race detector, and says so loudly when it cannot.
#
# ============================================================================
# -race needs cgo and a C compiler. Not every development box has one.
# ============================================================================
#
# The old form was `go test ./... -race` unconditionally, which on a machine
# without gcc fails at the FIRST target of `make ci` with "cgo: C compiler not
# found" — so the whole local gate was unrunnable there, which is how gates
# started being run one at a time by hand and how two of them stopped being run
# at all.
#
# Falling back to a non-race run is the right trade, and announcing it is what
# makes it a trade rather than a silent downgrade: Conn.done is an atomic.Bool
# because a callback can start a goroutine that outlives it, and until -race ran
# in CI that fix was reasoned rather than demonstrated. CI always has the
# compiler and always runs with -race; a local run without it is a weaker claim
# and has to say so.
test: ## Run tests with the race detector, or say loudly that it could not
	@if [ "$$CGO_ENABLED" != "0" ] && { command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; }; then \
		echo "go test ./... -race"; \
		CGO_ENABLED=1 go test ./... -race; \
	else \
		echo ""; \
		echo "################################################################"; \
		echo "#  RACE DETECTOR UNAVAILABLE: no C compiler on this machine     #"; \
		echo "#                                                              #"; \
		echo "#  Running WITHOUT -race. CI runs with it and this run does     #"; \
		echo "#  not, so a data race introduced here will be caught there     #"; \
		echo "#  and not now. Install gcc or clang to close the gap.          #"; \
		echo "################################################################"; \
		echo ""; \
		go test ./...; \
	fi

vet: ## go vet
	go vet ./...

lint: ## golangci-lint
	golangci-lint run

# gosec, and it is NOT what `lint` runs.
#
# golangci-lint has its own gosec integration and this repository does not enable
# it, so `make lint` can be clean while CI's standalone gosec fails — which is
# exactly what happened when the scan point runtime landed. The two also read
# different directives: golangci-lint honours //nolint:gosec, standalone gosec
# honours #nosec, and a //nolint on a gosec finding is a suppression that
# suppresses nothing while looking like it does.
#
# Same invocation as CI, including the gen/ exclusion, so a clean run here means
# a clean run there.
GOSEC_VERSION := v2.29.0

gosec: ## Static security analysis, exactly as CI runs it
	@command -v gosec >/dev/null || go install github.com/securego/gosec/v2/cmd/gosec@$(GOSEC_VERSION)
	gosec -exclude-dir=gen ./...

fmt: ## Format and tidy
	gofmt -l -w .
	go mod tidy

tidy: fmt

# fmt-check and tidy-check are the CI steps, and `fmt` cannot stand in for
# either: `fmt` WRITES, so it always succeeds and proves nothing about what is
# committed. Neither was reachable from `make ci` until now.
fmt-check: ## Fail if anything is not gofmt-clean
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "These files are not gofmt-clean:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

# tidy-check asserts that `go mod tidy` is a NO-OP, which is the property CI
# means by "go mod tidy is committed".
#
# CI expresses it as `go mod tidy && git diff --exit-code`, which works there
# because the runner starts from a clean checkout. It cannot work here: a
# dependency you have just added and not yet committed is a git diff, so the
# check would fail on every legitimate `go get` until it was committed — and a
# gate that cannot pass before you commit is a gate you learn to skip.
#
# Comparing against a snapshot asks the same question without involving git.
tidy-check: ## Fail if go mod tidy would change go.mod or go.sum
	@cp go.mod .go.mod.tidycheck && cp go.sum .go.sum.tidycheck
	@go mod tidy || { rm -f .go.mod.tidycheck .go.sum.tidycheck; exit 1; }
	@if ! cmp -s go.mod .go.mod.tidycheck || ! cmp -s go.sum .go.sum.tidycheck; then \
		echo "go mod tidy changed go.mod or go.sum:"; \
		diff -u .go.mod.tidycheck go.mod || true; \
		diff -u .go.sum.tidycheck go.sum || true; \
		rm -f .go.mod.tidycheck .go.sum.tidycheck; \
		exit 1; \
	fi
	@rm -f .go.mod.tidycheck .go.sum.tidycheck

govulncheck: ## Known vulnerabilities in the dependency graph, as CI runs it
	@command -v govulncheck >/dev/null || go install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

# ci is the WHOLE runner, and keeping it that way is the point.
#
# Two of the last three CI failures were gates that existed only on the runner.
# rls-test caught fixture rows missing from three tables — its sweep refuses to
# prove isolation for a table holding no rows, which is one of the better checks
# here — and gofmt and `go mod tidy` were never reachable from this target at
# all. A `make ci` that is a subset of CI trains you to trust a green local run
# that means less than it says.
#
# db-gates is last: slowest, and the failure most likely to need the dev stack
# looked at. govulncheck is here for parity and needs the network; it can fail on
# an advisory published against code this commit did not touch, which is true of
# CI too and is the point of running it.
ci: fmt-check tidy-check build vet test lint gosec govulncheck proto frontmatter \
    gitignore-test scope-guard-test contract-guard-test secret-logging \
    secret-logging-test env-check licences db-gates ## Everything CI runs, locally

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
	@# Warn when the local .env is missing a key the template defines. A missing
	@# key does not fail here -- it fails much later, in whatever subsystem first
	@# reads an empty string, which is how MINIO_BUCKET and LOG_LEVEL went missing
	@# from a .env without anything noticing.
	@# Plain sh: make's default SHELL is /bin/sh, which has no process
	@# substitution, so this compares the two key lists with a loop and grep
	@# rather than comm on two <(...) inputs.
	@if [ -f .env ] && [ -f env.example ]; then \
		missing=''; \
		for k in $$(grep -oE '^[A-Z][A-Z0-9_]*=' env.example | tr -d '='); do \
			grep -qE "^$$k=" .env || missing="$$missing $$k"; \
		done; \
		if [ -n "$$missing" ]; then \
			echo "WARNING: your .env is missing keys that env.example defines:"; \
			for k in $$missing; do echo "  - $$k"; done; \
			echo "The stack will start. Whatever reads them will get an empty string."; \
		fi; \
	fi
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
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy env.example to .env."; exit 1; }
	@if [ -z "$$(ls -A $(MIGRATIONS_DIR)/*.sql 2>/dev/null)" ]; then \
		echo "No migrations yet — nothing to apply. Schema lands in session 4."; \
	else \
		docker run --rm --network host \
			-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
			$(MIGRATE_IMAGE) \
			-path=/migrations -database "$(DATABASE_URL)" up; \
	fi

migrate-down: ## Roll back the most recent migration
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy env.example to .env."; exit 1; }
	docker run --rm --network host \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) \
		-path=/migrations -database "$(DATABASE_URL)" down 1

# migrate-verify runs against a THROWAWAY database, never the dev one.
#
# It used to run up / down -all / up against DATABASE_URL directly, which made
# the verification destructive to whatever you were working on. Two costs, and
# the second was the one that bit:
#
#   * `down -all` dropped cvap_app, taking cvap_app_login's membership with it,
#     so every store test failed until you remembered `make app-role`. That
#     ordering wart was carried in a comment on store-test since session 6.
#   * Some tests legitimately leave data that a down migration must refuse to
#     roll back through. TestSubmissionIdCollisionAcrossTenantsIsNotADuplicate
#     creates a submission_id held by two tenants, which is exactly what 0022's
#     down refuses — correctly, because restoring the global unique would mean
#     deleting a tenant's results. The app role holds no DELETE on
#     result_submissions (ADR-026), so the test cannot clean up after itself and
#     should not be able to. The dev loop is what has to bend.
#
# A fresh database also makes the verification honest: it proves the migrations
# apply from nothing, rather than from whatever this database happened to hold.
VERIFY_DB ?= cvap_migrate_verify
# Swap the database name, keeping user, host, port and query string.
VERIFY_URL = $(shell echo "$(DATABASE_URL)" | sed -E 's,(://[^/]*)/[^?]*,\1/$(VERIFY_DB),')

# psql as the migration role, for the create and drop either side of a run.
define verify_psql
docker run --rm --network host postgres:16-alpine \
	psql "$(DATABASE_URL)" -v ON_ERROR_STOP=1 -q -c
endef

## ---------- gates that need a database ----------

# db-gates: every CI check that needs Postgres, skipped LOUDLY when there is none.
#
# ============================================================================
# A skip prints a banner. It never passes quietly.
# ============================================================================
#
# The requirement is that `make ci` still works on a machine with no dev stack,
# and the hazard is the obvious implementation of it: a conditional that turns
# four real gates into nothing and lets the target exit 0 with no output. This
# repository keeps finding that shape — `safety` and `corpus-check` are failing
# stubs for exactly this reason, because a gate that silently passes is worse
# than one that fails, since the first gets trusted.
#
# So the skip is as loud as a failure looks, names every gate that did not run,
# and says how to run them. What it must never be is invisible.
db-gates: ## Every gate needing Postgres. Skips loudly, never silently, when there is none.
	@if $(MAKE) --no-print-directory db-reachable >/dev/null 2>&1; then \
		set -e; \
		$(MAKE) --no-print-directory migrate-verify; \
		$(MAKE) --no-print-directory migrate-up; \
		$(MAKE) --no-print-directory app-role; \
		$(MAKE) --no-print-directory rls-test; \
		$(MAKE) --no-print-directory store-test; \
		$(MAKE) --no-print-directory e2e; \
		$(MAKE) --no-print-directory mutate; \
	else \
		echo ""; \
		echo "################################################################"; \
		echo "#  SKIPPED: every gate that needs a database                   #"; \
		echo "#                                                              #"; \
		echo "#  NOT RUN:  migrate-verify   rls-test                         #"; \
		echo "#            store-test       e2e         mutate               #"; \
		echo "#                                                              #"; \
		echo "#  THIS IS NOT A PASS. rls-test proves tenant isolation and    #"; \
		echo "#  refuses to prove it for any table holding no fixture rows;  #"; \
		echo "#  store-test runs every integration suite in the repository.  #"; \
		echo "#  CI runs all four, so a green run here claims less than it   #"; \
		echo "#  looks like it does.                                         #"; \
		echo "#                                                              #"; \
		echo "#  To run them:   make up && make ci                           #"; \
		echo "################################################################"; \
		echo ""; \
	fi

# db-reachable exits 0 when Postgres is up and DATABASE_URL points at it.
#
# Both halves matter. An unset DATABASE_URL is a machine with no .env; a set one
# with nothing listening is a machine whose dev stack is down. Both skip rather
# than fail — and neither is allowed to look like a pass, which is what the
# banner above is for.
db-reachable:
	@test -n "$(DATABASE_URL)" || exit 1
	@docker run --rm --network host postgres:16-alpine \
		psql "$(DATABASE_URL)" -v ON_ERROR_STOP=1 -qtAc 'SELECT 1' >/dev/null 2>&1

migrate-verify: ## Apply every migration, roll it all back, apply again — on a throwaway database
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy env.example to .env."; exit 1; }
	@echo "==> creating throwaway database $(VERIFY_DB)"
	@$(verify_psql) 'DROP DATABASE IF EXISTS $(VERIFY_DB) WITH (FORCE)'
	@$(verify_psql) 'CREATE DATABASE $(VERIFY_DB)'
	@echo "==> up"
	@docker run --rm --network host \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) \
		-path=/migrations -database "$(VERIFY_URL)" up
	@echo "==> down (all)"
	@docker run --rm --network host \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) \
		-path=/migrations -database "$(VERIFY_URL)" down -all
	@echo "==> up again"
	@docker run --rm --network host \
		-v "$(CURDIR)/$(MIGRATIONS_DIR):/migrations" \
		$(MIGRATE_IMAGE) \
		-path=/migrations -database "$(VERIFY_URL)" up
	@# Dropped on success only. A failed run leaves the database for inspection,
	@# and the DROP IF EXISTS above clears it next time.
	@$(verify_psql) 'DROP DATABASE IF EXISTS $(VERIFY_DB) WITH (FORCE)'
	@echo "up / down / up all succeeded (on $(VERIFY_DB), now dropped)"

rls-test: ## Prove tenant isolation as cvap_app: reads, unset context, writes, composite FK
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy env.example to .env."; exit 1; }
	@docker run --rm --network host \
		-v "$(CURDIR)/internal/store/testdata:/testdata:ro" \
		-e PGOPTIONS=--client-min-messages=notice \
		postgres:16-alpine \
		psql "$(DATABASE_URL)" -v ON_ERROR_STOP=1 -f /testdata/rls_test.sql

app-role: ## Create the LOGIN role the application connects as (dev and CI)
	@test -n "$(DATABASE_URL)" || { echo "DATABASE_URL is not set. Copy env.example to .env."; exit 1; }
	@docker run --rm --network host \
		-v "$(CURDIR)/internal/store/testdata:/testdata:ro" \
		postgres:16-alpine \
		psql "$(DATABASE_URL)" -v ON_ERROR_STOP=1 -q -f /testdata/app_role.sql

# Extra flags for store-test. CI passes -race; it is not the default because
# -race needs cgo and a C compiler, which not every development box has, and a
# target that fails to build locally stops being run locally.
#
# CI MUST pass it. Conn.done is an atomic.Bool because a callback can start a
# goroutine that outlives it, and that fix was reasoned rather than demonstrated
# until the race detector ran over these tests. Reasoned-not-demonstrated is the
# gap the tenant-context bugs sat in.
GOTEST_FLAGS ?=

# The end-to-end suite runs the REAL binaries as two OS processes over real TLS:
# enrolment, mTLS dispatch, an engine subprocess, chunked submission, and rows in
# Postgres at the end. Everything below the process boundary — certificate
# loading, the handshake, SIGTERM reaching an engine's process group, a
# subprocess dying and the runtime noticing — is what an in-process test cannot
# reach, and all of it is where a scan point actually fails.
#
# It builds what it runs rather than assuming a prior `make build`, so the suite
# is honest about which source it exercised. Slow by construction: two of the
# three tests wait out a 20s lease renewal, because that is the mechanism under
# test rather than an inconvenience.
e2e: ## Run the two-process end-to-end suite against the dev database
	@test -n "$(APP_DATABASE_URL)" || { echo "APP_DATABASE_URL is not set. Copy env.example to .env."; exit 1; }
	CVAP_TEST_DATABASE_URL="$(APP_DATABASE_URL)" go test ./test/e2e/... -count=1 -timeout 10m -v

# A development CA and an enrollment token, for running the two binaries by hand.
# NEVER a production CA key: this one mints identities into a fleet, and Core
# holds a map of a customer's weaknesses plus credentials to their estate.
dev-ca: ## Generate a development CA into ./secrets (gitignored)
	@mkdir -p secrets
	go run ./cmd/cvap-cli dev-ca ./secrets

# Every package whose tests SKIP without a database. They skip silently, which
# is the hazard: a suite that skips looks exactly like a suite that passes in
# `make test`, and internal/dispatch sat unrun in CI for that reason. Adding a
# package here is what makes its integration tests actually execute.
DB_TEST_PKGS = ./internal/store/... ./internal/control/... ./internal/dispatch/...

store-test: ## Run the database-backed suites against the dev database as the application role
	@test -n "$(APP_DATABASE_URL)" || { echo "APP_DATABASE_URL is not set. Copy env.example to .env."; exit 1; }
	CVAP_TEST_DATABASE_URL="$(APP_DATABASE_URL)" go test $(DB_TEST_PKGS) -count=1 $(GOTEST_FLAGS)

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

env-check: ## Assert env.example matches the environment the code reads
	python3 .github/scripts/check_env_example.py

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

# Mutation testing for the guard scripts.
#
# A suite that has never failed proves nothing, and these suites have been green
# over checks they never reached three sessions running — the in-HEAD test, the
# dedup key, and "exactly one line changed" — each time because every existing
# case was caught by a DIFFERENT check first. Running the mutations by hand is
# what let that happen twice more after the first discovery.
#
# Each suite declares its own mutation list beside itself, so adding a check
# means adding the mutation that proves the check is reached, in the same diff.
# A surviving mutation fails the build with the name of the check nothing
# exercises.
# The Go suites here need a database, and a suite that SKIPS passes — so every
# mutation it would have killed survives instead. The driver refuses an empty
# baseline for exactly that reason; passing the URL is what makes the run mean
# something rather than fail loudly.
mutate: ## Assert every guard check is actually reached by its test suite
	CVAP_TEST_DATABASE_URL="$(APP_DATABASE_URL)" python3 .claude/hooks/mutate.py

contract-guard-test: ## Test both halves of the frozen-contract guard
	python3 .claude/hooks/test_protect_contracts.py
	python3 .claude/hooks/test_verify_contracts.py

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
