.PHONY: build test lint safety corpus-check lab-up lab-down migrate-up migrate-new

build:
	go build ./...

test:
	go test ./... -race

lint:
	golangci-lint run

safety:
	@echo "NOT IMPLEMENTED. Scope-enforcement suite — see docs/execution-plan.md 6.3."
	@echo "Runs scans in a netns with egress capture, asserts no packet leaves scope."
	@exit 1

corpus-check:
	@echo "NOT IMPLEMENTED. Golden corpus diff — see docs/execution-plan.md 6.2."
	@exit 1

lab-up:
	docker compose -f lab/compose.yml up -d

lab-down:
	docker compose -f lab/compose.yml down -v

migrate-up:
	@echo "NOT IMPLEMENTED. Wire to your migration tool in week 1."
	@exit 1

migrate-new:
	@test -n "$(NAME)" || (echo "usage: make migrate-new NAME=snake_case"; exit 1)
	@echo "NOT IMPLEMENTED. Should scaffold migrations/NNN_$(NAME).{up,down}.sql"
	@exit 1
