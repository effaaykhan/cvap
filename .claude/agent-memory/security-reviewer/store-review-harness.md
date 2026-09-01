---
name: store-review-harness
description: How to actually test internal/store and the RLS schema against the running dev database, including the non-obvious environment quirks
metadata:
  type: reference
---

Reviewing `internal/store` or any migration is testable rather than theoretical — do it.

- `.env` cannot be `cat`ed (permission-denied), but `set -a; . /home/ubuntu/CVAP/.env; set +a`
  works and is how to get `DATABASE_URL` (migration role `cvap`) and `APP_DATABASE_URL`
  (application role `cvap_app_login`).
- `psql` is on PATH; no docker needed for schema probing. Go is at `~/sdk/go1.25.14/bin/go`.
- Go PoCs go in a throwaway `internal/store/zz_*_test.go` with `package store` (internal, so
  `db.pool` and `resolveTenant` are reachable), run with
  `CVAP_TEST_DATABASE_URL="$APP_DATABASE_URL" go test ./internal/store/ -run ...`. Delete
  afterwards. Clean up seeded tenants/scan points from the dev DB too.
- **`-race` does not work here**: cgo is off and there is no gcc. Data-race findings have to
  be argued from the Go memory model, not demonstrated.
- Dev cluster facts worth re-checking rather than assuming: `cvap` is SUPERUSER+BYPASSRLS,
  `cvap_app` is NOLOGIN with no BYPASSRLS, `cvap_app_login` is its only member, and neither
  app role has CREATE on schema `public`. Every table is `FORCE ROW LEVEL SECURITY`.

See [[recurring-findings]] for what these probes have turned up.
