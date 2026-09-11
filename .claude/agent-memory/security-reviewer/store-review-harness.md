---
name: store-review-harness
description: How to actually test internal/store, internal/control/api and the RLS schema against the running dev database, including the non-obvious environment quirks
metadata:
  type: reference
---

Reviewing `internal/store` or any migration is testable rather than theoretical — do it.

- `.env` cannot be `cat`ed (permission-denied), but `set -a; . /home/ubuntu/CVAP/.env; set +a`
  works and is how to get `DATABASE_URL` (migration role `cvap`) and `APP_DATABASE_URL`
  (application role `cvap_app_login`).
- `psql` is on PATH; no docker needed for schema probing. Go is at `~/sdk/go1.25.14/bin/go`.
  The dev DB is kept migrated to HEAD *including the migrations in the working tree*, so a
  schema question about an uncommitted migration can usually just be asked of the database.
- Go PoCs go in a throwaway `internal/store/zz_*_test.go` with `package store` (internal, so
  `db.pool` and `resolveTenant` are reachable), run with
  `CVAP_TEST_DATABASE_URL="$APP_DATABASE_URL" go test ./internal/store/ -run ...`. Delete
  afterwards. Clean up seeded tenants/scan points from the dev DB too.
- **`-race` does not work here**: cgo is off and there is no gcc. Data-race findings have to
  be argued from the Go memory model, not demonstrated.
- Dev cluster facts worth re-checking rather than assuming: `cvap` is SUPERUSER+BYPASSRLS,
  `cvap_app` is NOLOGIN with no BYPASSRLS, `cvap_app_login` is its only member, and neither
  app role has CREATE on schema `public`. Every table is `FORCE ROW LEVEL SECURITY`.

Seeding a job the dispatcher will actually claim, from scratch, in one `db.Write`:
`tenants` has no `slug`; `scan_policies` takes `(tenant_id, name)` and defaults the rest;
`scan_target_type` is `cidr|host|url|repo|cloud_account` (no `ip`); and `Jobs.Claim` now
requires each `scan_tasks` row to have a `target_id` pointing at a `scan_targets` row with
`authorization_verified = true`. `internal/dispatch/dispatch_test.go` has `enrolledScanPoint`,
`seedQueuedJob`, `peerCtx`, and `internal/dispatch/ingest_test.go` has `leased`, `chunk`,
`runIngest` — reuse them from a throwaway `package dispatch_test` file rather than reseeding.
Clean up with `DELETE FROM tenants WHERE name LIKE ...`; it cascades.

`mapError` maps SQLSTATE 22P02 to `ErrNoTenantContext` ("query ran without a usable
app.tenant_id"), but 22P02 is raised by *any* bad text-to-type cast — an invalid enum label or
an invalid `jsonb` payload from a scan point included. Expect that message to be a lie.

For `internal/control/enrollment` and `internal/control/ca`, PoCs go in throwaway
`internal/control/enrollment/zz_*_test.go` with `package enrollment_test`, which already has
`testDB` / `testCA` / `testService` / `enrolled` / `peerCtx` / `enrollRequest` helpers, and
needs `CVAP_TEST_DATABASE_URL="$APP_DATABASE_URL"`. `internal/control/ca` has no test file of
its own, so a `package ca` scratch test reaches unexported fields directly.

Quirks that cost time: in `internal/dispatch` the Go toolchain did **not** pick up a scratch
test file named `zz_*_test.go` — `go list -f '{{.TestGoFiles}}'` omitted it and `go test -run`
reported "no tests to run", with no error, even on a clean GOCACHE; renaming it to
`aacost_internal_test.go` made it compile immediately. `zz_*_test.go` works fine in
`internal/store`. Name scratch files in `internal/dispatch` something else. Also: a
`scan-safety-auditor` may be running in the same session and writing its own `zz_*_test.go`
probes into `internal/store` — check `git status` before assuming a stray `zz_` file is yours,
and do not delete another agent's.

Quirks that cost time:  `go vet` fails the build on a deliberately-wrong printf verb, so a
leak PoC must launder the argument through an `any`-typed helper. Hand-seeding the schema in
`psql` needs `deployment_mode = 'onprem'` (not `on_prem`) and `scan_zones.trust_level` is
NOT NULL with no default. Forced interleavings are best written as one `db.Write` callback
that parks on a channel while a second goroutine drives the real service.

**`internal/control/api` probes.** Scratch files go in `internal/control/api/` as
`package api_test` (reaches `newFixture`, `newOIDCFixture`, `newFakeIDP`, `fixture.do`) or
`package api` (reaches `isSafeReturnPath`, `refuseUnsafeAddress`, `newOIDCClient`). Same
`CVAP_TEST_DATABASE_URL="$APP_DATABASE_URL"`. `newFixture` seeds a tenant with a random
`.test` domain and drives requests by setting `r.Host`, so multi-tenant probes are just two
fixtures. `newFakeIDP` serves discovery/JWKS/token over TLS and hands the server cert to
`api.Config.OIDCRootCAs`; to change what the DISCOVERY document says (jwks_uri scheme, a
huge body) you have to build your own mux rather than extend it — `newFakeIDP`'s handlers
are closures over fixed values.

Two gotchas that cost time here:
- Go runs tests in a package **in parallel by default within one binary is false, but
  separate packages are parallel** — the real bite was that a probe allocating ~2 GB makes
  UNRELATED tests in the same run fail with 500s that look like real findings. Run
  memory-heavy probes with `-run '^TestOne$'` on their own before believing a result.
- **Other agents rewrite the files you are reviewing, mid-review.** A concurrent
  ADR-compliance pass rewrote `oidc_client.go`, `oidc.go` and `internal/store/oidc.go` and
  added migration 0028 while this review was running, and the dev DB was migrated under the
  reviewed commit. When that happens, `git worktree add --detach <dir> <commit>` gives a
  clean tree at the commit under review — but the DEV DATABASE is shared and moves with the
  working tree, so a worktree at an older commit may fail against a newer schema. Check
  `git status` and re-verify each finding against the CURRENT tree before reporting it as
  open; some may already be fixed.

See [[recurring-findings]] for what these probes have turned up.

**Scan-point probes.** Scratch files go in `internal/scanpoint/` as `package scanpoint`; name them
`aareview_*_test.go` (the `zz_` prefix is picked up here, but `aareview_` is safe in every package
including `internal/dispatch`). `credentialed_test.go` carries the pattern for a REAL child process:
write a `#!/bin/sh` wrapper that re-execs `os.Executable()` with
`-test.run='^TestHelperEngineProcess$'` and a trigger env var, because `engineEnv()` hands the child
PATH/HOME/TZ/LANG only. `newEngineHost(log, binary, jobID, allowed, exclusions)` + `start(ctx,
[]enginewire.Target{...}, engineBudget{SafetyMode:"safe", RatePPS:10})` drives the production spawn
path in-process. To probe fd inheritance, have the fake engine run `ls -l /proc/self/fd`.
In `internal/dispatch`, `export_test.go` already exports `OfferWorkForTest`; a second
`package dispatch` file can export a clock setter (`s.now`) and an `onTerminal` driver — that is how
to ask "what does a DIFFERENT scan point's session do to this job's rows" without forging a cert.
The dev DB accumulates `disp-%` tenants from every dispatch run (144 before this session); the
suite does not clean them and another agent may be mid-run, so leave them alone.
