# internal/store

PostgreSQL access. RLS-aware.

Rules:

- Every connection sets the tenant context before use — including background workers,
  migrations aside. A query that runs without it must fail, not fall back to unfiltered
  (ADR-002).
- Application roles never bypass RLS. Only migration roles do.
- Every tenant-scoped table carries a denormalised `tenant_id` with its own policy, and
  every child table has a composite FK `(tenant_id, parent_id)` to its parent. Scope is not
  inherited through a plain foreign key — Postgres RLS does not work that way (ADR-017).
- `RULE_PACK`, `RULE`, `VULNERABILITY_DEF`, `VENDOR_ADVISORY` and `ADVISORY_FIXED_PACKAGE`
  are global knowledge tables and correctly carry no `tenant_id`.
- Observations are ephemeral. **Anything that must outlive them is copied at the moment it
  becomes load-bearing** (ADR-016): merge evidence into `asset_identity_keys`, finding and
  verdict payloads into `evidence`. `evidence.observation_id` is a nullable soft reference,
  never a hard FK.
- `observations` is partitioned monthly; `evidence` is not partitioned — it is pruned by
  finding status, not by time.
- Large evidence goes to the object store; the row holds a summary and a pointer (ADR-015).

Nine tables in the schema are not drawn in the v2 ERD. They are required, and ADR-029 records
why, so they do not read as inventions when you diff schema against diagram: `result_submissions`
(ADR-026's idempotency ledger — `observations.submission_id` has no FK target without it),
`asset_resolution_queue` (ADR-007's unresolved merge queue), `enrollment_tokens` and
`scan_point_certificates` (ADR-018), `kill_switches` and `kill_acks` (ADR-024), `cancel_acks`
(ADR-024's per-scan half, migration 0025), and the join tables
`scan_policy_credential_profiles` and `advisory_vuln_map`.

That list is ADR-029's to hold, not this file's — a tenth table belongs in the ADR, and this
paragraph should be updated from it rather than the other way round. It said "four" for two
sessions after the ADR said eight.

The application role is `cvap_app`: `NOLOGIN`, `NOBYPASSRLS`, `NOSUPERUSER`, granted
per-table by the migration that creates each table rather than by a blanket schema grant, so
a new table defaults to no access. Migration 0001 asserts the role holds neither `BYPASSRLS`
nor `SUPERUSER` and fails the deploy if it does — repeat that assertion at the top of any
migration that changes its grants. `internal/store/testdata/rls_test.sql` (`make rls-test`)
proves isolation as that role: filtered reads, an unset tenant context raising rather than
returning nothing, a refused cross-tenant write, and a refused cross-tenant composite FK.

Every RLS policy carries **both** `USING` and `WITH CHECK`, and uses the one-argument
`current_setting('app.tenant_id')`. The two-argument form returns NULL when unset, which
makes the predicate NULL and silently returns nothing instead of raising.

## The pool

`Read` and `Write` are the only doors, and a `TenantID` is what opens them. There is no
`Acquire`, no `Begin`, no exported accessor for the pool or a connection.

- **`SET LOCAL` inside a transaction, always.** A session `SET` would have to be undone by
  our own cleanup on release, and cleanup that must run is cleanup that eventually does not.
  Postgres discards `SET LOCAL` at `COMMIT`/`ROLLBACK`, so a connection returning to the pool
  *cannot* carry the previous tenant. **This is why there is no non-transactional path, and
  adding one would undo the guarantee.** Set via `set_config('app.tenant_id', $1, true)` — a
  bind parameter, because `SET` takes none and interpolating there is an injection shape in
  the statement that decides which tenant's data is visible.
- **`Read` opens `READ ONLY`**, so a write on a read path fails at the database.
- **`Conn` holds `pgx.Tx` as a named field, never embedded.** Embedding promotes `Tx.Conn()`.
  For the same reason `Conn.Query` returns `store.Rows`, not `pgx.Rows`: the pgx interface
  carries `Conn() *pgx.Conn`, so returning it would hand out the connection through a method
  nobody wrote. Same for `SendBatch` and `store.BatchResults`.
- **A `Conn` is dead after its callback returns** — every method then gives `ErrConnReleased`.
- **Repositories are stateless and take the tenant from `c.Tenant()`**, never as an argument,
  so a row cannot be written claiming a tenant the connection is not scoped to.
- `store.Open` refuses a role holding `BYPASSRLS` or `SUPERUSER`. Migration 0001 asserts the
  same at deploy time; the two catch different things, the second catching a `DATABASE_URL`
  edited to the migration user to "fix" a permission error.

`encapsulation_test.go` parses the package and fails the build if any of that regresses. It
is a test rather than a comment because the regression looks like a convenience in review.

**Connect as `cvap_app_login`, not `cvap_app`.** `cvap_app` is `NOLOGIN`: a group role
carrying the grants, with no password to leak or rotate. A `LOGIN` member of it is what
connects — `internal/store/testdata/app_role.sql` in dev and CI, provisioning elsewhere.
`APP_DATABASE_URL` is that connection string; `DATABASE_URL` is the migration role and must
never be used by the running application.

## Deliberate exceptions, all narrow

- **`DB.resolveTenant`** (ADR-031) maps a scan point certificate fingerprint to a tenant with
  no tenant context, because deriving the tenant is its whole job. It is unexported, returns
  only a `TenantID`, and must never return a connection. The narrowness lives in the database:
  `tenant_for_scan_point` is `SECURITY DEFINER`, returns one uuid, resolves only enrollable
  statuses, and returns NULL rather than raising so it is not an enrolment oracle.
- **`DB.ActiveTenantIDs`** (ADR-036) lists active tenant ids for the dispatch sweeper, and is
  the only unscoped read in the package. A sweep has no tenant to inherit — the thing it reacts
  to is a scan point that stopped talking — and `ExpireLeases` had no caller at all until it
  existed, so ADR-012's at-most-once rule was written down and never enforced. It returns
  `[]TenantID` and nothing wider, takes no filter, and is Core-side only: nothing reachable
  from a wire handler may call it. The narrowness is in the database — `active_tenant_ids()` is
  `SECURITY DEFINER`, `STABLE`, parameterless and returns `SETOF uuid`.

There is no *general* unscoped path, deliberately. The knowledge tables carry no `tenant_id`,
so they would need one — but nothing in this package reads them yet, and an escape hatch with
no caller is how escape hatches get misused. The session that needs `rules` on the finding read
path should make the case then, the way ADR-036 made it for the sweep.

## Observations

`ingest_state` is written at INSERT as `pending` and promoted **once** — to `accepted` or
`quarantined` — by the terminal ack, in the same transaction as the final epoch check. It is a
**ratchet**, not a flag: migration 0020 grants `UPDATE (asset_id, ingest_state)` and installs a
`BEFORE UPDATE` trigger that permits `pending → anything` and refuses every transition out of a
terminal state. A grant cannot express "ingest may set this and the pipeline may not" — both
run as `cvap_app` — but a ratchet can, because un-quarantining is not an operation anything
legitimately performs.

Landing `pending` rather than `accepted` is what closes the mid-upload window: a submission
arrives in chunks and its epoch can be superseded partway, so with rows landing `accepted`
chunk 0 is readable before chunk 5 reveals the supersession. The pipeline filters `accepted`,
so an in-flight submission is invisible to it *without the pipeline knowing submissions exist*.

An abandoned upload leaves rows `pending` forever. That is correct — the results were never
attested complete — and it needs a **metric**, not a cleanup: `Observations.PendingOlderThan`
is that query.

Every read path filters `ingest_state = 'accepted'` in the query rather than leaving it to the
caller — a filter the caller can forget is one that will be forgotten. `ListQuarantined` and
`PendingOlderThan` are the two deliberate exceptions, named so.

`submission_id` comes from the wire and is therefore attacker-chosen. It is unique **per
tenant** (migration 0022), never globally: a global unique let one tenant collide with
another's id, which both discarded results ADR-026 says are always stored and answered a
cross-tenant existence question.

`Policies.ForJob` and `Policies.ScopeRules` exist for the dispatch path only. ADR-024's
ceilings are LOWER-ONLY, and `max_rate_pps` has a CHECK bounding it at the platform default —
but Core compares again when it builds the constraints, because a ceiling enforced in one place
is decorative and the place that must never be wrong is the one deciding what goes on the wire.

Reads over `observations` require a bounded time window. It is partitioned by `observed_at`,
so a query without one scans every live partition.

## cert_fingerprint has exactly two writers

`scan_points.cert_fingerprint` must always name the live row in
`scan_point_certificates` for that scan point. No constraint enforces it: a circular foreign
key would need `DEFERRABLE INITIALLY DEFERRED` on one side, and a deferred constraint is the
kind of cleverness that surprises whoever debugs it at 2am.

Instead each pairing is **one statement** — `Certificates.EnrollScanPoint` takes the
certificate's fingerprint from the scan point row it is inserting, and
`Certificates.RotateCertificate` takes the scan point's fingerprint from the certificate row
it is inserting. There is no window where one exists without the other, and no way for a
caller to do half of it.

**Any code path that writes `cert_fingerprint` outside those two statements is a defect.** Not
a style preference: the fingerprint is the scan point's identity in the audit log and the
input to `tenant_for_scan_point`, so a scan point pointing at a superseded certificate is a
peer that cannot authenticate, and one pointing at no certificate at all is an identity with
no issuance record. `TestScanPointAndCertificateHistoryAgree` asserts the agreement after both
enrolment and rotation.

## Pre-tenant resolution is a closed class of three (ADR-041, superseding ADR-033)

Three lookups run before any tenant is known, because deriving the tenant is their whole job:
`ResolveScanPointTenant` (certificate fingerprint), `ResolveEnrollmentTokenTenant` (token hash)
and `ResolveDomainTenant` (request hostname). All three are thin wrappers over one unexported
implementation, `resolvePreTenant`, which is the only place in this package that queries the
raw pool.

Every member returns exactly `(TenantID, error)` and nothing wider, and every resolution
failure is the same sentinel — distinguishing "unknown" from "expired" from "revoked" is an
oracle. A FOURTH member amends ADR-041; `encapsulation_test.go` checks the class, so adding one
without reading the ADR fails the build.

`ResolveDomainTenant` is by far the hottest: it runs on every operator API request, not only at
login, because a session cookie is scoped to the tenant that issued it and cannot be validated
until the tenant is known. **`Tenants.Create` therefore requires a domain and has no overload
that omits one** — on-prem included, where it is usually `localhost`. A tenant created without
one is a tenant nobody can sign in to, and the single-tenant path that skips resolution is the
branch ADR-017 exists to prevent.

Resolution is **not** redemption. `ResolveEnrollmentTokenTenant` says which tenant to open a
transaction as; single-use is enforced inside it by `EnrollmentTokens.Redeem`, a conditional
UPDATE whose atomicity comes from the database re-evaluating its predicate after a lock wait.

## Errors carry schema detail — do not pass them to a caller

`mapError` embeds `pgErr.ConstraintName`, `pgErr.ColumnName` and `pgErr.Message`. That is
deliberate and useful at this layer: `findings_dedup_key_uidx` and `network_ranges_zone_fk`
say very different things about what went wrong. Every one of them is also a schema fact.

**The API layer must not return these verbatim.** Map to a sentinel, log the detail, return
something that does not describe the schema to whoever sent the request. Written down here
while the constraint was being created rather than left to be remembered when the API landed —
and it landed: `internal/control/api/errors.go` is the one-way mapping, and
`TestErrorBodiesNeverCarrySchemaDetail` drives it with an error carrying a constraint name, a
column name and a message.

Two errors are deliberately conflated and two deliberately are not:

- `ErrNotFound` covers both "no such row" and "belongs to another tenant". Under RLS these
  are the same answer, and an error that distinguished them would be a cross-tenant oracle.
- `ErrTenantIsolation` (an RLS refusal) and `ErrNotPermitted` (a missing GRANT) are separate,
  even though PostgreSQL reports both as SQLSTATE 42501. A cross-tenant write attempt is a
  security event worth alerting on; a missing GRANT is a deployment mistake. Alerting that
  cannot tell them apart fires on the wrong one and gets muted.

Run `schema-auditor` on any migration.
