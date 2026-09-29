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
- `RULE_PACK`, `RULE`, `VULNERABILITY_DEF`, `VENDOR_ADVISORY`, `ADVISORY_FIXED_PACKAGE`,
  `knowledge_feed_status` (advisory-feed provenance/freshness, migration 0034),
  `product_packages` (the product→package map for release resolution, migration 0035, ADR-064),
  `release_coverage` (per-release advisory coverage window, migration 0036, ADR-067),
  `kev`/`epss` (the CISA KEV and FIRST EPSS risk feeds that prioritise findings, migration 0037,
  ADR-069) and `attack_techniques`/`cve_techniques`/`rule_techniques` (the MITRE ATT&CK
  catalogue and its two mapping anchors, migration 0050/0051, ADR-105) are global knowledge
  tables and correctly carry no `tenant_id`. `cvap_app` holds `SELECT` on all of them. The
  eleven advisory-knowledge tables (`VULNERABILITY_DEF` through `cve_techniques`) are written
  only by `cvap_knowledge_import` (ADR-063 — `kev`/`epss` are its 8th and 9th, ADR-069;
  `attack_techniques`/`cve_techniques` its 10th and 11th, ADR-105). `rule_techniques` is the
  exception: it is CURATED content on the rule-pack path, migration-seeded like `rules`, so the
  import role holds only `SELECT` on it — and it needs that one grant because the corpus
  importer VALIDATES against it, refusing a corpus that lacks any curated technique.
  `RULE_PACK` and `RULE` are detection content on the separate rule-pack path
  (ADR-030's "separate identity", migration-seeded today), not by `cvap_knowledge_import`.
- Observations are ephemeral. **Anything that must outlive them is copied at the moment it
  becomes load-bearing** (ADR-016): merge evidence into `asset_identity_keys`, finding and
  verdict payloads into `evidence`, and — the fourth instance, added by ADR-103 — an OPEN PORT
  into `services`. ADR-016's own text still enumerates three; it is frozen, so this is the copy
  that gets to be current. `evidence.observation_id` is a nullable soft reference, never a hard FK.
- `observations` is partitioned monthly; `evidence` is not partitioned — it is pruned by
  finding status, not by time.
- Large evidence goes to the object store; the row holds a summary and a pointer (ADR-015).

Nineteen tables in the schema are not drawn in the v2 ERD. They are required, and ADR-029
records why, so they do not read as inventions when you diff schema against diagram:
`result_submissions` (ADR-026's idempotency ledger — `observations.submission_id` has no FK
target without it), `asset_resolution_queue` (ADR-007's unresolved merge queue),
`enrollment_tokens` and `scan_point_certificates` (ADR-018), `kill_switches` and `kill_acks`
(ADR-024), `cancel_acks` (ADR-024's per-scan half, migration 0025), `tenant_auth_config`,
`user_credentials` and `sessions` (the operator API's authentication surface, migration 0026),
`oidc_auth_requests` (ADR-046's pre-auth state, migration 0027), the join tables
`scan_policy_credential_profiles` and `advisory_vuln_map`, `knowledge_feed_status`
(advisory-feed freshness, migration 0034 — recorded in ADR-063), `product_packages`
(the product→package map for release resolution, migration 0035 — recorded in ADR-064),
`release_coverage` (per-release advisory coverage window, migration 0036 — the sixteenth,
recorded in ADR-067), and `kev`/`epss` (the CISA KEV and FIRST EPSS risk feeds, migration 0037 —
the seventeenth and eighteenth, recorded in ADR-069), and `asset_identity_key_sightings` (distinct
scans that saw an identity key at an address — the ADR-091 observed trust root's count, migration
0044 — the nineteenth, recorded in ADR-094).

That list is ADR-029's to hold, not this file's — a tenth table belongs in the ADR, and this
paragraph should be updated from it rather than the other way round. It said "four" for two
sessions after the ADR said eight. The fourteenth (`knowledge_feed_status`) trips ADR-029's own
review trigger: the annotation approach has stopped scaling, and the fix is to redraw the ERD
with these absorbed rather than to extend this list further (backlog B27).

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

`Read`, `Write`, `ReadWithin` and `WriteWithin` are the only doors, and a `TenantID` is what opens
them. There is no `Acquire`, no `Begin`, no exported accessor for the pool or a connection.

**Every transaction carries a time budget (ADR-101).** `Read`/`Write` take `OperatorBudget` (30 s);
`ReadWithin`/`WriteWithin` take the caller's, and a zero or negative budget is REFUSED rather than
treated as unbounded. The budget is applied TWICE, and neither is redundant: a context deadline,
which bounds the whole transaction and is the bound that actually holds, and `SET LOCAL
statement_timeout`, which bounds each STATEMENT. `statement_timeout` alone bounds nothing over a
callback — measured: three `pg_sleep(0.8)` statements in one transaction under a 1 s
`statement_timeout` all completed, 2.4 s, none cancelled, because the setting resets per statement.
Exceeding either gives `ErrStatementTimeout`, which the API maps to 504.

- **`SET LOCAL` inside a transaction, always** — now TWO of them, `app.tenant_id` and
  `statement_timeout`, both set with `set_config(..., true)` and both VERIFIED on the round trip
  that sets them (the timeout compares as an `interval`, because `set_config` normalises `30000` to
  `30s`). A session `SET` would have to be undone by
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
so they would need one — and an escape hatch with no caller is how escape hatches get misused.
The finding read path (session 18) DOES now read `rules`, but it needed no such primitive: the
join `findings f JOIN rules r ON r.rule_id = f.rule_id` runs inside a tenant-scoped `Read`
transaction on `findings`, and `rules` is a global no-RLS table `cvap_app` may `SELECT`
(migration 0010's grant). A global table read from inside a tenant transaction is not an
unscoped read of tenant data — it is the case ADR-030 anticipated. A future need to read a
knowledge table with *no* finding to anchor the join to is the one that would still have to make
the case, the way ADR-036 made it for the sweep.

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

## `services` means "a port we have seen", not "a service we identified"

Since ADR-103, a row in `services` may be either. A discovery scan's open port is promoted to a
row carrying `port`, `protocol` and `identification_method = 'discovery'` with every
identification column empty; a fingerprint pass later upgrades that same row in place.
`Service.Identified()` is the predicate — ask it rather than assuming a row means an
identification.

**Seen-only rows are deliberately invisible to the rule engine** (ADR-103 decision 2), and the
enforcement is one line: `serviceObservations` in `internal/correlate/findings.go` filters
`o.Type != "service"`. Two things feed off that line, not one — the rules AND advisory matching
(`internal/correlate/advisories.go`). Anything that relaxes it opens both.

The measurement behind the decision: ports 2000 and 5060 answered on 19 of 19 hosts of a real
/24 pair — one middlebox replying for the range. Those rows are durable now; the filter is what
keeps them from becoming nineteen findings.

## An ATT&CK technique is an inference, and the type says so

`Techniques.ForFindings` returns techniques for a BATCH of findings, never one at a time: the
finding list is what it feeds, and a per-row lookup there would be one query per listed finding
inside a transaction that already carries a time budget (ADR-101).

A finding with no techniques is **absent from the returned map**, and the caller renders
"unmapped". That is not the same claim as "no technique applies" (ADR-105 decision 4), and the
API carries a coverage statement precisely so a client cannot collapse the two. There is a third
state that looks identical from a finding and is not: **no catalogue has been ingested at all**,
in which case nothing anywhere can be mapped. `CatalogueStatus` exists only to separate those —
without it, forgetting `make knowledge-attack` reads exactly like full coverage of an estate with
no techniques.

`Technique.Anchor` says which route reached the finding and the two are not interchangeable:
`rule` is a judgement a person made about that specific detection rule and carries a rationale;
`cve` is a third party's judgement about the CVE and carries that source's own qualifier.
`Confidence` stays nil unless the SOURCE published one — no ingested source currently does, and
ADR-105 forbids inventing a number here.

**Deprecated techniques are returned, never filtered.** A finding that cited a technique must
still be able to explain itself after that technique leaves the corpus, so the retirement is a
flag rather than a deletion, and a read path that hid them would silently strip an old finding's
only reason.

**Techniques are NOT an input to `priority_score`** (ADR-105 decision 5). KEV is observed
exploitation and EPSS a measured probability; adding an inference to that sum would launder a
guess into a number and double-count the same weakness.

## A failed service write loses the HOST, not just the service

`deriveServices` runs inside `resolveHost`'s transaction, which is ADR-006 working as designed —
resolveHost is one decision and a half-resolved host is the state it exists to prevent. The
consequence is not obvious from reading `deriveServices`: a row the database refuses rolls the
whole resolution back, so the asset is never written, its observations stay unresolved, and they
fail again on every later sweep. A poison pill visible only as a log line.

Measured twice: an `identification_method` outside the CHECK gave `assets=0` (ADR-104), and so
did one port observation carrying `"safety_mode":"bogus"`. **Anything written into `services`
from a wire payload must be narrowed against the column's constraint first**, and any future
CHECK added to `services` is a change to the failure mode of host resolution.

## A refusal must not roll back its own record

**If a closure passed to `Write` records that a refusal happened, it must not then return an
error.** The error aborts the transaction, and the record goes with it.

This has now been found three times, twice in shipped code, and every time it read as correct in
review — the control is right there in the function:

```go
err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
    if !ok {
        RecordFailure(ctx, c, userID)   // the control
        return errRefused               // ← throws it away
    }
    ...
})
```

**The shape to write instead**: return `nil`, and carry the refusal out in a captured variable.
Only a genuine FAULT — a database error, a broken constraint — returns an error, because only a
fault wants the transaction undone.

**That shape is NECESSARY AND NOT SUFFICIENT, since ADR-101.** A transaction can now be ended by
its own time budget, and when it is, the refusal record rolls back whether or not the closure
returned nil — measured: an `INSERT` committed earlier in a transaction that then times out leaves
0 rows. So a fourth way to lose the record exists, and returning nil does not close it.

Two rules follow, and the second is the one people get wrong:

1. **Check the transaction error BEFORE the refusal variable.** `if err != nil` first, then
   `if denied != nil`. A refusal that was not recorded must never be reported as though it was.
2. **A timeout is not the same as "nothing happened".** "A transaction that times out commits
   nothing" is FALSE and was measured to be false: sweeping the deadline across the COMMIT round
   trip, **42 of 400 trials committed durably while the call returned `ErrStatementTimeout`**
   (the error reads `store: commit: ... context deadline exceeded`). Zero trials went the other
   way — a write never returned nil and was lost — so the dangerous direction is still
   unreachable, but code that treats a timeout as proof the write did not land is wrong. Where
   that matters, ask the database.

The durable answer for a refusal that MUST leave a record is the one `identity.refused` already
uses (ADR-100): write it in its OWN transaction, so the decision's fate and the record's fate are
separate. Login, `changePassword` and the OIDC state consume have not been moved yet.

```go
var denied error
err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
    if !ok {
        denied = errRefused
        return RecordFailure(ctx, c, userID)   // its own error still aborts, correctly
    }
    ...
})
if err != nil { /* fault */ }
if denied != nil { /* refusal, and it was recorded */ }
```

### The three instances

1. **The local-auth lockout counter** (`internal/control/api/handlers_auth.go`). `RecordFailure`
   followed by `return errWrongPassword`. `failed_attempts` was still 0 after fifteen wrong
   passwords: the lockout existed in the schema, in this package and in the handler, and engaged
   never. Found by a security-review probe, not by review — every test checked the response, and
   the response is identical either way.
2. **The OIDC browser-binding check** (`internal/control/api/oidc.go`). The binding is compared
   inside the transaction that consumed the single-use state with `DELETE ... RETURNING`;
   returning an error on mismatch un-deleted it, so a wrong binding left the state redeemable and
   a second callback with the right cookie succeeded. Found by its own regression test, written
   because instance 1 had happened.
3. **Ingest's ledger conflict** (`internal/dispatch/ingest.go`) is the same hazard arriving from
   the other direction, and it is here because the answer is different. A unique violation aborts
   the transaction *whatever the code does* — there is no "return nil" available. So the work
   moves: `errConflictResume` travels out as a sentinel and `resume` asks the question again in a
   **fresh** transaction. When the abort is unavoidable, the record cannot be written in that
   transaction at all, and pretending otherwise is instance 1 with extra steps.

### Why there is no checker for this

Attempted, measured, rejected. An AST pass over the tree flagging "a recording call inside a
`Write` closure with a non-nil return after it" produced **9 findings and 0 true positives**, on a
tree where all three instances were already fixed. Excluding each recording call's own
`if err != nil { return err }` guard took it from 17 to 9; the rest are returns in sibling
branches, which need path sensitivity rather than lexical position.

Path sensitivity would not fix it either, because the discriminating fact is **not syntactic**:
`return err` where `err` is a database fault is correct and must roll back, and
`return errWrongPassword` is a refusal and must not. A checker cannot tell those apart, and one
that guessed would fire on every correct handler in the package. Documented with three worked
examples in preference to a checker that produces noise — a gate that fires on correct code is
one people learn to skip, which is the same failure as a gate that silently passes.

`security-reviewer` is prompted to look for this shape by hand.

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
