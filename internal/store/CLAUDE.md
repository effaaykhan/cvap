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

Four tables in the schema are not drawn in the v2 ERD. They are required, and ADR-029
records why, so they do not read as inventions when you diff schema against diagram:
`result_submissions` (ADR-026's idempotency ledger — `observations.submission_id` has no FK
target without it), `asset_resolution_queue` (ADR-007's unresolved merge queue), and the
join tables `scan_policy_credential_profiles` and `advisory_vuln_map`.

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

Run `schema-auditor` on any migration.
