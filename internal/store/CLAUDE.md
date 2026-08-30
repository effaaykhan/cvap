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

Run `schema-auditor` on any migration.
