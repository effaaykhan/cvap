---
name: write-migration
description: Procedure for writing a CVAP database migration. Use when adding or altering a table, index, or RLS policy.
paths:
  - migrations/**
  - internal/store/**
allowed-tools: Bash(make migrate-*) Bash(psql *)
---

# Writing a CVAP migration

## Steps

1. `make migrate-new NAME=<snake_case>` to scaffold the numbered pair.
2. Write the `up`. Write the `down` in the same sitting — a down written later is a down that is wrong.
3. Apply to a scratch database, then apply the down, then the up again. All three must succeed.
4. Run the `schema-auditor` subagent before considering it done.

## Required in the same file as the table

Not a follow-up migration. The same file.

- `tenant_id uuid NOT NULL REFERENCES tenants(tenant_id)` on every tenant-scoped table.
- `ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;`
- `CREATE POLICY <t>_tenant_isolation ON <t> USING (tenant_id = current_setting('app.tenant_id')::uuid);`
- `ALTER TABLE <t> FORCE ROW LEVEL SECURITY;` so the owner is covered too.

## Partitioning

`observations` and `evidence` are `PARTITION BY RANGE (observed_at)` from creation, with
monthly partitions and a default partition. Retrofitting onto a populated table means
downtime, so there is no second chance.

## Model rules

- Time-varying facts get `valid_from` / `valid_to`, not a bare current-state column. This
  covers `asset_addresses` and `asset_identity_keys`.
- No `zone` on `assets`.
- `findings.rule_id` NOT NULL. `findings.vuln_def_id` nullable.
- Exposure lives in `finding_exposure`, one row per zone, not columns on `findings`.
- Enums as Postgres enum types or CHECK constraints, not free text.
- Explicit `ON DELETE` on every foreign key.

## Indexes

Add them for the queries that exist, not speculatively. The ones that always earn their keep:
`(tenant_id, last_seen DESC)` on assets and findings, a unique index on `findings.dedup_key`,
and `(task_id, observed_at)` on observations for ingest.
