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
- `ALTER TABLE <t> FORCE ROW LEVEL SECURITY;` so the owner is covered too.
- The policy, with **both** `USING` and `WITH CHECK`:

```sql
CREATE POLICY <t>_tenant_isolation ON <t>
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
```

Two details in that policy are load-bearing, and both fail silently if you get them wrong.

**`WITH CHECK` is not optional.** `USING` governs reads only. A policy with `USING` alone
lets a tenant `INSERT` or `UPDATE` rows into another tenant's scope while being unable to
read them back — worse than a read leak, because nothing in the writing tenant's own view
ever shows it happened.

**Use the one-argument `current_setting`.** The two-argument form,
`current_setting('app.tenant_id', true)`, returns NULL when the setting is unset, which makes
the predicate NULL and returns an empty result. That reads as "no data" to a caller. The
one-argument form raises. A query with no tenant context must fail, not quietly return
nothing (ADR-002).

Both are checked by `schema-auditor` and by `internal/store/testdata/rls_test.sql`
(`make rls-test`), which proves all of this as `cvap_app` — the application role, which holds
neither `BYPASSRLS` nor `SUPERUSER`. Running those assertions as a migration role would pass
every case while proving nothing.

## Partitioning

`observations` is `PARTITION BY RANGE (observed_at)` from creation, with monthly partitions
and a default partition. Retrofitting onto a populated table means downtime, so there is no
second chance. Declare it in the creating migration, and remember the partition key must be
part of the primary key.

**`evidence` is NOT partitioned** (ADR-016, which supersedes architecture-v2 §9.1 and
execution-plan §4.3 — both of those still say it is). Do not add `PARTITION BY` to it. It is
pruned by finding status rather than by time: evidence on an open finding is retained as long
as the finding, and evidence on a closed finding drops 90 days after closure. There is
therefore no partition key that matches how the table is actually dropped, and partitioning by
capture time would buy a mechanism nobody uses while fixing the wrong key permanently.

The instinct to partition anything that might grow is why §9.1 said otherwise, and it is a
reasonable instinct — which is why this needs stating rather than assuming. ADR-016's review
trigger for that decision is Phase 4, with measured row counts, not an estimate.

`evidence.observation_id` is a **nullable soft reference with no foreign key**, for the same
reason: a hard FK would either block or fail the observation partition drop. The column is
expected to go null when its partition ages out, because the content was copied at finding
creation rather than referenced — which is the general rule that covers every such case:

> Observations are ephemeral. Anything that must outlive them is copied at the moment it
> becomes load-bearing.

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
