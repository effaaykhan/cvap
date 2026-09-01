-- 0016_observations_resolve_grant
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Fixes a gap in 0009. That migration granted `SELECT, INSERT` on observations
-- and withheld UPDATE, reasoning that observations are immutable and pruned by
-- partition drop rather than row-by-row. That reasoning is right about content
-- and wrong about one column: `asset_id` is documented in the ERD as "nullable
-- until resolved", and correlation is what resolves it (ADR-006). With no
-- UPDATE grant at all, Core cannot attach an observation to the asset it
-- derived — the observation-first model does not work.
--
-- The fix is a COLUMN-level grant, not a table-level one. Correlation may set
-- asset_id and nothing else. In particular `ingest_state` stays unwritable
-- after INSERT, which is what keeps it a fact about how the row arrived rather
-- than mutable state — ADR-026 requires quarantined results to be withheld from
-- the finding pipeline, and a pipeline that could clear the flag it is filtered
-- by would be enforcing nothing. `payload`, `zone_id` and `observed_at` stay
-- unwritable for the same reason: an immutable record whose content can be
-- edited is not evidence.
--
-- Postgres has no column-level DELETE, and none is wanted: observations are
-- pruned by dropping a partition, which is a migration-role operation.

BEGIN;

-- Re-assert the role's properties, per the rule 0001 established: any migration
-- that changes cvap_app's grants re-checks that it still cannot bypass RLS.
DO $$
DECLARE
    r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls THEN
        RAISE EXCEPTION
            'Role cvap_app holds BYPASSRLS. Tenant isolation depends on it not having this (ADR-002). Fix: ALTER ROLE cvap_app NOBYPASSRLS;';
    END IF;
    IF r.rolsuper THEN
        RAISE EXCEPTION
            'Role cvap_app is a superuser, which bypasses RLS unconditionally (ADR-002). Fix: ALTER ROLE cvap_app NOSUPERUSER;';
    END IF;
END
$$;

GRANT UPDATE (asset_id) ON observations TO cvap_app;

COMMENT ON COLUMN observations.asset_id IS
    'Nullable until correlation resolves it (ADR-006). The ONLY updatable column on this table: migration 0016 grants UPDATE (asset_id) and nothing wider, so payload, zone_id, observed_at and ingest_state stay immutable after INSERT.';

COMMIT;
