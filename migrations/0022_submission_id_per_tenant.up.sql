-- 0022_submission_id_per_tenant
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- submission_id is unique PER TENANT, not globally.
--
-- ============================================================================
-- A global unique on an attacker-chosen value is a cross-tenant oracle.
-- ============================================================================
--
-- Migration 0008 made submission_id the primary key on its own, while also
-- declaring UNIQUE (tenant_id, submission_id) — which is what observations'
-- composite FK targets, and which shows the intent was per-tenant all along.
--
-- The value comes from the wire. A security review proved the consequence:
-- tenant B submitting a submission_id first used by tenant A gets a unique
-- violation on the global key, which mapError turns into ErrConflict and ingest
-- answers REJECTED_DUPLICATE — telling B to clear a buffer whose contents were
-- never stored. That is a result discarded, which ADR-026 says never happens,
-- and a blind existence oracle for another tenant's submission ids.
--
-- The composite unique already exists and already carries the FK, so promoting
-- it to the primary key is the whole change.

BEGIN;

DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION 'Role cvap_app can bypass RLS (ADR-002). Fix: ALTER ROLE cvap_app NOBYPASSRLS NOSUPERUSER;';
    END IF;
END
$$;

-- The composite unique is what observations' FK references, so it cannot simply
-- be promoted in place: the FK is a dependency and Postgres refuses the drop.
-- Drop the FK, restructure, put the FK back pointing at the new primary key.
--
-- observations is partitioned, so re-adding the FK revalidates every partition.
-- That is acceptable here and stated rather than discovered: this migration
-- should run before the table carries production volume, and a later variant
-- would need ADD CONSTRAINT ... NOT VALID followed by VALIDATE CONSTRAINT in a
-- separate transaction.
-- The volume assumption above was enforced by deployment sequencing and nothing
-- else, which is not how anything else in this schema states a precondition.
--
-- Re-adding the FK takes ACCESS EXCLUSIVE on result_submissions AND observations
-- — both on the hot ingest path — for the whole validation scan. On an empty
-- database that is instant, which is exactly why CI cannot catch it: make
-- migrate-verify proves the DDL, never the lock duration. Run late, this is a
-- full ingest outage, and it would be discovered as one.
--
-- reltuples rather than count(*): the estimate is free and a count on a
-- partitioned table with enough rows to matter is itself the problem.
DO $$
DECLARE est bigint;
BEGIN
    SELECT coalesce(sum(GREATEST(c.reltuples, 0)), 0)::bigint INTO est
      FROM pg_class c
      JOIN pg_inherits i ON i.inhrelid = c.oid
     WHERE i.inhparent = 'public.observations'::regclass;

    IF est > 1000000 THEN
        RAISE EXCEPTION 'observations holds roughly % rows; 0022 revalidates a foreign key across every partition under ACCESS EXCLUSIVE and would block ingest for the duration.', est
            USING HINT = 'Run the constraint swap as ADD CONSTRAINT ... NOT VALID followed by VALIDATE CONSTRAINT in a separate transaction, in a maintenance window. Do not raise this threshold to get past the check.';
    END IF;
END
$$;

ALTER TABLE observations DROP CONSTRAINT observations_submission_fk;

ALTER TABLE result_submissions DROP CONSTRAINT result_submissions_pkey;
ALTER TABLE result_submissions
    DROP CONSTRAINT result_submissions_tenant_submission_key;
ALTER TABLE result_submissions
    ADD CONSTRAINT result_submissions_pkey PRIMARY KEY (tenant_id, submission_id);

ALTER TABLE observations
    ADD CONSTRAINT observations_submission_fk FOREIGN KEY (tenant_id, submission_id)
        REFERENCES result_submissions (tenant_id, submission_id) ON DELETE CASCADE;

COMMENT ON COLUMN result_submissions.submission_id IS
    'Generated at the scan point, so ATTACKER-CHOSEN. Unique per tenant, never globally: a global unique lets one tenant collide with another''s id, which both discards results and answers a cross-tenant existence question (migration 0022).';

COMMIT;
