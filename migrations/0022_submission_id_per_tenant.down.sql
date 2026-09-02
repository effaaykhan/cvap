-- Down migration for 0022_submission_id_per_tenant
--
-- ============================================================================
-- This rollback stops being possible the moment the migration starts working.
-- ============================================================================
--
-- 0022 exists so two tenants may use the same submission_id, because the value
-- is attacker-chosen and a global unique on it was the vulnerability. A
-- collision post-0022 is therefore the ANTICIPATED case, not an edge one — and
-- restoring the single-column primary key below fails against it.
--
-- Left bare, that failure is a raw unique_violation partway through a rollback,
-- naming one duplicated id and nothing about what to do. The check runs first so
-- the operator gets the real answer instead: this cannot be rolled back with the
-- data as it stands, and here is what is in the way.
--
-- 0020 makes the same kind of statement about the pending enum label. A down
-- migration that cannot honestly reverse should say so here, not discover it.

BEGIN;

DO $$
DECLARE collisions bigint;
BEGIN
    SELECT count(*) INTO collisions
      FROM (SELECT submission_id
              FROM result_submissions
             GROUP BY submission_id
            HAVING count(DISTINCT tenant_id) > 1) c;

    IF collisions > 0 THEN
        RAISE EXCEPTION 'Cannot roll back 0022: % submission_id value(s) are in use by more than one tenant.', collisions
            USING HINT = 'Restoring the global primary key would require deleting one tenant''s submissions, which ADR-026 forbids (results are always stored). Roll back only from a state with no cross-tenant collisions, or migrate the affected tenants to fresh submission ids first. Query: SELECT submission_id, array_agg(tenant_id) FROM result_submissions GROUP BY 1 HAVING count(DISTINCT tenant_id) > 1;';
    END IF;
END
$$;

ALTER TABLE observations DROP CONSTRAINT observations_submission_fk;

ALTER TABLE result_submissions DROP CONSTRAINT result_submissions_pkey;
ALTER TABLE result_submissions
    ADD CONSTRAINT result_submissions_tenant_submission_key
        UNIQUE (tenant_id, submission_id);
ALTER TABLE result_submissions
    ADD CONSTRAINT result_submissions_pkey PRIMARY KEY (submission_id);

ALTER TABLE observations
    ADD CONSTRAINT observations_submission_fk FOREIGN KEY (tenant_id, submission_id)
        REFERENCES result_submissions (tenant_id, submission_id) ON DELETE CASCADE;

COMMENT ON COLUMN result_submissions.submission_id IS NULL;

COMMIT;
