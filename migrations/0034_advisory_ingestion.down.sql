-- 0034_advisory_ingestion (down)

BEGIN;

REVOKE ALL ON knowledge_feed_status FROM cvap_app;
REVOKE ALL ON
    vulnerability_defs, vendor_advisories, advisory_vuln_map,
    advisory_fixed_packages, knowledge_feed_status
    FROM cvap_knowledge_import;

DROP TABLE IF EXISTS knowledge_feed_status;

-- Drop the role only if THIS migration created it, and tolerate the two ways a
-- drop legitimately cannot happen — the same shape 0001's down uses for
-- cvap_app, and for the same reason: a role is CLUSTER-wide while this migration
-- is per-database. The created-by marker is the COMMENT the up set.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles r
        WHERE r.rolname = 'cvap_knowledge_import'
          AND shobj_description(r.oid, 'pg_authid') LIKE 'Writes knowledge tables only%'
    ) THEN
        DROP ROLE cvap_knowledge_import;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Leaving role cvap_knowledge_import in place: insufficient privilege to drop it.';
    WHEN dependent_objects_still_exist THEN
        -- Another database in this cluster still grants to cvap_knowledge_import,
        -- so dropping it here would reach outside this database to break that one.
        -- `make migrate-verify` runs up / down -all / up against a THROWAWAY
        -- database precisely so it stops being destructive to the dev one, and
        -- the dev database's grants are what land here. The re-apply that follows
        -- recreates nothing, because the role was never removed and the up creates
        -- it idempotently (CREATE ROLE IF NOT EXISTS). Every GRANT to this role in
        -- the up is paired with a REVOKE above, so nothing but a genuinely external
        -- dependent reaches this branch. CI's Postgres is a fresh cluster, so there
        -- the role is genuinely dropped and recreated and the CREATE path is
        -- exercised fully; the up's NOBYPASSRLS/NOSUPERUSER assertion re-runs on
        -- every up regardless.
        RAISE NOTICE 'Leaving role cvap_knowledge_import in place: another database in this cluster still depends on it.';
END
$$;

COMMIT;
