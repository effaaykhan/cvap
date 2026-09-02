-- Down migration for 0001_tenancy_foundation

BEGIN;

REVOKE ALL ON tenants, roles, users FROM cvap_app;

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS tenants;

DROP TYPE IF EXISTS user_status;
DROP TYPE IF EXISTS tenant_status;
DROP TYPE IF EXISTS deployment_mode;

-- Drop the role only if this migration created it. The comment set at creation
-- is the marker: a role provisioning owns has no such comment, and dropping it
-- would leave the cluster without an application role that a re-migration
-- cannot recreate without privileges it may not have.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_roles r
        WHERE r.rolname = 'cvap_app'
          AND shobj_description(r.oid, 'pg_authid') LIKE 'CVAP application role. Created by migration 0001.%'
    ) THEN
        DROP ROLE cvap_app;
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'Leaving role cvap_app in place: insufficient privilege to drop it.';
    WHEN dependent_objects_still_exist THEN
        -- A role is CLUSTER-wide; this migration is per-database. Another
        -- database in the same cluster still grants to cvap_app, so dropping it
        -- here would be reaching outside this database to break that one.
        --
        -- This is not hypothetical: make migrate-verify runs up / down -all / up
        -- against a throwaway database precisely so it stops being destructive
        -- to the dev one, and the dev database's grants are what land here. The
        -- re-apply that follows recreates nothing, because the role was never
        -- removed and 0001 creates it idempotently.
        --
        -- Two costs, both stated rather than discovered later.
        --
        -- First: this cannot tell "another database depends on it" from "a
        -- future down migration in THIS database forgot a REVOKE". Postgres
        -- reports the dependent database only as free text in DETAIL, with no
        -- structured field to test. It is safe today because every GRANT to
        -- cvap_app across 0001-0023 is paired with a REVOKE and an object drop
        -- in the same down migration, so nothing but a genuinely external
        -- dependent can reach here. A migration that grants something no DROP
        -- tears down -- GRANT USAGE ON SCHEMA, ALTER DEFAULT PRIVILEGES, a
        -- schema-owned sequence -- must pair it with a REVOKE, because this
        -- handler would swallow the omission and the re-apply would not raise
        -- the duplicate-object error that catches a missed DROP TABLE.
        --
        -- Second: on a dev database that has ever run migrate-up, this branch
        -- now fires on EVERY local verify, so the CREATE ROLE path stops being
        -- exercised locally. CI still exercises it fully -- its Postgres service
        -- is a fresh cluster and migrate-verify runs before migrate-up, so no
        -- grants exist when down -all reaches here and the role is genuinely
        -- dropped and recreated. The unconditional property assertion in the up
        -- migration is NOT weakened either way: it re-runs on every up, so a
        -- role that acquired BYPASSRLS externally still fails the deploy.
        RAISE NOTICE 'Leaving role cvap_app in place: another database in this cluster still depends on it.';
END
$$;

COMMIT;
