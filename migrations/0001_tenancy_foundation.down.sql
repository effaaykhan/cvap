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
END
$$;

COMMIT;
