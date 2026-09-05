-- Provisions the LOGIN role cvap-core connects as, for a production single-node
-- deployment. Run AFTER migrations: migration 0001 creates the cvap_app group
-- role and the per-table grants, and this file only adds a login member of it.
--
-- The password is a psql variable, not a literal, so it is not committed: the
-- compose passes it with -v app_password="$APP_ROLE_PASSWORD". This is the
-- production counterpart of internal/store/testdata/app_role.sql, which hardcodes
-- the throwaway dev password on purpose (it matches .env); a real password does
-- not belong in a file under version control, which is why it arrives as a
-- variable here.
--
-- cvap_app is NOLOGIN and has no password to leak or rotate; what connects is a
-- login role that inherits its grants. BYPASSRLS and SUPERUSER are NOT inherited
-- through membership, so the login role is checked in its own right at the end —
-- inheriting the grants does not inherit the safety (ADR-002).

\set ON_ERROR_STOP on

SELECT 'provisioning cvap_app_login' AS step;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cvap_app') THEN
        RAISE EXCEPTION
            'Role cvap_app does not exist. Run migrations first: it is created by migration 0001 (ADR-002).';
    END IF;
END
$$;

-- Password from the -v variable. CREATE ... PASSWORD takes a string literal, so
-- the value is quoted with :'...', which psql escapes.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cvap_app_login') THEN
        EXECUTE format(
            'CREATE ROLE cvap_app_login LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L',
            :'app_password');
    ELSE
        EXECUTE format(
            'ALTER ROLE cvap_app_login LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD %L',
            :'app_password');
    END IF;
END
$$;

GRANT cvap_app TO cvap_app_login;
GRANT CONNECT ON DATABASE cvap TO cvap_app_login;
GRANT USAGE ON SCHEMA public TO cvap_app_login;

-- The safety assertion, in the login role's own right.
DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper, rolinherit INTO r
      FROM pg_roles WHERE rolname = 'cvap_app_login';

    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION
            'cvap_app_login holds BYPASSRLS or SUPERUSER. Every RLS policy in the schema would be inert (ADR-002).';
    END IF;
    IF NOT r.rolinherit THEN
        RAISE EXCEPTION
            'cvap_app_login does not inherit, so it gets none of cvap_app''s table grants.';
    END IF;
    RAISE NOTICE 'cvap_app_login ready: inherits cvap_app, holds neither BYPASSRLS nor SUPERUSER';
END
$$;
