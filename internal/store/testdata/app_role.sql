-- Creates the LOGIN role the application connects as.
--
-- cvap_app is NOLOGIN, deliberately: it is a group role carrying the per-table
-- grants, and a group role has no password to leak, rotate, or commit. Nothing
-- connects as it. What connects is a login role that is a MEMBER of it, so the
-- grants are inherited and the credential is provisioning's concern rather than
-- a migration's.
--
-- That split is also why migration 0001 does not create this role: a password
-- does not belong in a migration, and every deployment mode (ADR-017 includes
-- air-gapped on-prem) sets its own.
--
-- This file is the DEVELOPMENT and CI instance of that provisioning step. The
-- password here is a throwaway matching .env.
--
-- Note what is asserted at the end. BYPASSRLS and SUPERUSER are role attributes
-- and are NOT inherited through membership, so the login role needs checking in
-- its own right — inheriting cvap_app's grants does not inherit its safety.

\set ON_ERROR_STOP on

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cvap_app_login') THEN
        CREATE ROLE cvap_app_login LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE
            PASSWORD 'cvap_dev_only_app_password';
    ELSE
        ALTER ROLE cvap_app_login LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE
            PASSWORD 'cvap_dev_only_app_password';
    END IF;
END
$$;

GRANT cvap_app TO cvap_app_login;

-- Connecting needs CONNECT on the database and USAGE on the schema; the
-- per-table grants come from cvap_app membership.
GRANT CONNECT ON DATABASE cvap TO cvap_app_login;
GRANT USAGE ON SCHEMA public TO cvap_app_login;

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

-- ---------------------------------------------------------------------------
-- cvap_knowledge_import_login: the DEV/CI login member of cvap_knowledge_import
-- (migration 0034, ADR-063), which the advisory ingestion importer connects as.
-- Separate from cvap_app_login on purpose: cvap_app must never gain write access
-- to knowledge tables (ADR-030), so the importer is a distinct identity, and its
-- BYPASSRLS/SUPERUSER are checked in their own right (attributes are not
-- inherited through membership).
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cvap_knowledge_import_login') THEN
        CREATE ROLE cvap_knowledge_import_login LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE
            PASSWORD 'cvap_dev_only_import_password';
    ELSE
        ALTER ROLE cvap_knowledge_import_login LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE
            PASSWORD 'cvap_dev_only_import_password';
    END IF;
END
$$;

GRANT cvap_knowledge_import TO cvap_knowledge_import_login;
GRANT CONNECT ON DATABASE cvap TO cvap_knowledge_import_login;
GRANT USAGE ON SCHEMA public TO cvap_knowledge_import_login;

DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper, rolinherit INTO r
      FROM pg_roles WHERE rolname = 'cvap_knowledge_import_login';
    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION 'cvap_knowledge_import_login holds BYPASSRLS or SUPERUSER (ADR-063).';
    END IF;
    IF NOT r.rolinherit THEN
        RAISE EXCEPTION 'cvap_knowledge_import_login does not inherit, so it gets none of cvap_knowledge_import''s grants.';
    END IF;
    RAISE NOTICE 'cvap_knowledge_import_login ready: inherits cvap_knowledge_import, writes only knowledge tables';
END
$$;
