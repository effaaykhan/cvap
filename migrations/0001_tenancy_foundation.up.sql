-- 0001_tenancy_foundation
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Roots the whole schema. Everything tenant-scoped descends from tenants via a
-- composite FK chain, so this file also establishes the two mechanisms the rest
-- of the schema repeats: the application role that cannot bypass RLS (ADR-002)
-- and the (tenant_id, id) uniqueness that composite FKs target (ADR-017).

BEGIN;

-- ---------------------------------------------------------------------------
-- Application role
-- ---------------------------------------------------------------------------
-- ADR-002: application roles cannot bypass RLS; only migration roles do. That
-- is only true if nobody has granted BYPASSRLS to the application role, which
-- is a cluster-level property no schema object can hold. So we assert it.
--
-- Creation is best-effort, because managed Postgres often reserves role
-- creation for provisioning. The assertion below is not best-effort: it runs
-- whether this migration created the role or provisioning did, and it fails the
-- deploy rather than letting tenant isolation be silently lost.

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cvap_app') THEN
        CREATE ROLE cvap_app NOLOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;
        -- Recorded so the down migration knows it may drop the role. Dropping a
        -- role that provisioning owns is worse than leaving one behind.
        COMMENT ON ROLE cvap_app IS
            'CVAP application role. Created by migration 0001. Must never hold BYPASSRLS (ADR-002).';
    END IF;
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE EXCEPTION
            'Cannot create role cvap_app and it does not exist. Provisioning must create it before migrating: CREATE ROLE cvap_app NOLOGIN NOBYPASSRLS NOSUPERUSER; (ADR-002)';
END
$$;

-- Unconditional. This is the part that matters, and it is repeated as the first
-- statement of any later migration that changes cvap_app's grants, so the
-- property is re-checked over time rather than once at 0001.
DO $$
DECLARE
    r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist after creation attempt (ADR-002)';
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

-- ---------------------------------------------------------------------------
-- Enum types
-- ---------------------------------------------------------------------------
-- Native enums rather than free text (write-migration skill). Created in the
-- migration that first uses them, dropped in that migration's down.

CREATE TYPE deployment_mode AS ENUM ('saas', 'onprem');
CREATE TYPE tenant_status AS ENUM ('active', 'suspended', 'closed');
CREATE TYPE user_status AS ENUM ('invited', 'active', 'disabled');

-- ---------------------------------------------------------------------------
-- tenants
-- ---------------------------------------------------------------------------
-- On-prem is one row here, not a separate code path (ADR-017). deployment_mode
-- is the only mode switch in the system: no compile flag, no build variant.

CREATE TABLE tenants (
    tenant_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    deployment_mode deployment_mode NOT NULL,
    status          tenant_status NOT NULL DEFAULT 'active',
    created_at      timestamptz NOT NULL DEFAULT now()
);

COMMENT ON COLUMN tenants.deployment_mode IS
    'saas | onprem. ADR-017: on-prem is a deployment with one tenant row, not a fork.';

-- tenants is itself tenant-scoped: its PK is the tenant_id, so the standard
-- policy applies unchanged.
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;

-- The one-argument current_setting is deliberate. current_setting('x', true)
-- returns NULL when unset, which makes the predicate NULL and silently returns
-- nothing; the one-argument form raises. A query with no tenant context must
-- fail, not quietly return an empty set that reads as "no data" (ADR-002,
-- internal/store/CLAUDE.md).
--
-- WITH CHECK is not optional either. USING alone governs reads, so a policy
-- without it lets a tenant INSERT or UPDATE rows into another tenant's scope
-- while being unable to read them back.
CREATE POLICY tenants_tenant_isolation ON tenants
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- roles
-- ---------------------------------------------------------------------------

CREATE TABLE roles (
    role_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    name        text NOT NULL,
    permissions jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at  timestamptz NOT NULL DEFAULT now(),

    -- Composite FK target for children. Not a query index: this constraint is
    -- what lets users declare (tenant_id, role_id) REFERENCES roles, which is
    -- what makes the denormalised tenant_id on users safe. See the note on
    -- users.tenant_id below.
    CONSTRAINT roles_tenant_role_key UNIQUE (tenant_id, role_id),

    CONSTRAINT roles_name_per_tenant_key UNIQUE (tenant_id, name)
);

ALTER TABLE roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE roles FORCE ROW LEVEL SECURITY;
CREATE POLICY roles_tenant_isolation ON roles
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- users
-- ---------------------------------------------------------------------------

CREATE TABLE users (
    user_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised, and it reads as redundant because roles already implies a
    -- tenant. It is not redundant: Postgres RLS does not inherit scope through
    -- a foreign key, so a child table with no tenant_id of its own has no
    -- policy and is unprotected (ADR-017). The alternative — an RLS policy with
    -- an EXISTS subquery to the parent — was rejected because it re-evaluates
    -- per row and cannot be pushed into an index scan.
    --
    -- The composite FK below is what makes the denormalisation safe rather than
    -- merely fast: a user row in tenant A physically cannot reference a role in
    -- tenant B, because no such (tenant_id, role_id) pair exists in roles. The
    -- column and the constraint are one mechanism; neither is correct alone.
    tenant_id     uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    role_id       uuid NOT NULL,
    email         text NOT NULL,
    auth_provider text NOT NULL,
    status        user_status NOT NULL DEFAULT 'invited',
    created_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT users_tenant_user_key UNIQUE (tenant_id, user_id),

    CONSTRAINT users_role_fk FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles (tenant_id, role_id) ON DELETE RESTRICT
);

-- Per-tenant, not global. The ERD marks email "UK", but a global constraint
-- forecloses one person holding accounts at two tenants and turns signup into a
-- cross-tenant membership oracle.
--
-- Functional index on lower(email), not a plain column constraint, or
-- Alice@corp.com and alice@corp.com are two accounts. Email is stored as
-- entered and compared lowercased: normalising on write loses what the user
-- typed, which then shows up in outbound mail.
--
-- Consequence, recorded in internal/control/CLAUDE.md: tenant discovery is now
-- its own problem. Login resolves tenant first — subdomain, SSO issuer, or
-- explicit selection — then the user within it. Any "which tenant?" flow that
-- answers from an email address is the enumeration oracle this constraint
-- exists to avoid. It must ask, not tell.
CREATE UNIQUE INDEX users_tenant_email_key ON users (tenant_id, lower(email));

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
CREATE POLICY users_tenant_isolation ON users
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
-- Per-table in the migration that creates the table, never a blanket grant on
-- the schema. A future table then defaults to no access rather than inheriting
-- it, which is the right direction to fail.

GRANT SELECT, INSERT, UPDATE, DELETE ON tenants, roles, users TO cvap_app;

COMMIT;
