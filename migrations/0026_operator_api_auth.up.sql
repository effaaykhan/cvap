-- 0026_operator_api_auth
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.
--
-- The operator API's authentication surface: how a request names a tenant
-- before it is authenticated, how a browser session is represented, and where a
-- local password lives when there is no identity provider to delegate to.

BEGIN;

DO $$
DECLARE
    r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls THEN
        RAISE EXCEPTION 'Role cvap_app holds BYPASSRLS (ADR-002). Fix: ALTER ROLE cvap_app NOBYPASSRLS;';
    END IF;
    IF r.rolsuper THEN
        RAISE EXCEPTION 'Role cvap_app is a superuser, which bypasses RLS unconditionally (ADR-002). Fix: ALTER ROLE cvap_app NOSUPERUSER;';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- tenants.domain — the only thing an unauthenticated request carries
-- ---------------------------------------------------------------------------
-- ADR-041. A login request has a hostname, a form and nothing else. Email is
-- UNIQUE (tenant_id, lower(email)) rather than globally unique, deliberately
-- (0001), so there is no email -> tenant function to build and building one
-- would be a cross-tenant enumeration oracle in front of an unauthenticated
-- form. The host is what remains, and it is bounded by what the deployment's
-- DNS and TLS actually terminate rather than by what the request invented.

ALTER TABLE tenants ADD COLUMN domain text;

-- Backfill to a name that CANNOT resolve. .invalid is reserved by RFC 2606 for
-- exactly this, so an existing tenant does not silently acquire a working
-- hostname and does not accidentally answer for one that belongs to someone
-- else: the deployment fails closed until an operator sets a real domain.
UPDATE tenants SET domain = tenant_id::text || '.unset.invalid' WHERE domain IS NULL;

ALTER TABLE tenants ALTER COLUMN domain SET NOT NULL;

-- Stored lowercased and matched lowercased, because a hostname is
-- case-insensitive and a request can carry any casing it likes. Unlike email —
-- which is stored as entered because what the user typed ends up in outbound
-- mail — nothing renders this back to a human, so there is nothing to preserve.
ALTER TABLE tenants ADD CONSTRAINT tenants_domain_lowercase
    CHECK (domain = lower(domain));

-- No port, no scheme, no path, no trailing dot, no empty label. The resolution
-- function strips a port before it looks, so a domain WITH one would be
-- unreachable rather than merely odd — a row that can never match is worse than
-- a rejected insert, because it looks configured.
ALTER TABLE tenants ADD CONSTRAINT tenants_domain_is_a_hostname
    CHECK (domain ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$'
           AND length(domain) BETWEEN 1 AND 253);

-- Globally unique, not per tenant, for the same reason enrollment_tokens.token_hash
-- is: the lookup happens BEFORE the tenant is known, so two tenants sharing a
-- domain would make the pre-tenant resolution ambiguous — the exact hazard
-- ADR-041 closes by requiring one unambiguous row.
CREATE UNIQUE INDEX tenants_domain_key ON tenants (domain);

COMMENT ON COLUMN tenants.domain IS
    'The hostname this tenant is reached at, lowercased. Resolved to a tenant by tenant_for_domain() before any handler runs (ADR-041). Every deployment sets one, on-prem included, where it is typically localhost: a single-tenant code path that skips resolution is the branch ADR-017 exists to prevent.';

-- ---------------------------------------------------------------------------
-- tenant_auth_config — how this tenant's users authenticate
-- ---------------------------------------------------------------------------

CREATE TYPE auth_method AS ENUM ('oidc', 'local');

CREATE TABLE tenant_auth_config (
    tenant_id             uuid PRIMARY KEY REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    method                auth_method NOT NULL,

    -- OIDC discovery is done from the issuer; nothing else is stored, and in
    -- particular no client secret.
    --
    -- The client is PUBLIC and uses authorization code + PKCE. That is not a
    -- simplification: a confidential client means a per-tenant secret sitting
    -- in a table that a backup, a read replica or one SQL injection yields, and
    -- the protection PKCE gives against code interception does not depend on
    -- one. The cost is that an IdP requiring a confidential client cannot be
    -- used until there is somewhere real to keep the secret, which is the same
    -- key-custody problem ADR-026's encrypted buffer is deferred on.
    oidc_issuer           text,
    oidc_client_id        text,

    -- Which claim carries the address matched against users.email. Configurable
    -- because IdPs disagree, defaulted because most do not.
    oidc_email_claim      text NOT NULL DEFAULT 'email',

    -- An OIDC user who authenticates but has no users row is REFUSED, not
    -- created, unless this is set. Auto-provisioning from an assertion means the
    -- IdP decides who has an account here; a tenant that wants that says so.
    oidc_auto_provision   boolean NOT NULL DEFAULT false,

    -- The role an auto-provisioned user receives. Never inferred from a claim:
    -- a role that comes from the assertion lets the IdP grant permissions in
    -- this system (ADR-002).
    oidc_default_role_id  uuid,

    updated_at            timestamptz NOT NULL DEFAULT now(),
    updated_by            uuid,

    CONSTRAINT tenant_auth_config_default_role_fk
        FOREIGN KEY (tenant_id, oidc_default_role_id)
        REFERENCES roles (tenant_id, role_id) ON DELETE RESTRICT,

    CONSTRAINT tenant_auth_config_updated_by_fk
        FOREIGN KEY (tenant_id, updated_by)
        REFERENCES users (tenant_id, user_id) ON DELETE SET NULL (updated_by),

    -- The columns are only meaningful for one method, and a half-configured
    -- OIDC tenant is a tenant whose login fails at runtime in a handler rather
    -- than here.
    CONSTRAINT tenant_auth_config_oidc_complete CHECK (
        method <> 'oidc'
        OR (oidc_issuer IS NOT NULL AND oidc_client_id IS NOT NULL
            AND oidc_issuer <> '' AND oidc_client_id <> '')
    ),

    CONSTRAINT tenant_auth_config_issuer_is_https CHECK (
        oidc_issuer IS NULL OR oidc_issuer LIKE 'https://%'
    ),

    CONSTRAINT tenant_auth_config_auto_provision_needs_a_role CHECK (
        NOT oidc_auto_provision OR oidc_default_role_id IS NOT NULL
    )
);

COMMENT ON TABLE tenant_auth_config IS
    'Per-tenant authentication method. method = local is additionally gated by a Core-wide flag and by deployment_mode = onprem; this table cannot enable it on its own (ADR-041, ADR-002).';

COMMENT ON COLUMN tenant_auth_config.method IS
    'A tenant admin setting this to local does NOT enable local authentication. Core refuses local login unless CVAP_CORE_LOCAL_AUTH is set on the DEPLOYMENT and the tenant is onprem. The flag is Core-wide rather than per tenant precisely so that an admin of one tenant cannot turn password authentication on for their own users and thereby opt out of the deployment operator SSO policy.';

ALTER TABLE tenant_auth_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_auth_config FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_auth_config_tenant_isolation ON tenant_auth_config
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- user_credentials — local passwords, on-prem only
-- ---------------------------------------------------------------------------

CREATE TABLE user_credentials (
    user_id        uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    -- The full PHC-format argon2id string, parameters included, so a cost
    -- increase does not invalidate existing hashes and a verify can tell
    -- whether the stored hash needs rewriting.
    --
    -- argon2id here rather than the plain SHA-256 that enrollment_tokens uses,
    -- and the difference is the entropy of the input: a token is 256 bits from
    -- crypto/rand and has nothing to brute-force, while a password is whatever
    -- a human chose.
    password_hash  text NOT NULL,

    updated_at     timestamptz NOT NULL DEFAULT now(),

    -- Set when an operator sets an initial or reset password. The session is
    -- issued but every endpoint except the password change refuses it.
    must_change    boolean NOT NULL DEFAULT false,

    -- Consecutive failures and the lockout that follows. Counted in the
    -- database rather than in process memory because Core is not the only
    -- process that will ever serve this, and a counter that resets on deploy is
    -- not a lockout.
    failed_attempts   integer NOT NULL DEFAULT 0,
    locked_until      timestamptz,

    CONSTRAINT user_credentials_tenant_user_key UNIQUE (tenant_id, user_id),

    CONSTRAINT user_credentials_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

    CONSTRAINT user_credentials_hash_is_argon2id CHECK (password_hash LIKE '$argon2id$%'),
    CONSTRAINT user_credentials_failed_attempts_sane CHECK (failed_attempts >= 0)
);

COMMENT ON TABLE user_credentials IS
    'Local password verifiers, argon2id in PHC format. A row here is not sufficient to log in: Core requires the deployment-wide local-auth flag and an onprem tenant as well.';

ALTER TABLE user_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY user_credentials_tenant_isolation ON user_credentials
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- sessions
-- ---------------------------------------------------------------------------

CREATE TABLE sessions (
    session_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    user_id        uuid NOT NULL,

    -- SHA-256 of the session token, never the token. Same argument as
    -- enrollment_tokens.token_hash and the same reason a slow KDF would buy
    -- nothing: the token is 256 bits from crypto/rand.
    token_hash     bytea NOT NULL,

    -- SHA-256 of the CSRF token, which is a SECOND random value bound to this
    -- session and returned in a readable cookie for the browser to echo in a
    -- header. Hashed for the same reason the session token is: a database read
    -- must not yield anything usable.
    csrf_hash      bytea NOT NULL,

    issued_at      timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    last_seen_at   timestamptz NOT NULL DEFAULT now(),

    -- Set on logout, on password change, and on an administrative revocation.
    -- The row is kept: who was signed in from where is audit material, and
    -- deleting it on logout erases exactly the sessions an investigation cares
    -- about.
    revoked_at     timestamptz,
    revoked_reason text,

    -- Recorded for the audit trail, never for authorisation. A session is not
    -- bound to an address: mobile clients change networks constantly and an
    -- address check produces support tickets rather than security.
    created_ip     inet,
    user_agent     text,

    CONSTRAINT sessions_tenant_session_key UNIQUE (tenant_id, session_id),

    CONSTRAINT sessions_user_fk FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, user_id) ON DELETE CASCADE,

    CONSTRAINT sessions_expiry_after_issue CHECK (expires_at > issued_at),

    -- Twelve hours, enforced here and not only in Go. An absolute cap rather
    -- than an idle timeout: a sliding expiry that renews on activity is a
    -- session that never ends for an active attacker.
    CONSTRAINT sessions_lifetime_cap CHECK (expires_at <= issued_at + interval '12 hours')
);

COMMENT ON TABLE sessions IS
    'Operator API sessions. Stores SHA-256 of the session and CSRF tokens, never the tokens. Rows survive logout so that the audit trail does.';

-- Per tenant rather than global, because unlike an enrollment token a session
-- is never looked up before the tenant is known: tenant_for_domain runs first
-- and the session is then read inside that tenant's scope.
CREATE UNIQUE INDEX sessions_tenant_token_key ON sessions (tenant_id, token_hash);

CREATE INDEX sessions_active_idx ON sessions (tenant_id, user_id, expires_at)
    WHERE revoked_at IS NULL;

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
CREATE POLICY sessions_tenant_isolation ON sessions
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- tenant_for_domain — third member of the ADR-041 class
-- ---------------------------------------------------------------------------
-- Same shape as tenant_for_scan_point (0015) and tenant_for_enrollment_token
-- (0017), deliberately identical: one input, RETURNS uuid, STABLE, pinned
-- search_path, the validity filter in SQL, NULL rather than RAISE, owned by the
-- migration role. ADR-041 defines the class and closes it at three; a fourth
-- member amends that ADR rather than adding a function here.
--
-- The validity filter is the tenant's own status, so a suspended or closed
-- tenant resolves to NULL and its users cannot log in — the SAME NULL an
-- unknown hostname produces, which is what stops the endpoint confirming that a
-- tenant exists at a given hostname.
--
-- Lowercasing is done HERE rather than only in the caller. A caller that forgot
-- would get NULL for a correctly configured deployment, which presents as a
-- broken deployment rather than as a bug, and someone would eventually fix it
-- by relaxing the comparison.

CREATE FUNCTION tenant_for_domain(host text)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT t.tenant_id
    FROM public.tenants t
    WHERE t.domain = lower(tenant_for_domain.host)
      AND t.status = 'active'
$$;

COMMENT ON FUNCTION tenant_for_domain(text) IS
    'ADR-041 pre-tenant resolution. Resolves a request hostname to its tenant so the API middleware can set app.tenant_id before any handler runs. Returns exactly one uuid, or NULL for unknown, suspended or closed — indistinguishable by design. MUST NOT be widened to return the tenant row: the name and status of a tenant are not things an unauthenticated request may learn.';

REVOKE ALL ON FUNCTION tenant_for_domain(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_for_domain(text) TO cvap_app;

DO $$
DECLARE
    owner_name text;
BEGIN
    SELECT pg_get_userbyid(p.proowner) INTO owner_name
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.proname = 'tenant_for_domain' AND n.nspname = 'public';

    IF owner_name = 'cvap_app' THEN
        RAISE EXCEPTION
            'tenant_for_domain is owned by cvap_app, which can therefore CREATE OR REPLACE its body and run arbitrary SQL as the definer (ADR-041).';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = owner_name AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION
            'tenant_for_domain is owned by % which holds neither BYPASSRLS nor SUPERUSER. tenants is FORCE ROW LEVEL SECURITY, so the definer cannot read it and every request would raise instead of returning NULL (ADR-041).',
            owner_name;
    END IF;
END
$$;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_auth_config TO cvap_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_credentials TO cvap_app;
GRANT SELECT, INSERT, UPDATE ON sessions TO cvap_app;

COMMIT;
