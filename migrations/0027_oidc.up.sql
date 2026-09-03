-- 0027_oidc
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.
--
-- The authorization-code flow's server-side half: the per-request secrets that
-- must survive between the redirect out to the identity provider and the
-- callback back, and the column that binds an IdP subject to a user here.

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
-- users.oidc_subject — the IdP's identifier for this person
-- ---------------------------------------------------------------------------
-- The `sub` claim, not the email, is what identifies a returning user.
--
-- Email is the obvious key and it is the wrong one. It is mutable at the
-- identity provider, it is reassignable — an employee leaves, the address is
-- given to someone else — and at many providers it is self-asserted. A login
-- path keyed on it hands an account to whoever holds the address this week.
-- `sub` is required by OpenID Connect to be stable and never reassigned within
-- an issuer.
--
-- Email still has a job: linking an existing invited user to a subject on first
-- login. That link happens ONCE, requires email_verified from the IdP, and is
-- enforced by a conditional UPDATE — see internal/control/api/oidc.go.

ALTER TABLE users ADD COLUMN oidc_subject text;

COMMENT ON COLUMN users.oidc_subject IS
    'The OIDC `sub` claim from this tenant''s issuer. NULL until first login. Identity for a returning user; email is used only to link an invited account to a subject once, and only when the IdP asserts email_verified.';

-- Per tenant, like every other identifier here. Two tenants may federate with
-- the same identity provider — a managed service provider and its customer, or
-- two subsidiaries — and a global constraint would make the second one to link
-- a subject fail with a conflict naming a row it cannot see.
--
-- Partial, so the many NULLs of local-auth and invited users do not collide.
CREATE UNIQUE INDEX users_tenant_oidc_subject_key
    ON users (tenant_id, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

-- ---------------------------------------------------------------------------
-- oidc_auth_requests — the pre-auth state of one login attempt
-- ---------------------------------------------------------------------------

CREATE TABLE oidc_auth_requests (
    request_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    -- SHA-256 of the state parameter. The state is what the callback presents,
    -- so only its hash is stored — the same reasoning as sessions.token_hash and
    -- enrollment_tokens.token_hash, and for the same reason a slow KDF would buy
    -- nothing: it is 256 bits from crypto/rand.
    --
    -- ============================================================================
    -- The row is looked up WITHIN a tenant, which is what binds it to one.
    -- ============================================================================
    --
    -- A state minted at tenant A and presented at tenant B's callback resolves to
    -- tenant B by hostname first (ADR-041), and the lookup then runs under B's
    -- RLS policy and finds nothing. The callback cannot name its own tenant, so
    -- it cannot redeem another tenant's login attempt.
    state_hash     bytea NOT NULL,

    -- SHA-256 of the nonce. Compared against the `nonce` claim of the ID token,
    -- which is what stops a token minted for a different login attempt — or
    -- replayed from an earlier one — being accepted for this one.
    nonce_hash     bytea NOT NULL,

    -- The PKCE code verifier, in the clear, because it has to be SENT to the
    -- token endpoint and a hash cannot be.
    --
    -- That is a real and bounded exposure: for the lifetime of one login attempt
    -- a database read yields a value that, combined with an intercepted
    -- authorization code, completes an exchange. PKCE exists to protect the code
    -- in transit through the browser, and it still does that. The row is
    -- single-use, expires in minutes, and is deleted on consumption.
    code_verifier  text NOT NULL,

    -- Where the IdP was told to come back to, recorded so the token exchange
    -- sends the identical value — RFC 6749 requires it to match, and deriving it
    -- twice is how the two come to differ.
    redirect_uri   text NOT NULL,

    -- Where to send the browser after a successful login. A PATH, never a URL:
    -- an absolute value here is an open redirect, and an open redirect on a
    -- login callback is a phishing primitive that borrows this deployment's
    -- hostname.
    return_path    text NOT NULL DEFAULT '/',

    created_at     timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,

    CONSTRAINT oidc_auth_requests_tenant_request_key UNIQUE (tenant_id, request_id),

    CONSTRAINT oidc_auth_requests_expiry_after_creation CHECK (expires_at > created_at),

    -- Ten minutes. A login attempt is a person clicking through an IdP, not a
    -- background job; anything longer is a widened window in which an
    -- intercepted state is still redeemable.
    CONSTRAINT oidc_auth_requests_ttl_cap
        CHECK (expires_at <= created_at + interval '10 minutes'),

    CONSTRAINT oidc_auth_requests_return_path_is_a_path
        CHECK (return_path ~ '^/[^/\\]' OR return_path = '/')
);

COMMENT ON TABLE oidc_auth_requests IS
    'Server-side state of one in-flight OIDC login: state and nonce hashes, the PKCE verifier, and the redirect_uri that must match at exchange. Single-use — the row is deleted on consumption — and TTL-bounded at 10 minutes. Not drawn in the v2 ERD; see ADR-029.';

-- Globally unique, unlike sessions.token_hash, and the difference is which side
-- knows the tenant. A session is read after tenant_for_domain has run, so a
-- per-tenant constraint is checkable. A state arrives on a callback whose
-- hostname also resolves the tenant, so the same is true here — but two tenants
-- holding one state hash would still be a collision between two live login
-- attempts, and there is no reason to permit it.
CREATE UNIQUE INDEX oidc_auth_requests_state_key ON oidc_auth_requests (state_hash);

-- For the expiry sweep.
CREATE INDEX oidc_auth_requests_expiry_idx ON oidc_auth_requests (expires_at);

ALTER TABLE oidc_auth_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE oidc_auth_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY oidc_auth_requests_tenant_isolation ON oidc_auth_requests
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- DELETE is granted, unlike on sessions.
--
-- A consumed login attempt is deleted rather than marked, because unlike a
-- session there is nothing about it worth keeping: it records that a browser
-- began a login, not that anybody signed in. The session it produces is the
-- durable record, and sessions.revoked_at is where the audit trail lives.
GRANT SELECT, INSERT, DELETE ON oidc_auth_requests TO cvap_app;

-- No GRANT on users here. 0001 already grants table-wide UPDATE, so a
-- column-list grant would be a no-op that READS like a narrowing control and is
-- not one — the linking constraint is the conditional UPDATE in
-- Users.LinkSubject, and pretending otherwise would put a second, false claim
-- next to the real one.

COMMIT;
