-- 0029_oidc_browser_binding
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Run schema-auditor before merging.
--
-- Bind an in-flight login to the browser that started it.

BEGIN;

DO $$
DECLARE
    r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION 'Role cvap_app holds BYPASSRLS or SUPERUSER (ADR-002)';
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- oidc_auth_requests.browser_hash
-- ---------------------------------------------------------------------------
-- ============================================================================
-- state is REPLAY protection. It is not CSRF protection. They are different
-- properties and the flow needs both.
-- ============================================================================
--
-- Migration 0027 bound a login attempt to a tenant and to one use, and to
-- nothing else. A security review demonstrated the consequence by measuring it:
-- an attacker begins a flow from their own client, completes it at their own
-- identity provider, holds the resulting code and state, and then causes the
-- VICTIM's browser to open the callback URL. The victim's browser is issued a
-- session — for the attacker's account. The operator then works inside an
-- account the attacker reads at leisure, which in this product means scan
-- targets and credential profiles.
--
-- SameSite=Lax does not help: the callback is a top-level GET navigation, which
-- is precisely what Lax permits. The missing property is the one OAuth 2.0
-- Security BCP §4.7 requires — the callback must arrive from the same user agent
-- that began the flow.
--
-- So /start sets a cookie carrying a second random value and this column holds
-- its SHA-256. The callback must present it. An attacker can cause a victim's
-- browser to issue a request; they cannot make it send a cookie the attacker's
-- own browser was given.

ALTER TABLE oidc_auth_requests ADD COLUMN browser_hash bytea;

-- Existing rows cannot acquire one, and a row that cannot be bound must not be
-- redeemable. There are at most ten minutes of them by construction.
DELETE FROM oidc_auth_requests WHERE browser_hash IS NULL;

ALTER TABLE oidc_auth_requests ALTER COLUMN browser_hash SET NOT NULL;

COMMENT ON COLUMN oidc_auth_requests.browser_hash IS
    'SHA-256 of the value in the browser-binding cookie set by /v1/auth/oidc/start. The callback must present it. state gives single-use; this gives user-agent binding (OAuth 2.0 Security BCP 4.7) — an attacker can make a victim''s browser issue a request but cannot make it send a cookie their own browser received.';

COMMIT;
