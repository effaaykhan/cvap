-- 0028_oidc_issuer_in_identity
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Run schema-auditor before merging.
--
-- The identity a returning single-sign-on user is found by must name the ISSUER
-- as well as the subject.

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
-- users.oidc_issuer
-- ---------------------------------------------------------------------------
-- ADR-045 rests on `sub` being stable and never reassigned, and states the
-- qualifier itself: OpenID Connect requires that WITHIN AN ISSUER. Migration
-- 0027 then stored the subject without one, so the lookup was
-- (tenant_id, oidc_subject) and the issuer was implied by whatever
-- tenant_auth_config happened to say at the time.
--
-- The consequence, found by an ADR-compliance pass reading the ADR against the
-- code: changing tenant_auth_config.oidc_issuer silently re-points every
-- existing binding into a NEW issuer's subject namespace. A `sub` minted by the
-- new provider that collides with an old one takes over that account — and the
-- once-only linking control does not apply, because the row is found by subject
-- lookup rather than by the linking path.
--
-- Nothing writes oidc_issuer today except a migration or an operator's SQL,
-- which is precisely why this is the moment to fix it: the tenant administration
-- endpoints are a later session, and after they land this is a data migration
-- against live bindings rather than a column addition against none.

ALTER TABLE users ADD COLUMN oidc_issuer text;

COMMENT ON COLUMN users.oidc_issuer IS
    'The issuer that minted oidc_subject. Part of the identity, not decoration: `sub` is unique and stable only within an issuer, so a binding that does not name one is a binding that silently follows a change of provider into a different subject namespace.';

-- Backfill: an existing binding was minted by the issuer the tenant is
-- configured with, because that is the only one that could have minted it.
UPDATE users u
   SET oidc_issuer = ac.oidc_issuer
  FROM tenant_auth_config ac
 WHERE ac.tenant_id = u.tenant_id
   AND u.oidc_subject IS NOT NULL
   AND u.oidc_issuer IS NULL
   AND ac.oidc_issuer IS NOT NULL;

-- A binding whose issuer cannot be determined — the tenant has no auth config,
-- or its config names no issuer — has its SUBJECT CLEARED rather than being
-- given a guess.
--
-- Fail-closed, and the cost is understood: that user signs in again and the
-- once-only linking path re-binds them, which requires a verified email from the
-- provider. Inventing an issuer would be the opposite trade — a binding that
-- looks authoritative and names a namespace nobody checked.
UPDATE users
   SET oidc_subject = NULL
 WHERE oidc_subject IS NOT NULL AND oidc_issuer IS NULL;

-- Both or neither. A subject with no issuer is a binding whose namespace is
-- unknown, and an issuer with no subject names nobody.
ALTER TABLE users ADD CONSTRAINT users_oidc_identity_complete
    CHECK ((oidc_subject IS NULL) = (oidc_issuer IS NULL));

DROP INDEX users_tenant_oidc_subject_key;

CREATE UNIQUE INDEX users_tenant_oidc_identity_key
    ON users (tenant_id, oidc_issuer, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

-- No GRANT: 0001 grants table-wide UPDATE on users, so a column list here would
-- be a no-op dressed as a control. See the note in 0027.

COMMIT;
