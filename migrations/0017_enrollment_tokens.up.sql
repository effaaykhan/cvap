-- 0017_enrollment_tokens
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- The enrollment token: issued per zone by an operator, single use, TTL-bounded,
-- carrying the tenant and the zone (ADR-018).
--
-- The scan point asserts NEITHER. Not the tenant, and not the zone — the zone
-- above all, because exposure is derived from the vantage point an observation
-- was made from (ADR-008), so a scan point that could choose its own zone could
-- rewrite the derived exposure of every asset it reports. EnrollRequest
-- deliberately has no zone field; this table is where the zone actually comes
-- from.
--
-- Not in the v2 ERD; recorded in ADR-029.

BEGIN;

-- Re-assert the role's properties: this migration changes cvap_app's grants and
-- adds a SECURITY DEFINER function, per the rule 0001 established.
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

CREATE TABLE enrollment_tokens (
    token_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FKs (ADR-017); see users.tenant_id in
    -- 0001. Note the token is the thing that TELLS Core which tenant this is,
    -- which is why reading this table needs the pre-tenant lookup below
    -- (ADR-033) — but once read, it is ordinary tenant-scoped data.
    tenant_id           uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    -- The zone the scan point is being enrolled INTO. Operator-chosen, never
    -- scan-point-asserted.
    zone_id             uuid NOT NULL,

    -- SHA-256 of the token. The token itself is NEVER stored.
    --
    -- It is a bearer credential: whoever holds it obtains a fleet identity. A
    -- database backup, a read replica, an operator with SELECT, or a SQL
    -- injection must not yield usable tokens.
    --
    -- Plain SHA-256 rather than bcrypt or argon2, deliberately. Those exist to
    -- make low-entropy secrets expensive to guess. This is 256 bits from
    -- crypto/rand, so there is nothing to brute-force, and a deliberately slow
    -- KDF would only add latency to the redemption path for no gain.
    token_hash          bytea NOT NULL,

    issued_by           uuid,
    issued_at           timestamptz NOT NULL DEFAULT now(),
    expires_at          timestamptz NOT NULL,

    -- NULL until redeemed. The conditional UPDATE that sets it is what makes
    -- redemption single-use; see the comment on the unique index below.
    redeemed_at         timestamptz,
    redeemed_scan_point uuid,

    -- Operator-facing label, so a pending token is identifiable in a UI without
    -- revealing anything. Never used for authentication.
    description         text,

    CONSTRAINT enrollment_tokens_tenant_token_key UNIQUE (tenant_id, token_id),

    CONSTRAINT enrollment_tokens_zone_fk FOREIGN KEY (tenant_id, zone_id)
        REFERENCES scan_zones (tenant_id, zone_id) ON DELETE CASCADE,

    -- Column-list SET NULL (Postgres 15+): a bare SET NULL would null tenant_id
    -- too. A departed operator must not erase the record of a token issuance.
    CONSTRAINT enrollment_tokens_issued_by_fk FOREIGN KEY (tenant_id, issued_by)
        REFERENCES users (tenant_id, user_id) ON DELETE SET NULL (issued_by),

    CONSTRAINT enrollment_tokens_redeemed_scan_point_fk
        FOREIGN KEY (tenant_id, redeemed_scan_point)
        REFERENCES scan_points (tenant_id, scan_point_id)
        ON DELETE SET NULL (redeemed_scan_point),

    CONSTRAINT enrollment_tokens_expiry_after_issue CHECK (expires_at > issued_at),

    -- The 7-day hard cap (the default TTL is 24h, set by the issuing code).
    -- Enforced here rather than only in Go: a token valid for a month is the
    -- shape of a long-lived shared secret, which is what ADR-018 rejected.
    CONSTRAINT enrollment_tokens_ttl_cap
        CHECK (expires_at <= issued_at + interval '7 days'),

    -- One-directional, not a biconditional, and the difference is load-bearing.
    --
    -- The obvious form is
    --     CHECK ((redeemed_at IS NULL) = (redeemed_scan_point IS NULL))
    -- and it deadlocks against the ON DELETE SET NULL above: deleting a scan
    -- point nulls redeemed_scan_point on any token that redeemed it, which
    -- leaves redeemed_at set and violates the biconditional. The scan point
    -- then cannot be deleted at all, while scan_point_certificates and
    -- scan_point_capabilities both cascade from the same parent — so the schema
    -- expects deletion to work and this one constraint silently forbids it.
    --
    -- The dangerous outcome is not the failed delete. It is that someone under
    -- time pressure removes the CHECK, which is what the redemption audit trail
    -- rests on. So the direction that matters is kept — a token naming a
    -- redeemer must be redeemed — and the reverse is allowed, because "redeemed
    -- by a scan point that has since been deleted" is a true statement about
    -- history rather than an inconsistency.
    CONSTRAINT enrollment_tokens_redemption_consistent
        CHECK (redeemed_scan_point IS NULL OR redeemed_at IS NOT NULL)
);

COMMENT ON TABLE enrollment_tokens IS
    'Single-use, TTL-bounded enrollment credentials (ADR-018). Stores a SHA-256 hash, never the token. Not drawn in the v2 ERD; see ADR-029.';

-- Globally unique, not per tenant: the lookup happens BEFORE the tenant is
-- known, so a per-tenant constraint could not be checked at that point — and two
-- tenants holding the same token hash would make the pre-tenant lookup
-- ambiguous, which is precisely the hazard ADR-033 closes by requiring a single
-- unambiguous row. A SHA-256 collision is not the concern; a copied row is.
CREATE UNIQUE INDEX enrollment_tokens_hash_key ON enrollment_tokens (token_hash);

-- The operator's pending-token list.
CREATE INDEX enrollment_tokens_pending_idx
    ON enrollment_tokens (tenant_id, expires_at)
    WHERE redeemed_at IS NULL;

ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY enrollment_tokens_tenant_isolation ON enrollment_tokens
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- tenant_for_enrollment_token — second member of the ADR-033 class
-- ---------------------------------------------------------------------------
-- Same shape as tenant_for_scan_point (0015), deliberately identical: one
-- input, RETURNS uuid, STABLE, pinned search_path, validity filter in SQL,
-- NULL rather than RAISE, owned by the migration role. ADR-033 is the authority
-- and defines the class; a third member amends that ADR rather than adding a
-- function here.
--
-- The validity filter is what stops this being an oracle: an unknown hash, an
-- expired token and an already-redeemed token are indistinguishable to the
-- caller, all returning NULL.
--
-- It resolves the tenant only. It does NOT redeem — redemption is the
-- conditional UPDATE in 0017's repository code, which runs under RLS inside the
-- enrolling transaction, so single-use is enforced by the database's own
-- re-evaluation of the UPDATE predicate after a lock wait, not by this lookup.

CREATE FUNCTION tenant_for_enrollment_token(token_hash bytea)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT t.tenant_id
    FROM public.enrollment_tokens t
    WHERE t.token_hash = tenant_for_enrollment_token.token_hash
      AND t.redeemed_at IS NULL
      AND t.expires_at > now()
$$;

COMMENT ON FUNCTION tenant_for_enrollment_token(bytea) IS
    'ADR-033 pre-tenant resolution. Resolves an enrollment token hash to its tenant so Enroll can set app.tenant_id. Returns exactly one uuid, or NULL for unknown, expired or already-redeemed. MUST NOT be widened, and MUST NOT redeem.';

REVOKE ALL ON FUNCTION tenant_for_enrollment_token(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_for_enrollment_token(bytea) TO cvap_app;

DO $$
DECLARE
    owner_name text;
BEGIN
    SELECT pg_get_userbyid(p.proowner) INTO owner_name
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.proname = 'tenant_for_enrollment_token' AND n.nspname = 'public';

    IF owner_name = 'cvap_app' THEN
        RAISE EXCEPTION
            'tenant_for_enrollment_token is owned by cvap_app, which can therefore CREATE OR REPLACE its body and run arbitrary SQL as the definer (ADR-033).';
    END IF;

    -- enrollment_tokens is FORCE ROW LEVEL SECURITY, so SECURITY DEFINER alone
    -- does not let this read it. Same constraint as 0015, same reason it is
    -- asserted rather than assumed: on a cluster whose schema owner is not a
    -- superuser this fails at enrollment time rather than here.
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles WHERE rolname = owner_name AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION
            'tenant_for_enrollment_token is owned by % which holds neither BYPASSRLS nor SUPERUSER. enrollment_tokens is FORCE ROW LEVEL SECURITY, so the definer cannot read it and enrollment would raise instead of returning NULL (ADR-033).',
            owner_name;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- The capability ceiling, recorded where it will be read
-- ---------------------------------------------------------------------------
-- The column is called `enabled`, which invites exactly the wrong reading.

COMMENT ON COLUMN scan_point_capabilities.enabled IS
    'A SELF-ASSERTION by the scan point, and a CEILING rather than a grant. It states what that scan point CAN execute, never what it MAY. Core MUST use it only to WITHHOLD work, and MUST take authorisation — safety mode, engine enablement, policy — from its own records keyed on the authenticated identity. Read as a grant, it lets a scan point in a network whose compromise the threat model assumes (ADR-020) obtain intrusive work by claiming to support it.';

GRANT SELECT, INSERT, UPDATE ON enrollment_tokens TO cvap_app;

COMMIT;
