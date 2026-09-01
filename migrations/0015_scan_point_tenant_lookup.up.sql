-- 0015_scan_point_tenant_lookup
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- The one deliberate exception to "every read is tenant-scoped" (ADR-002).
-- ADR-031 is the authority; read it before changing anything in this file.
--
-- The problem this solves: a scan point presents a client certificate and
-- nothing else. Core must know which tenant it belongs to BEFORE it can set
-- app.tenant_id — but scan_points is tenant-scoped, so reading it requires the
-- context we are trying to derive. Chicken and egg, and RLS has no answer of
-- its own.
--
-- A SECURITY DEFINER function is a hole through RLS, so this one is exactly one
-- value wide. Every constraint below is load-bearing:
--
--   * RETURNS uuid, not a row and not SETOF. The caller gets a tenant id and
--     nothing else. Widening it to return the scan_point row "for convenience"
--     turns a lookup into a cross-tenant read primitive — that is the review
--     trigger in ADR-031, and the answer is no.
--   * SET search_path. A SECURITY DEFINER function without a pinned search_path
--     is exploitable by search_path manipulation, and this one runs as the
--     definer. pg_catalog first, and the table is schema-qualified anyway.
--   * STABLE, parameterised. The fingerprint is a bind parameter and is never
--     interpolated.
--   * Returns NULL on no match rather than raising. A distinguishable error is
--     an oracle for whether a fingerprint is enrolled.
--   * One indexed equality probe on the unique index over cert_fingerprint,
--     with a filter on the single row it can return. A hit does no more work
--     than a miss, so the function does not leak enrolment by timing either.

BEGIN;

-- ---------------------------------------------------------------------------
-- Role assertion
-- ---------------------------------------------------------------------------
-- Repeated as the first statement of any migration that changes cvap_app's
-- grants, per the rule migration 0001 established. This migration grants EXECUTE
-- on a SECURITY DEFINER function, which is the most consequential grant in the
-- schema, so the property is re-checked before it is made.

DO $$
DECLARE
    r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
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
-- tenant_for_scan_point
-- ---------------------------------------------------------------------------

CREATE FUNCTION tenant_for_scan_point(fingerprint text)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    -- The status list is an ALLOWLIST of enrollable states, deliberately, so
    -- that a status added later defaults to NOT resolving. See the COMMENT ON
    -- TYPE below: any new scan_point_status value must be considered here
    -- explicitly. 'revoked' and 'disabled' are the current exclusions — a
    -- revoked certificate must not resolve to a tenant, which is most of the
    -- point of revoking it.
    SELECT sp.tenant_id
    FROM public.scan_points sp
    WHERE sp.cert_fingerprint = fingerprint
      AND sp.status IN ('pending', 'online', 'offline')
$$;

COMMENT ON FUNCTION tenant_for_scan_point(text) IS
    'ADR-031. The single deliberate exception to tenant-scoped reads: resolves a scan point certificate fingerprint to its tenant id so enrolment can set app.tenant_id. Returns exactly one uuid, or NULL. MUST NOT be widened to return more.';

-- ---------------------------------------------------------------------------
-- Grants and ownership
-- ---------------------------------------------------------------------------
-- Owned by the migration role, which is whoever runs this. NOT cvap_app: a
-- SECURITY DEFINER function its caller can CREATE OR REPLACE is not a control,
-- it is a way to run arbitrary SQL as the definer. Asserted rather than assumed.

REVOKE ALL ON FUNCTION tenant_for_scan_point(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenant_for_scan_point(text) TO cvap_app;

DO $$
DECLARE
    owner_name text;
BEGIN
    SELECT pg_get_userbyid(p.proowner) INTO owner_name
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE p.proname = 'tenant_for_scan_point' AND n.nspname = 'public';

    IF owner_name = 'cvap_app' THEN
        RAISE EXCEPTION
            'tenant_for_scan_point is owned by cvap_app, which can therefore CREATE OR REPLACE its body and run arbitrary SQL as the definer (ADR-031). Run this migration as the migration role.';
    END IF;

    -- The attribute this function actually depends on, and the one it is
    -- easiest to have without noticing.
    --
    -- scan_points carries FORCE ROW LEVEL SECURITY, which applies RLS to the
    -- table owner too. SECURITY DEFINER alone therefore does NOT let this
    -- function read it: the definer must additionally hold BYPASSRLS or
    -- SUPERUSER. On a cluster where the schema owner is a superuser — the
    -- common case, and the case this was written on — that is true by accident.
    --
    -- Where it is not true, and a hardened on-prem deployment with a
    -- non-superuser schema owner is a normal thing for a DBA to build, the
    -- function raises 'unrecognized configuration parameter "app.tenant_id"'
    -- instead of returning NULL. Two things break at once: enrolment stops
    -- working, and the oracle ADR-031 closes reopens — a resolvable fingerprint
    -- and an unresolvable one start producing different failure classes,
    -- controlled by an unrelated environmental condition.
    --
    -- Fail at migrate time, where it is one clear message, rather than at
    -- enrolment time in a deployment nobody tested.
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
         WHERE rolname = owner_name AND (rolbypassrls OR rolsuper)
    ) THEN
        RAISE EXCEPTION
            'tenant_for_scan_point is owned by % which holds neither BYPASSRLS nor SUPERUSER. scan_points is FORCE ROW LEVEL SECURITY, so the definer cannot read it: enrolment would raise instead of returning NULL, which also reopens the enrolment oracle (ADR-031). Grant the owner BYPASSRLS, or run this migration as a role that has it.',
            owner_name;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- The forward pointer for whoever adds a status
-- ---------------------------------------------------------------------------
-- On the type rather than only in migration 0002's text, so it is visible from
-- \dT+ and from any tooling that reads the catalog, and so it reaches databases
-- that already ran 0002 — a comment added to 0002 now would only appear on
-- fresh deployments, since golang-migrate tracks versions rather than content.

COMMENT ON TYPE scan_point_status IS
    'Adding a value here REQUIRES considering tenant_for_scan_point() (migration 0015, ADR-031): its allowlist of enrollable states decides whether a scan point in the new status can resolve to a tenant at all. The default for an unlisted value is "cannot enrol", which is the safe direction but is silent — decide explicitly rather than inheriting it.';

COMMIT;
