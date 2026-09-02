-- 0023_active_tenant_ids
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.
--
-- This migration creates no table. It creates one function, and the reason it
-- needs its own file and its own ADR is that it is a second deliberate hole
-- through RLS.
--
-- ============================================================================
-- A background sweep has no tenant, and RLS means it cannot find one.
-- ============================================================================
--
-- ExpireLeases is where at-most-once is won or lost: a non-reassign_safe job
-- whose lease ran out must FAIL loudly rather than silently re-run against a
-- customer's estate (ADR-012). A security review found it had no caller at all,
-- so the property was written down and never enforced.
--
-- A caller has to exist, and it has to be a periodic sweep, because the thing it
-- reacts to is a scan point that stopped talking — there is no request to hang
-- the work off. Every sweep query is tenant-scoped, so the sweep needs the list
-- of tenants, and RLS on `tenants` deliberately means a cvap_app connection can
-- only ever see the one tenant it is already scoped to.
--
-- ADR-036 records the shape of the answer. The narrowness is here, in the
-- database, not in a Go convention:
--
--   * SETOF uuid. Not the row. A sweep needs identifiers, and returning the
--     tenant record would make this a cross-tenant read primitive.
--   * No parameters. There is nothing to interpolate and nothing to probe with.
--   * STABLE and read-only. It cannot be the write half of anything.
--   * Only 'active'. A suspended tenant's jobs are not swept, which is the
--     conservative direction: a lease left granted expires nothing, it does not
--     re-dispatch.
--
-- What it costs: anything holding cvap_app can enumerate tenant ids. That is a
-- real widening and is stated rather than glossed. It buys the enforcement of
-- ADR-012, and the alternative shapes are all worse — a SECURITY DEFINER
-- function that performs the sweep would be a WRITE bypassing RLS across every
-- tenant, which is a far larger hole than a list of uuids.

BEGIN;

DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION 'Role cvap_app can bypass RLS (ADR-002). Fix: ALTER ROLE cvap_app NOBYPASSRLS NOSUPERUSER;';
    END IF;
END
$$;

-- Plain CREATE, matching 0015 and 0017. CREATE OR REPLACE preserves an
-- existing owner and ACL, so a replace over a function someone had already
-- created keeps their grants and the assertion below would be checking a
-- state this migration did not establish.
CREATE FUNCTION active_tenant_ids()
RETURNS SETOF uuid
LANGUAGE sql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, public
AS $$
    SELECT tenant_id FROM public.tenants WHERE status = 'active' ORDER BY tenant_id
$$;

COMMENT ON FUNCTION active_tenant_ids() IS
    'ADR-036. The ONLY unscoped enumeration in the schema. Returns ids and nothing else, so it cannot become a cross-tenant read primitive. Its one caller is the dispatch sweeper, which enforces ADR-012 lease expiry. Any request to widen the return type is a change to ADR-036.';

REVOKE ALL ON FUNCTION active_tenant_ids() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION active_tenant_ids() TO cvap_app;

-- The same assertion 0015 makes about tenant_for_scan_point, for the same
-- reason. SECURITY DEFINER runs as the OWNER, and every table is FORCE ROW
-- LEVEL SECURITY — which applies to the table owner too. So an owner without
-- BYPASSRLS would have the function silently return nothing, and a sweep that
-- finds no tenants looks exactly like a sweep with nothing to do.
DO $$
DECLARE owner_name text; owner_bypasses boolean; owner_super boolean;
BEGIN
    SELECT r.rolname, r.rolbypassrls, r.rolsuper
      INTO owner_name, owner_bypasses, owner_super
      FROM pg_proc p JOIN pg_roles r ON r.oid = p.proowner
     WHERE p.proname = 'active_tenant_ids'
       AND p.pronamespace = 'public'::regnamespace;

    IF owner_name = 'cvap_app' THEN
        RAISE EXCEPTION 'active_tenant_ids() is owned by cvap_app. A SECURITY DEFINER function owned by the role it is granted to is not a privilege boundary at all (ADR-036).';
    END IF;
    IF NOT (owner_bypasses OR owner_super) THEN
        RAISE EXCEPTION 'active_tenant_ids() is owned by % which holds neither BYPASSRLS nor SUPERUSER. Every table is FORCE ROW LEVEL SECURITY, so the function would return no rows and the sweep would silently do nothing (ADR-036).', owner_name;
    END IF;
END
$$;

COMMIT;
