-- Tenant isolation test. Run against a database with all migrations applied:
--
--     make rls-test
--
-- Every assertion runs as cvap_app, the application role. That is the point: a
-- migration role bypasses RLS and would pass every case below while proving
-- nothing. If this file is ever run without the SET ROLE, it is testing the
-- wrong identity and its passes are meaningless.
--
--   Case 1  reads are filtered to the session's tenant, swept across every
--           tenant-scoped table so a table added later without a policy fails
--           here rather than in production
--   Case 2  a query with no tenant context RAISES rather than returning rows
--   Case 3  a write into another tenant's scope is refused (WITH CHECK, which
--           USING alone does not give you) — 3a asserts every policy in the
--           catalog carries it, 3b/3c prove it refuses a real INSERT and UPDATE
--   Case 4  a composite FK refuses a child in tenant A pointing at a parent in
--           tenant B — ADR-017's claim, executed
--
-- Everything runs inside one transaction and ends in ROLLBACK, so the test
-- leaves no fixtures behind.
--
-- Implementation note: fixture IDs live in a temp table rather than psql
-- variables because psql does not interpolate `:vars` inside dollar-quoted
-- blocks, and every assertion here needs to be inside one — a DO block with an
-- EXCEPTION handler is what lets a deliberately-failing statement be caught
-- instead of aborting the transaction.

\set ON_ERROR_STOP on
\timing off

BEGIN;

-- ---------------------------------------------------------------------------
-- Fixtures, created as the migration role.
-- ---------------------------------------------------------------------------

CREATE TEMP TABLE rls_fixture (label text PRIMARY KEY, id uuid NOT NULL);
GRANT SELECT ON rls_fixture TO cvap_app;

WITH a AS (
    -- domain is NOT NULL since 0026: every tenant is reachable at a hostname,
    -- because that is what names it before a request is authenticated (ADR-041).
    INSERT INTO tenants (name, domain, deployment_mode)
    VALUES ('rls-test-A', 'rls-test-a.invalid', 'saas')
    RETURNING tenant_id
), b AS (
    INSERT INTO tenants (name, domain, deployment_mode)
    VALUES ('rls-test-B', 'rls-test-b.invalid', 'onprem')
    RETURNING tenant_id
)
INSERT INTO rls_fixture (label, id)
SELECT 'tenant_a', tenant_id FROM a
UNION ALL
SELECT 'tenant_b', tenant_id FROM b;

-- A role, a user and a zone in each tenant, so case 1 has something to filter
-- and case 4 has a real cross-tenant parent to aim at.
WITH ra AS (
    INSERT INTO roles (tenant_id, name)
    SELECT id, 'rls-test-role' FROM rls_fixture WHERE label = 'tenant_a'
    RETURNING tenant_id, role_id
), rb AS (
    INSERT INTO roles (tenant_id, name)
    SELECT id, 'rls-test-role' FROM rls_fixture WHERE label = 'tenant_b'
    RETURNING tenant_id, role_id
)
INSERT INTO rls_fixture (label, id)
SELECT 'role_a', role_id FROM ra
UNION ALL
SELECT 'role_b', role_id FROM rb;

INSERT INTO users (tenant_id, role_id, email, auth_provider)
SELECT t.id, r.id, 'alice@a.example', 'local'
FROM rls_fixture t, rls_fixture r
WHERE t.label = 'tenant_a' AND r.label = 'role_a';

INSERT INTO users (tenant_id, role_id, email, auth_provider)
SELECT t.id, r.id, 'bob@b.example', 'local'
FROM rls_fixture t, rls_fixture r
WHERE t.label = 'tenant_b' AND r.label = 'role_b';

WITH za AS (
    INSERT INTO scan_zones (tenant_id, name, zone_type, trust_level)
    SELECT id, 'rls-test-zone', 'internal', 50 FROM rls_fixture WHERE label = 'tenant_a'
    RETURNING zone_id
), zb AS (
    INSERT INTO scan_zones (tenant_id, name, zone_type, trust_level)
    SELECT id, 'rls-test-zone', 'internal', 50 FROM rls_fixture WHERE label = 'tenant_b'
    RETURNING zone_id
)
INSERT INTO rls_fixture (label, id)
SELECT 'zone_a', zone_id FROM za
UNION ALL
SELECT 'zone_b', zone_id FROM zb;

-- ---------------------------------------------------------------------------
-- Populate every tenant-scoped table, for both tenants.
-- ---------------------------------------------------------------------------
-- Case 1's sweep asserts that no foreign rows are visible. Against an empty
-- table that assertion is vacuous, and it used to be vacuous for 29 of the 33
-- tables — the suite said so on every run rather than reporting a clean pass,
-- which is what made it worth fixing rather than living with.
--
-- Both tenants are populated, not just one. If only tenant A had rows there
-- would be no foreign rows for the sweep to fail on, and it would pass for the
-- wrong reason.

\i /testdata/fixtures.sql

-- CALL takes no subquery argument at all, even inside a DO block, so the ids
-- go through local variables.
DO $seed$
DECLARE
    a uuid;
    b uuid;
BEGIN
    SELECT id INTO a FROM rls_fixture WHERE label = 'tenant_a';
    SELECT id INTO b FROM rls_fixture WHERE label = 'tenant_b';
    CALL fixture_seed_tenant(a, 'a');
    CALL fixture_seed_tenant(b, 'b');
END
$seed$;

-- ---------------------------------------------------------------------------
-- Drop to the application role. Everything below is cvap_app.
-- ---------------------------------------------------------------------------

DO $$
BEGIN
    IF (SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = 'cvap_app') THEN
        RAISE EXCEPTION
            'cvap_app holds BYPASSRLS or SUPERUSER. Every case below would pass while proving nothing (ADR-002).';
    END IF;
END
$$;

SET LOCAL ROLE cvap_app;

DO $$
BEGIN
    IF current_user <> 'cvap_app' THEN
        RAISE EXCEPTION 'SET ROLE did not take: running as %, not cvap_app', current_user;
    END IF;
END
$$;

SELECT set_config('app.tenant_id', (SELECT id::text FROM rls_fixture WHERE label = 'tenant_a'), true);

-- ---------------------------------------------------------------------------
-- Case 1: reads are filtered to the session's tenant.
-- ---------------------------------------------------------------------------

DO $$
DECLARE
    n_visible int;
    n_foreign int;
BEGIN
    SELECT count(*) INTO n_visible FROM users;
    SELECT count(*) INTO n_foreign FROM users
        WHERE tenant_id <> current_setting('app.tenant_id')::uuid;

    IF n_foreign <> 0 THEN
        RAISE EXCEPTION 'CASE 1 FAILED: % rows from another tenant are visible in users', n_foreign;
    END IF;
    -- Tenant B's users exist and must not be counted. If nothing is visible at
    -- all the filter has proved nothing, so that is a failure too. The count is
    -- not pinned to an exact number: the fixtures may grow, and a test that has
    -- to be edited every time a fixture is added is a test people edit without
    -- reading.
    IF n_visible < 1 THEN
        RAISE EXCEPTION 'CASE 1 FAILED: no users visible at all, so the filter proved nothing';
    END IF;
    RAISE NOTICE 'case 1 passed on users: % own rows visible, 0 foreign', n_visible;
END
$$;

-- The sweep. Every tenant-scoped table, so a table added later without a policy
-- fails here. Empty tables are counted and reported rather than silently
-- passing — an empty table proves nothing, and saying so is the difference
-- between a test and a green tick.
DO $$
DECLARE
    tbl     text;
    n       int;
    checked int := 0;
    empty   int := 0;
    empties text[] := ARRAY[]::text[];
BEGIN
    FOR tbl IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_namespace ns ON ns.oid = c.relnamespace
        JOIN pg_attribute a  ON a.attrelid = c.oid AND a.attname = 'tenant_id'
                            AND NOT a.attisdropped
        WHERE ns.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND NOT c.relispartition
        ORDER BY c.relname
    LOOP
        EXECUTE format(
            'SELECT count(*) FROM %I WHERE tenant_id <> current_setting(''app.tenant_id'')::uuid',
            tbl) INTO n;
        IF n <> 0 THEN
            RAISE EXCEPTION 'CASE 1 FAILED on %: % foreign rows visible', tbl, n;
        END IF;

        EXECUTE format('SELECT count(*) FROM %I', tbl) INTO n;
        IF n = 0 THEN
            empty   := empty + 1;
            empties := empties || tbl;
        END IF;
        checked := checked + 1;
    END LOOP;

    RAISE NOTICE 'case 1 swept % tenant-scoped tables', checked;

    -- Empty tables are now a FAILURE, not a note.
    --
    -- Before fixtures existed this printed a warning, because the alternative
    -- was failing every run for a known gap. The fixtures close that gap, so an
    -- empty tenant-scoped table now means either a table was added without a
    -- fixture row, or a fixture stopped inserting one. Both make the sweep
    -- silently weaker, which is exactly the failure mode this suite exists to
    -- avoid — the sweep would still pass, over less.
    IF empty > 0 THEN
        RAISE EXCEPTION
            'CASE 1 FAILED: % tenant-scoped table(s) have no rows, so the sweep proves nothing for them: %. Add fixture rows in internal/store/testdata/fixtures.sql.',
            empty, empties;
    END IF;
    RAISE NOTICE 'case 1: every swept table had rows, so the filter was actually exercised';
END
$$;

-- ---------------------------------------------------------------------------
-- Case 2: no tenant context must RAISE, not return rows.
-- ---------------------------------------------------------------------------
-- This is the case that catches a policy written with the two-argument
-- current_setting('app.tenant_id', true), which returns NULL when unset. A NULL
-- predicate is not an error: it filters everything out and reads as "no data",
-- which is exactly the silent failure ADR-002 refuses. An empty result set and
-- an exception are very different things to a caller.

RESET app.tenant_id;

DO $$
DECLARE
    n int;
BEGIN
    SELECT count(*) INTO n FROM users;
    RAISE EXCEPTION
        'CASE 2 FAILED: a query with no tenant context returned % rows instead of raising. The policy is probably using the two-argument current_setting.', n;
EXCEPTION
    WHEN undefined_object THEN
        RAISE NOTICE 'case 2 passed: unset app.tenant_id raised undefined_object';
    WHEN invalid_text_representation THEN
        RAISE NOTICE 'case 2 passed: unset app.tenant_id raised invalid_text_representation';
END
$$;

SELECT set_config('app.tenant_id', (SELECT id::text FROM rls_fixture WHERE label = 'tenant_a'), true);

-- ---------------------------------------------------------------------------
-- Case 3: writing into another tenant's scope must fail.
-- ---------------------------------------------------------------------------
-- USING alone governs reads. Without WITH CHECK a tenant can write rows it
-- cannot read back — worse than a read leak, because nothing in the writing
-- tenant's own view ever shows it happened.
--
-- Two halves, and both are needed.
--
-- 3a is exhaustive but static: it asserts against the catalog that EVERY policy
-- on EVERY tenant-scoped table has both USING and WITH CHECK, with exactly the
-- expected expression. This is the half that proves the rule holds everywhere
-- rather than only on the tables someone remembered — a runtime insert can only
-- ever test the tables you wrote an insert for, and the failure mode being
-- guarded against is precisely a policy nobody thought about.
--
-- 3b/3c are narrow but real: they prove the catalog's WITH CHECK actually
-- refuses a write at runtime, on INSERT and on UPDATE. Without 3b/3c, 3a is
-- just asserting that a string matches a string.

-- 3a: every policy, from the catalog.
DO $$
DECLARE
    expected  text := '(tenant_id = (current_setting(''app.tenant_id''::text))::uuid)';
    bad       text[] := ARRAY[]::text[];
    r         record;
    n_tables  int := 0;
    n_policies int := 0;
BEGIN
    -- Every table with a tenant_id column must have RLS on, forced, and exactly
    -- one policy. A table added later without them fails here.
    FOR r IN
        SELECT c.relname AS tbl, c.relrowsecurity, c.relforcerowsecurity,
               (SELECT count(*) FROM pg_policy pol WHERE pol.polrelid = c.oid) AS npol
        FROM pg_class c
        JOIN pg_namespace ns ON ns.oid = c.relnamespace
        JOIN pg_attribute a  ON a.attrelid = c.oid AND a.attname = 'tenant_id'
                            AND NOT a.attisdropped
        WHERE ns.nspname = 'public'
          AND c.relkind IN ('r', 'p')
        ORDER BY c.relname
    LOOP
        n_tables := n_tables + 1;
        IF NOT r.relrowsecurity THEN
            bad := bad || (r.tbl || ': RLS not enabled');
        END IF;
        IF NOT r.relforcerowsecurity THEN
            bad := bad || (r.tbl || ': RLS not FORCEd, so the owner is exempt');
        END IF;
        IF r.npol <> 1 THEN
            bad := bad || (r.tbl || ': expected exactly 1 policy, found ' || r.npol);
        END IF;
    END LOOP;

    -- Every policy's expressions must be exactly right. A policy with a NULL
    -- with_check permits any write; one with a different expression is a policy
    -- nobody has reasoned about.
    FOR r IN
        SELECT tablename AS tbl, qual, with_check
        FROM pg_policies WHERE schemaname = 'public'
        ORDER BY tablename
    LOOP
        n_policies := n_policies + 1;
        IF r.with_check IS NULL THEN
            bad := bad || (r.tbl || ': policy has NO WITH CHECK — this tenant can write into another tenant''s scope');
        ELSIF r.with_check <> expected THEN
            bad := bad || (r.tbl || ': unexpected WITH CHECK: ' || r.with_check);
        END IF;
        IF r.qual IS NULL THEN
            bad := bad || (r.tbl || ': policy has no USING clause');
        ELSIF r.qual <> expected THEN
            bad := bad || (r.tbl || ': unexpected USING: ' || r.qual);
        END IF;
    END LOOP;

    IF cardinality(bad) > 0 THEN
        RAISE EXCEPTION 'CASE 3a FAILED: %', array_to_string(bad, E'\n  ');
    END IF;

    IF n_tables = 0 OR n_policies = 0 THEN
        RAISE EXCEPTION 'CASE 3a INCONCLUSIVE: found % tenant-scoped tables and % policies', n_tables, n_policies;
    END IF;

    RAISE NOTICE 'case 3a passed: % tenant-scoped tables (incl. partitions), % policies, all with USING + WITH CHECK', n_tables, n_policies;
END
$$;

-- 3b: the catalog's WITH CHECK actually refuses an INSERT at runtime.
DO $$
DECLARE
    b_tenant uuid;
BEGIN
    SELECT id INTO b_tenant FROM rls_fixture WHERE label = 'tenant_b';

    INSERT INTO scan_zones (tenant_id, name, zone_type, trust_level)
    VALUES (b_tenant, 'rls-test-cross-tenant-zone', 'internal', 1);

    RAISE EXCEPTION
        'CASE 3b FAILED: inserted a row scoped to tenant B while the session is tenant A. The policy is missing WITH CHECK.';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'case 3b passed: cross-tenant INSERT refused by RLS WITH CHECK';
END
$$;

-- 3c: the same for UPDATE. A row can be moved out of the tenant by an UPDATE
-- even where the INSERT path is covered, if the check is written wrong.
DO $$
DECLARE
    b_tenant uuid;
    a_zone   uuid;
BEGIN
    SELECT id INTO b_tenant FROM rls_fixture WHERE label = 'tenant_b';
    SELECT id INTO a_zone   FROM rls_fixture WHERE label = 'zone_a';

    UPDATE scan_zones SET tenant_id = b_tenant WHERE zone_id = a_zone;

    IF FOUND THEN
        RAISE EXCEPTION
            'CASE 3c FAILED: moved a row into tenant B with an UPDATE. WITH CHECK is not covering UPDATE.';
    END IF;
    RAISE NOTICE 'case 3 passed: cross-tenant UPDATE matched no rows';
EXCEPTION
    WHEN insufficient_privilege THEN
        RAISE NOTICE 'case 3c passed: cross-tenant UPDATE refused by RLS WITH CHECK';
END
$$;

-- ---------------------------------------------------------------------------
-- Case 4: composite FK refuses a cross-tenant parent.
-- ---------------------------------------------------------------------------
-- ADR-017 claims the denormalised tenant_id is safe BECAUSE of the composite
-- FK, not despite it. This is that claim, executed.
--
-- Note what makes it a distinct guarantee from RLS: the row being inserted is
-- scoped to tenant A and passes the policy. It fails on the constraint, because
-- (tenant_a, zone_b) does not exist in scan_zones. Referential integrity checks
-- run with row security off, so the FK sees tenant B's zone and still refuses —
-- which is the point. RLS would have hidden the parent; the constraint makes
-- the child unrepresentable.

DO $$
DECLARE
    a_tenant uuid;
    a_zone   uuid;
BEGIN
    SELECT id INTO a_tenant FROM rls_fixture WHERE label = 'tenant_a';
    SELECT id INTO a_zone   FROM rls_fixture WHERE label = 'zone_a';

    -- Control. If this fails, case 4's failure below would prove nothing about
    -- tenancy — it would just mean the insert was broken.
    INSERT INTO network_ranges (tenant_id, zone_id, cidr)
    VALUES (a_tenant, a_zone, '10.0.0.0/24');

    RAISE NOTICE 'case 4 control passed: same-tenant child insert succeeded';
END
$$;

DO $$
DECLARE
    a_tenant uuid;
    b_zone   uuid;
BEGIN
    SELECT id INTO a_tenant FROM rls_fixture WHERE label = 'tenant_a';
    SELECT id INTO b_zone   FROM rls_fixture WHERE label = 'zone_b';

    INSERT INTO network_ranges (tenant_id, zone_id, cidr)
    VALUES (a_tenant, b_zone, '10.0.1.0/24');

    RAISE EXCEPTION
        'CASE 4 FAILED: a child in tenant A now references a parent in tenant B. The composite FK is not doing its job, and every "safe because of the constraint" comment in migrations/ is wrong.';
EXCEPTION
    WHEN foreign_key_violation THEN
        RAISE NOTICE 'case 4 passed: composite FK refused a cross-tenant parent';
END
$$;

RESET ROLE;

SELECT 'all four cases passed' AS result;

ROLLBACK;
