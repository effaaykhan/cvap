-- 0034_advisory_ingestion (P3.2, ADR-014, ADR-019, ADR-030, ADR-063)
--
-- Two things the advisory ingestion pipeline needs that 0010 deliberately left
-- to "the importer's own migration": a feed-freshness record, and a WRITE role
-- for the knowledge tables that is NOT cvap_app (which stays SELECT-only, ADR-030).

BEGIN;

-- ---------------------------------------------------------------------------
-- knowledge_feed_status: one row per ingested feed. Global knowledge (no
-- tenant_id, ADR-030). The staleness THRESHOLD lives here, in the data, so the
-- API answers "is this feed stale" and the panel renders the answer rather than
-- an operator inferring it from a timestamp (the exposure-count lesson).
-- ---------------------------------------------------------------------------
CREATE TABLE knowledge_feed_status (
    feed                 text PRIMARY KEY,          -- 'ubuntu-usn'
    source_url           text NOT NULL,
    last_fetched_at      timestamptz,
    source_etag          text,                      -- provenance: feed's own version marker
    source_version       text,
    advisory_count       integer NOT NULL DEFAULT 0,
    -- Past this age a match against the feed is under-reporting, so the feed is
    -- STALE. A property of the feed, not a UI constant.
    staleness_threshold  interval NOT NULL
);

-- ---------------------------------------------------------------------------
-- cvap_knowledge_import: the signed-import identity 0010's grants comment named.
-- ADR-030 in reverse (ADR-063): a role that can WRITE knowledge is the path by
-- which detection content could be injected, so it is scoped to exactly the
-- knowledge tables and nothing else, and — like cvap_app — must never hold
-- BYPASSRLS or SUPERUSER.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'cvap_knowledge_import') THEN
        CREATE ROLE cvap_knowledge_import NOLOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;
    END IF;
    COMMENT ON ROLE cvap_knowledge_import IS
        'Writes knowledge tables only (advisories, CVEs, feed status). The signed-import identity of ADR-019/ADR-030/ADR-063. Never BYPASSRLS/SUPERUSER; never granted anything outside the knowledge tables.';
EXCEPTION WHEN insufficient_privilege THEN
    RAISE EXCEPTION
        'Cannot create role cvap_knowledge_import and it does not exist. Provisioning must create it: CREATE ROLE cvap_knowledge_import NOLOGIN NOBYPASSRLS NOSUPERUSER; (ADR-063)';
END $$;

-- The same assertion 0001 makes for cvap_app: the injection guarantee depends on
-- this role not being able to reach past its grants via RLS bypass.
DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_knowledge_import';
    IF r.rolbypassrls THEN
        RAISE EXCEPTION 'cvap_knowledge_import holds BYPASSRLS (ADR-063). Fix: ALTER ROLE cvap_knowledge_import NOBYPASSRLS;';
    END IF;
    IF r.rolsuper THEN
        RAISE EXCEPTION 'cvap_knowledge_import is SUPERUSER (ADR-063). Fix: ALTER ROLE cvap_knowledge_import NOSUPERUSER;';
    END IF;
END $$;

-- Write access to EXACTLY the knowledge tables, nothing more. Adding a table
-- here is a visible reversal, the way ADR-030 makes widening cvap_app's grant one.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    vulnerability_defs, vendor_advisories, advisory_vuln_map,
    advisory_fixed_packages, knowledge_feed_status
    TO cvap_knowledge_import;

-- The application role reads feed status for the freshness surface; it never writes it.
GRANT SELECT ON knowledge_feed_status TO cvap_app;

COMMIT;
