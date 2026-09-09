-- 0036_release_coverage (B29, ADR-067)
--
-- The keyspace coverage window as DATA, not a constant. A release's advisory feed
-- covers only until that release's support ends (EOL, or ESM end); a host on a
-- release past that window has real exposure the keyspace cannot know about, so a
-- no-match must read as "cannot know", never "clean" (the silent false negative
-- P3.1 was sequenced first to prevent). The boundary lives here, ingested from the
-- feed (ubuntu.com/security/releases.json exposes release_date / support_expires /
-- esm_expires), so it tracks the feed rather than drifting from it — the same
-- argument as knowledge_feed_status's staleness threshold (ADR-063) and ADR-024's
-- ceilings.

BEGIN;

-- ---------------------------------------------------------------------------
-- release_coverage: one row per (feed, release). Global knowledge (no tenant_id,
-- ADR-030). esm_expires is the coverage END — the last date advisories flow,
-- including ESM. A release whose esm_expires is in the past is OUT OF COVERAGE:
-- the keyspace stopped accumulating for it, so absence of a match is not evidence
-- of safety.
-- ---------------------------------------------------------------------------
CREATE TABLE release_coverage (
    feed             text NOT NULL,           -- 'ubuntu-usn'
    distro_release   text NOT NULL,           -- 'hardy'
    release_date     date,
    support_expires  date,                    -- standard support end
    esm_expires      date,                    -- ESM end = coverage end (last advisories)
    -- Provenance of the dates. 'feed' when the feed gave a real support window;
    -- 'feed-degenerate' when it returned only the release date for all three (its
    -- placeholder for releases predating ESM tracking, e.g. hardy) — the release
    -- is still clearly EOL, but the exact coverage end is unknown from the feed and
    -- the empirical newest-advisory date is the better display value. Constrained
    -- to the two values the importer writes: an enum-shaped column gets an enum's
    -- guarantee, so a typo in a future writer is refused, not stored.
    coverage_source  text NOT NULL CHECK (coverage_source IN ('feed', 'feed-degenerate')),
    last_fetched_at  timestamptz NOT NULL,
    PRIMARY KEY (feed, distro_release)
);

COMMENT ON TABLE release_coverage IS
    'Per-release advisory coverage window (B29, ADR-067). Global knowledge (ADR-030); cvap_app reads, cvap_knowledge_import writes. esm_expires is the coverage end.';

-- The injection guarantee (ADR-063), re-asserted because this migration grants to
-- the write role.
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

GRANT SELECT ON release_coverage TO cvap_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON release_coverage TO cvap_knowledge_import;

COMMIT;
