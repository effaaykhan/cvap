-- 0037_kev_epss (P3.4, ADR-069)
--
-- CISA KEV (known-exploited) and FIRST EPSS (exploitation probability), the two
-- risk signals that prioritise the finding set. Both key only on a CVE id and
-- join to vulnerability_defs by cve_id. Global knowledge (no tenant_id, ADR-030),
-- ingested via the P3.2/P3.3 pattern (fetch/import, freshness in
-- knowledge_feed_status), same as advisories and coverage.
--
-- Absence is not evidence (ADR-069): a CVE ABSENT from kev is unlisted, not
-- known-unexploited; a CVE with NO row in epss is unscored, not low-probability.
-- Neither table stores a "safe" sentinel — absence is the absence of a row, and
-- the model reads it as no-signal, never as a low value.

BEGIN;

-- CISA Known Exploited Vulnerabilities: ~1700 CVEs with confirmed in-the-wild
-- exploitation. Membership is the signal; date_added and known_ransomware refine it.
CREATE TABLE kev (
    cve_id            text PRIMARY KEY,
    date_added        date,
    known_ransomware  boolean NOT NULL DEFAULT false,
    source            text,              -- vendorProject/source, provenance
    last_fetched_at   timestamptz NOT NULL
);

-- FIRST EPSS: a daily probability (0..1) that a CVE will be exploited in the next
-- 30 days, for (nearly) every published CVE — ~370k rows. score and percentile are
-- the feed's; a CVE with no row here is unscored (no signal), not probability 0.
CREATE TABLE epss (
    cve_id           text PRIMARY KEY,
    score            numeric(6,5) NOT NULL CHECK (score BETWEEN 0 AND 1),
    percentile       numeric(6,5) CHECK (percentile IS NULL OR percentile BETWEEN 0 AND 1),
    scored_at        date,              -- the feed's score_date, provenance
    last_fetched_at  timestamptz NOT NULL
);

COMMENT ON TABLE kev IS 'CISA KEV known-exploited CVEs (P3.4, ADR-069). Global knowledge; absence = unlisted, not unexploited.';
COMMENT ON TABLE epss IS 'FIRST EPSS exploitation probability per CVE (P3.4, ADR-069). Global knowledge; absence = unscored, not low.';

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

GRANT SELECT ON kev, epss TO cvap_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON kev, epss TO cvap_knowledge_import;

COMMIT;
