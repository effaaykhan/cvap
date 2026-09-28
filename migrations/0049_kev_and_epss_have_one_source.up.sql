-- Drop `vulnerability_defs.in_kev` and `vulnerability_defs.epss_score` — two
-- denormalised copies of facts that ADR-069 moved into tables of their own.
--
-- Both columns date from 0010, before `kev` and `epss` existed. ADR-069 then
-- introduced those tables and named them the source: "a CVE absent from `kev`
-- is **unlisted**, not known-unexploited" (ADR-069 §Absence). Every production
-- read path followed it. Nothing followed the columns:
--
--     kev membership   internal/store/findings.go, overview.go, assets.go
--                      all LEFT JOIN kev k ON k.cve_id = vd.cve_id
--     epss score       findings.go reads e.score from the epss table
--     vd.in_kev        read by NOTHING; written once, as `false`, by a fixture
--     vd.epss_score    read by NOTHING; written by nothing at all
--
-- So the columns were not stale, which would be recoverable. They were
-- permanently false and permanently null, and they looked authoritative: NOT
-- NULL DEFAULT false, a partial index promising "risk ranking reads these two
-- together", and a line in the architecture ER diagram reading "CISA known
-- exploited". That is the shape of a gate that silently passes. It got trusted:
-- ADR-105 cites "0 are flagged in_kev" as evidence that the layer ATT&CK hangs
-- off is thin. Measured against `kev`, the real intersection is 4 of 6,021 —
-- still thin, but the stated figure came from a column no feed maintains, and a
-- reader could not have told the difference. ADR-105's DECISION is unaffected —
-- 4 of 6,021 is as partial as 0 of 6,021 — and ADR-106 supersedes the figure.
--
-- Dropping rather than populating. Populating means the same fact maintained in
-- two places by two importers that must both run and must agree forever, for a
-- reader that does not exist; `kev` is keyed by cve_id and holds 1,723 rows, so
-- the join it replaces costs nothing worth buying back.
--
-- `cvss_base` STAYS: findings.go reads it directly (the priority packing and the
-- "CVSS <x>" basis string). `cvss_vector` stays too — it is unpopulated, but
-- unlike these two it has no competing source contradicting it, so it is an
-- unfilled field rather than a wrong answer. It gets a comment saying so.
--
-- No RLS block here, unlike 0048: `vulnerability_defs` is a global knowledge
-- table with no tenant_id and no row level security, which is correct and
-- deliberate (ADR-069: the feeds are untenanted). The guard below asserts THAT,
-- so this migration fails rather than passes quietly if the table ever becomes
-- tenant-scoped without its policy.

DO $$
DECLARE
    tenanted  integer;
    kev_rows  bigint;
    epss_rows bigint;
    lost_kev  bigint;
    lost_epss bigint;
BEGIN
    -- 1. The premise: these columns carry no information to lose. If a later
    --    change ever started populating them, this drop would destroy data, and
    --    the migration must stop rather than discard it.
    SELECT count(*) INTO lost_kev  FROM vulnerability_defs WHERE in_kev;
    SELECT count(*) INTO lost_epss FROM vulnerability_defs WHERE epss_score IS NOT NULL;
    IF lost_kev > 0 OR lost_epss > 0 THEN
        RAISE EXCEPTION
            'vulnerability_defs carries information in the columns this migration drops (in_kev=true on % row(s), epss_score set on % row(s)). Something began writing them after ADR-069 made kev/epss the source. Reconcile the two sources before dropping — do not run this blind.',
            lost_kev, lost_epss;
    END IF;

    -- 2. The replacement must exist and be populated, or this trades a column
    --    that is always wrong for a join that is always empty.
    SELECT count(*) INTO kev_rows  FROM kev;
    SELECT count(*) INTO epss_rows FROM epss;
    IF kev_rows = 0 OR epss_rows = 0 THEN
        RAISE WARNING
            'kev has % row(s) and epss has % row(s). The columns are dropped either way — they held nothing — but until the feeds are ingested (make knowledge-kev, knowledge-epss) every finding reads as unlisted and unscored, which ADR-069 requires be shown as "not listed", never as "not exploited".',
            kev_rows, epss_rows;
    END IF;

    -- 3. Untenanted by design. Stated rather than assumed, so a regression is
    --    caught by the migration that introduces it (the 0048 house rule).
    SELECT count(*) INTO tenanted
      FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'vulnerability_defs'
       AND column_name = 'tenant_id';
    IF tenanted > 0 THEN
        RAISE EXCEPTION
            'vulnerability_defs has grown a tenant_id. It is a global knowledge table under ADR-069; if that changed it needs RLS + FORCE + a policy in the migration that changed it (non-negotiable #3), and this migration is no longer the right place to be touching it.';
    END IF;

    RAISE NOTICE 'vulnerability_defs: untenanted, columns empty; kev=% epss=% rows carry the facts', kev_rows, epss_rows;
END
$$;

DROP INDEX IF EXISTS vulnerability_defs_kev_idx;

ALTER TABLE vulnerability_defs
    DROP COLUMN in_kev,
    DROP COLUMN epss_score;

COMMENT ON COLUMN vulnerability_defs.cvss_vector IS
    'Unpopulated: the USN feed publishes no CVSS vectors. Kept rather than dropped in 0049 because nothing contradicts it — unlike in_kev/epss_score, which a table already answered. Read by nothing today; check before relying on it.';
