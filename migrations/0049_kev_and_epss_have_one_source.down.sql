-- Restore the two columns 0049 dropped, and the partial index over in_kev.
--
-- A faithful inverse, and cheap to be faithful about: the columns carried no
-- information when they were dropped (0049's up asserts exactly that before
-- touching them), so restoring them empty restores everything they held. The
-- shape comes back identical to 0010 — NOT NULL DEFAULT false for in_kev, the
-- 0..1 CHECK for epss_score — because a down that returns a LOOSER schema than
-- the one it claims to restore lets a row exist that the up-migration could not
-- have produced, and the next up would then fail on data the down invited in.
--
-- What does not come back is a reader. Nothing consumed these columns before
-- 0049 and nothing will after this down; the kev and epss tables still answer
-- membership and score, and rolling back this migration does not roll back
-- ADR-069. So a rollback restores two empty columns, which is precisely the
-- state that made them worth dropping. Rolling back is for getting a schema
-- version consistent again, not for getting the facts back — they were never
-- in here.

ALTER TABLE vulnerability_defs
    ADD COLUMN in_kev     boolean NOT NULL DEFAULT false,
    ADD COLUMN epss_score numeric(5,4);

ALTER TABLE vulnerability_defs
    ADD CONSTRAINT vulnerability_defs_epss_range
        CHECK (epss_score IS NULL OR epss_score BETWEEN 0 AND 1);

-- Risk ranking reads these two together. (It does not, and that was the point —
-- restored verbatim from 0010 so the rolled-back schema matches what 0010 made.)
CREATE INDEX vulnerability_defs_kev_idx ON vulnerability_defs (in_kev) WHERE in_kev;

COMMENT ON COLUMN vulnerability_defs.cvss_vector IS NULL;
