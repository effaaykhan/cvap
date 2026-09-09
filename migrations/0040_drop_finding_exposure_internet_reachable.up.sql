-- 0040: drop finding_exposure.internet_reachable — the never-written column
-- (ADR-074, resolving backlog #6).
--
-- Added in 0011 as `boolean NOT NULL DEFAULT false`, it was never written true —
-- SetExposure has always omitted it — so every row read false. That was tolerable
-- while it fed only a read endpoint, but P3.4 made it the second-strongest term in
-- the shipping priority model (the 1e8 exposure weight), where an always-false
-- input is not weak, it is inert. ADR-059 and ADR-069 disclosed the gap; this
-- migration makes the decision instead: the exposure signal derives from the zone's
-- type (external/dmz = internet-reachable), which IS written, and the dead column
-- and its (never-selective) partial index are removed.
--
-- auth_required is deliberately NOT dropped here: it is the same never-written
-- shape, but it is display-only and not a term in the priority model, so it has not
-- accrued the "input nobody wrote" problem. Phase 4's credentialed checks are its
-- natural writer; ADR-074 records it as the sibling left standing.
BEGIN;

DROP INDEX IF EXISTS finding_exposure_internet_idx;
ALTER TABLE finding_exposure DROP COLUMN internet_reachable;

COMMIT;
