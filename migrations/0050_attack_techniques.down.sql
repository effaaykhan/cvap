-- Drop the three ATT&CK tables 0050 created.
--
-- A faithful inverse, and an honest one: these tables hold only feed data and
-- curated content, both of which are reproducible. The catalogue and the CVE
-- mappings come back from `make knowledge-attack`; the curated rule mappings come
-- back from the migration that seeds them. Nothing here is a record of something
-- this installation observed, so nothing is lost that cannot be re-derived —
-- which is the test for whether a down migration is allowed to drop a table
-- rather than refuse.
--
-- Drop order is irrelevant. None of the three references another: the two
-- technique_id columns are deliberately NOT foreign keys to attack_techniques
-- (0050 says why), and rule_techniques' only FK points OUT at `rules`, which
-- this migration does not touch. An earlier version of this file claimed the
-- order mattered "because of rule_techniques' FK to rules", which confused an
-- outgoing reference with an incoming one — dropping a table with an outgoing FK
-- has never needed anything dropped first.

BEGIN;

DROP TABLE IF EXISTS rule_techniques;
DROP TABLE IF EXISTS cve_techniques;
DROP TABLE IF EXISTS attack_techniques;

-- BOTH feed rows, because the importer writes two: `mitre-attack` for the
-- catalogue (attack_ingest.py import_corpus) and `mitre-attack-cve` for the
-- mappings (import_mappings). Leaving either would advertise a freshness figure
-- and a row count for a table that no longer exists — the shape of a gate that
-- silently passes, since a knowledge dashboard would show ATT&CK as ingested and
-- merely stale.
--
-- The first version of this file deleted only `mitre-attack`, and
-- `make migrate-verify` passed anyway. It could not have failed: verify runs
-- up/down/up on a throwaway database that has never run the Python importer, so
-- the orphan row it would have orphaned was never written there. The gate is
-- structurally blind to this class of defect, which is worth knowing before
-- trusting it about any other down migration that cleans up after an importer.
DELETE FROM knowledge_feed_status WHERE feed IN ('mitre-attack', 'mitre-attack-cve');

COMMIT;
