-- Down migration for 0009_observations

BEGIN;

REVOKE ALL ON observations FROM cvap_app;

-- Dropping the parent drops every partition with it, including any created by
-- the partition automation after this migration ran. That is the correct
-- behaviour for a down migration — a partition left behind would have no parent
-- to attach to — but it is worth stating, because it is the one place this down
-- destroys data the up did not create.
DROP TABLE IF EXISTS observations;

DROP TYPE IF EXISTS observation_ingest_state;
DROP TYPE IF EXISTS observation_type;

COMMIT;
