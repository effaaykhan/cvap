-- Down migration for 0020_observation_pending_state

BEGIN;

DROP INDEX IF EXISTS observations_pending_idx;
DROP TRIGGER IF EXISTS observations_ingest_state_ratchet ON observations;
DROP FUNCTION IF EXISTS observations_ingest_state_ratchet();

REVOKE UPDATE (ingest_state) ON observations FROM cvap_app;
ALTER TABLE observations ALTER COLUMN ingest_state SET DEFAULT 'accepted';

COMMENT ON COLUMN observations.ingest_state IS NULL;

-- The enum VALUE is deliberately not removed. PostgreSQL cannot drop one, and
-- recreating the type would require rewriting every partition of the largest
-- table in the system. A down migration that takes an outage is worse than one
-- that leaves an unused label behind: nothing can insert 'pending' once the
-- default is back and the code is gone.

COMMIT;
