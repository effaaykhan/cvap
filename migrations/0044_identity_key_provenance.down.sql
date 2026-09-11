BEGIN;

DROP INDEX IF EXISTS asset_resolution_queue_pending_obs_idx;

REVOKE ALL ON asset_identity_key_sightings FROM cvap_app;
DROP TABLE IF EXISTS asset_identity_key_sightings;

ALTER TABLE asset_identity_keys
    DROP COLUMN IF EXISTS provenance;

DROP TYPE IF EXISTS identity_key_provenance;

COMMIT;
