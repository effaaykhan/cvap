-- Down migration for 0013_asset_resolution_queue

BEGIN;

REVOKE ALL ON asset_resolution_queue FROM cvap_app;

DROP TABLE IF EXISTS asset_resolution_queue;

DROP TYPE IF EXISTS resolution_state;

COMMIT;
