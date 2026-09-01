-- Down migration for 0016_observations_resolve_grant

BEGIN;

REVOKE UPDATE (asset_id) ON observations FROM cvap_app;
COMMENT ON COLUMN observations.asset_id IS NULL;

COMMIT;
