-- Down migration for 0047_identity_settings

BEGIN;
DROP TABLE IF EXISTS identity_settings;
COMMIT;
