-- Down migration for 0004_credential_profiles

BEGIN;

REVOKE ALL ON credential_profiles, scan_policy_credential_profiles FROM cvap_app;

DROP TABLE IF EXISTS scan_policy_credential_profiles;
DROP TABLE IF EXISTS credential_profiles;

DROP TYPE IF EXISTS credential_type;

COMMIT;
