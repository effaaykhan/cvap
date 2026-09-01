-- Down migration for 0017_enrollment_tokens

BEGIN;

REVOKE ALL ON FUNCTION tenant_for_enrollment_token(bytea) FROM cvap_app;
DROP FUNCTION IF EXISTS tenant_for_enrollment_token(bytea);

REVOKE ALL ON enrollment_tokens FROM cvap_app;
DROP TABLE IF EXISTS enrollment_tokens;

COMMENT ON COLUMN scan_point_capabilities.enabled IS NULL;

COMMIT;
