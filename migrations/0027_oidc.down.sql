BEGIN;

DROP TABLE IF EXISTS oidc_auth_requests;
DROP INDEX IF EXISTS users_tenant_oidc_subject_key;
ALTER TABLE users DROP COLUMN IF EXISTS oidc_subject;

COMMIT;
