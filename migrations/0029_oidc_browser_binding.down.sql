BEGIN;
ALTER TABLE oidc_auth_requests DROP COLUMN IF EXISTS browser_hash;
COMMIT;
