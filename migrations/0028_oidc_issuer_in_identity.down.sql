BEGIN;

DROP INDEX IF EXISTS users_tenant_oidc_identity_key;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_oidc_identity_complete;
ALTER TABLE users DROP COLUMN IF EXISTS oidc_issuer;

CREATE UNIQUE INDEX users_tenant_oidc_subject_key
    ON users (tenant_id, oidc_subject)
    WHERE oidc_subject IS NOT NULL;

COMMIT;
