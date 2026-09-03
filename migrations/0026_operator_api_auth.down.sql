BEGIN;

DROP FUNCTION IF EXISTS tenant_for_domain(text);
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS user_credentials;
DROP TABLE IF EXISTS tenant_auth_config;
DROP TYPE IF EXISTS auth_method;

DROP INDEX IF EXISTS tenants_domain_key;
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_domain_is_a_hostname;
ALTER TABLE tenants DROP CONSTRAINT IF EXISTS tenants_domain_lowercase;
ALTER TABLE tenants DROP COLUMN IF EXISTS domain;

COMMIT;
