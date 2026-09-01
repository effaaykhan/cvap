-- Down migration for 0006_credential_grants

BEGIN;

REVOKE ALL ON credential_grants FROM cvap_app;

DROP TABLE IF EXISTS credential_grants;

DROP TYPE IF EXISTS cred_kind;

COMMIT;
