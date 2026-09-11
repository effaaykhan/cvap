-- Down migration for 0042_credential_profile_ssh_fields.
-- Drops the two additive columns. Safe: no other object depends on them.

BEGIN;

ALTER TABLE credential_profiles DROP COLUMN IF EXISTS known_hosts;
ALTER TABLE credential_profiles DROP COLUMN IF EXISTS username;

COMMIT;
