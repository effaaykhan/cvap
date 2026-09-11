-- 0042_credential_profile_ssh_fields
--
-- The fleet credentialed-host path (ADR-086/090, Phase 4) needs two non-secret
-- facts a credential profile did not carry: which user to authenticate as, and —
-- optionally — an operator-pinned set of host keys to verify the target against.
-- Neither is a secret (the key material stays behind secret_ref, ADR-020), so both
-- are plain columns here rather than anything fetched at grant time.
--
-- Additive columns on an existing tenant-scoped table. credential_profiles already
-- carries tenant_id, its RLS policy and its grants (migration 0004); nothing about
-- the isolation of the table changes, so this file adds columns only.
--
-- Run schema-auditor before merging.

BEGIN;

-- The SSH user the runtime authenticates as. Nullable: only ssh-family profiles use
-- it, and a winrm/snmp/cloud/api profile has no ssh user. The runtime refuses a
-- host job whose profile has no username rather than guessing one.
ALTER TABLE credential_profiles ADD COLUMN username text;

-- Operator-pinned known_hosts lines ("host keytype base64"), verified in-memory by
-- the engine (ADR-086, no in-engine TOFU). NULL means "no operator override" — the
-- fleet path then supplies the host key CVAP already observed for the target
-- (asset_identity_keys where key_type = 'ssh_hostkey', the key in key_value). When
-- set, it takes precedence, so an operator can pin a trust root that does not depend
-- on what discovery happened to see.
ALTER TABLE credential_profiles ADD COLUMN known_hosts text;

COMMENT ON COLUMN credential_profiles.username IS
    'SSH (or other cred-family) user the runtime authenticates as. Not a secret. NULL for profiles whose type has no user; the runtime refuses a host job that needs one and has none.';

COMMENT ON COLUMN credential_profiles.known_hosts IS
    'Operator-pinned host-key lines, verified in-memory by the engine (ADR-086). NULL = use the host key CVAP observed for the target (asset_identity_keys, key_type = ''ssh_hostkey''). Not a secret.';

COMMIT;
