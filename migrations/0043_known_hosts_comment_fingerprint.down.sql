-- 0043_known_hosts_comment_fingerprint (down): restore 0042's wording.
BEGIN;

COMMENT ON COLUMN credential_profiles.known_hosts IS
    'Operator-pinned host-key lines, verified in-memory by the engine (ADR-086). NULL = use the host key CVAP observed for the target (asset_identity_keys, key_type = ''ssh_hostkey''). Not a secret.';

COMMIT;
