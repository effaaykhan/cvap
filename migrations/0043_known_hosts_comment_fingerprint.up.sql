-- 0043_known_hosts_comment_fingerprint
--
-- Comment-only. Migration 0042 described the fallback for a NULL known_hosts as
-- "the host key CVAP already observed ... the key in key_value". Building the
-- fleet path against the real column showed that what discovery stores in
-- asset_identity_keys.key_value for ssh_hostkey is the SHA256 FINGERPRINT of the
-- host key, never the key itself (ADR-091 §1), and the engine verifies by
-- fingerprint. 0042 is applied and frozen, so the correction is a new COMMENT.
--
-- No table, no column, no policy changes. Nothing here is tenant-scoped data.

BEGIN;

COMMENT ON COLUMN credential_profiles.known_hosts IS
    'Operator-pinned host-key lines, verified in-memory by the engine (ADR-086). NULL = use the SHA256 host-key FINGERPRINT CVAP observed for the target (asset_identity_keys, key_type = ''ssh_hostkey''; key_value is a fingerprint, not a key — ADR-091). Not a secret. On the wire the source travels as a header line (internal/hostkeytrust).';

COMMIT;
