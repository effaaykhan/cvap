-- Down: remove the seeded advisory-version-match rule. The 'advisory' engine_kind
-- value it uses is dropped by 0038's down only in a full rollback (via 0002); see
-- 0038_advisory_engine_kind.down.sql.
BEGIN;

DELETE FROM rules
 WHERE rule_pack_id = '00000000-0000-0000-0000-0000000000c6'
   AND name = 'advisory-version-match';

COMMIT;
