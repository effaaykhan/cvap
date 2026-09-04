-- 0032_builtin_rule_pack (down)
--
-- Written in the same sitting as the up.
--
-- Deleting rules is a RESTRICT-guarded operation: findings.rule_id is
-- ON DELETE RESTRICT (migration 0011), because a finding with no rule is
-- unexplainable and ADR-009 makes rule_id mandatory. So this down FAILS if any
-- finding references a built-in rule, which is correct: you cannot roll back the
-- rule that raised a finding that still exists. Resolve or delete those findings
-- first — the down migration will not orphan them.

BEGIN;

DELETE FROM rules
 WHERE rule_pack_id = '00000000-0000-0000-0000-0000000000c6';

DELETE FROM rule_packs
 WHERE rule_pack_id = '00000000-0000-0000-0000-0000000000c6';

COMMIT;
