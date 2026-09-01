-- Down migration for 0003_scan_policies

BEGIN;

REVOKE ALL ON scan_policies, policy_scope_rules FROM cvap_app;

DROP TABLE IF EXISTS policy_scope_rules;
DROP TABLE IF EXISTS scan_policies;

DROP TYPE IF EXISTS scope_match_type;
DROP TYPE IF EXISTS scope_rule_effect;
DROP TYPE IF EXISTS safety_mode;

COMMIT;
