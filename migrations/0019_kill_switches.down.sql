-- Down migration for 0019_kill_switches

BEGIN;

REVOKE ALL ON kill_acks FROM cvap_app;
REVOKE ALL ON kill_switches FROM cvap_app;

DROP TABLE IF EXISTS kill_acks;
DROP TABLE IF EXISTS kill_switches;

DROP TYPE IF EXISTS kill_scope;

COMMIT;
