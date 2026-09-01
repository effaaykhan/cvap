-- Down migration for 0014_reports_and_audit

BEGIN;

REVOKE ALL ON reports, audit_events FROM cvap_app;

DROP TABLE IF EXISTS audit_events;
DROP TABLE IF EXISTS reports;

DROP TYPE IF EXISTS actor_type;

COMMIT;
