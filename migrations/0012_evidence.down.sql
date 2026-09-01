-- Down migration for 0012_evidence

BEGIN;

REVOKE ALL ON evidence FROM cvap_app;

DROP TABLE IF EXISTS evidence;

DROP TYPE IF EXISTS evidence_type;

COMMIT;
