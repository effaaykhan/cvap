-- Down migration for 0011_findings

BEGIN;

REVOKE ALL ON findings, finding_exposure, finding_history, remediations FROM cvap_app;

DROP TABLE IF EXISTS remediations;
DROP TABLE IF EXISTS finding_history;
DROP TABLE IF EXISTS finding_exposure;
DROP TABLE IF EXISTS findings;

DROP TYPE IF EXISTS remediation_status;
DROP TYPE IF EXISTS finding_source;
DROP TYPE IF EXISTS finding_status;

COMMIT;
