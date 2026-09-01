-- Down migration for 0005_scan_execution

BEGIN;

REVOKE ALL ON scans, scan_targets, scan_jobs, job_leases, scan_tasks FROM cvap_app;

DROP TABLE IF EXISTS scan_tasks;
DROP TABLE IF EXISTS job_leases;
DROP TABLE IF EXISTS scan_jobs;
DROP TABLE IF EXISTS scan_targets;
DROP TABLE IF EXISTS scans;

DROP TYPE IF EXISTS lease_state;
DROP TYPE IF EXISTS termination_reason;
DROP TYPE IF EXISTS task_status;
DROP TYPE IF EXISTS job_status;
DROP TYPE IF EXISTS scan_target_type;
DROP TYPE IF EXISTS scan_status;

COMMIT;
