-- Down migration for 0008_result_submissions

BEGIN;

REVOKE ALL ON result_submissions FROM cvap_app;

DROP TABLE IF EXISTS result_submissions;

DROP TYPE IF EXISTS submit_status;

COMMIT;
