-- Down migration for 0018_scan_point_certificates

BEGIN;

REVOKE ALL ON scan_point_certificates FROM cvap_app;

DROP TABLE IF EXISTS scan_point_certificates;

DROP TYPE IF EXISTS certificate_supersede_reason;

COMMIT;
