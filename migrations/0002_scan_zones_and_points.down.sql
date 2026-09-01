-- Down migration for 0002_scan_zones_and_points

BEGIN;

REVOKE ALL ON scan_zones, network_ranges, scan_points, scan_point_capabilities FROM cvap_app;

DROP TABLE IF EXISTS scan_point_capabilities;
DROP TABLE IF EXISTS scan_points;
DROP TABLE IF EXISTS network_ranges;
DROP TABLE IF EXISTS scan_zones;

DROP TYPE IF EXISTS engine_kind;
DROP TYPE IF EXISTS scan_point_status;
DROP TYPE IF EXISTS zone_type;

COMMIT;
