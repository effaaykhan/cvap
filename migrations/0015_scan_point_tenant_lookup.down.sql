-- Down migration for 0015_scan_point_tenant_lookup

BEGIN;

REVOKE ALL ON FUNCTION tenant_for_scan_point(text) FROM cvap_app;
DROP FUNCTION IF EXISTS tenant_for_scan_point(text);

-- Restore the type comment to its prior state (none). The type itself was
-- created in 0002 and is not dropped here.
COMMENT ON TYPE scan_point_status IS NULL;

COMMIT;
