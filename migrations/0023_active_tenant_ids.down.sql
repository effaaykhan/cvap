-- Down migration for 0023_active_tenant_ids

BEGIN;
DROP FUNCTION IF EXISTS active_tenant_ids();
COMMIT;
