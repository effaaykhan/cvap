-- Down migration for 0021_task_asset_link

BEGIN;

DROP INDEX IF EXISTS scan_tasks_asset_idx;
ALTER TABLE scan_tasks DROP CONSTRAINT IF EXISTS scan_tasks_asset_fk;
ALTER TABLE scan_tasks DROP COLUMN IF EXISTS asset_id;

COMMIT;
