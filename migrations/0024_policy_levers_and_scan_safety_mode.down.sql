-- Down migration for 0024_policy_levers_and_scan_safety_mode

BEGIN;

COMMENT ON COLUMN scan_tasks.task_target IS NULL;

DROP TRIGGER IF EXISTS scan_policies_allowed_zones_are_uuids ON scan_policies;
DROP FUNCTION IF EXISTS scan_policies_allowed_zones_are_uuids();

DROP TRIGGER IF EXISTS scans_safety_mode_within_policy ON scans;
DROP FUNCTION IF EXISTS scans_safety_mode_within_policy();

ALTER TABLE scans DROP COLUMN IF EXISTS safety_mode;

DROP INDEX IF EXISTS scan_policies_windowed_idx;

ALTER TABLE scan_policies
    DROP CONSTRAINT IF EXISTS scan_policies_time_windows_bounded;
ALTER TABLE scan_policies
    DROP CONSTRAINT IF EXISTS scan_policies_allowed_zones_is_array;
ALTER TABLE scan_policies
    DROP CONSTRAINT IF EXISTS scan_policies_time_windows_is_array;

-- The COMMENTs on time_windows and allowed_zones go with them: the columns
-- survive this rollback, and a comment describing a convention the code no
-- longer implements is worse than none.
COMMENT ON COLUMN scan_policies.time_windows IS NULL;
COMMENT ON COLUMN scan_policies.allowed_zones IS NULL;

ALTER TABLE scan_policies
    DROP CONSTRAINT IF EXISTS scan_policies_concurrency_lower_only;
ALTER TABLE scan_policies DROP COLUMN IF EXISTS max_concurrent_per_target;

COMMIT;
