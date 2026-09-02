-- Down migration for 0025_cancel_acks

BEGIN;

DROP TABLE IF EXISTS cancel_acks;

ALTER TABLE scans DROP COLUMN IF EXISTS cancel_requested_at;

COMMIT;
