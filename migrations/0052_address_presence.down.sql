-- Remove the presence verdict columns 0052 added.
--
-- A faithful inverse: the verdicts are re-derivable. ADR-108 decision 7 makes the
-- rule PURE and keeps it in internal/domain precisely so it can be replayed over
-- stored observations without re-scanning a network — so dropping the recorded
-- answers loses a cache, not evidence. That is the test for whether a down
-- migration may drop rather than refuse, and this one passes it.
--
-- The index and both CHECK constraints go with the columns automatically:
-- Postgres drops a constraint and an index that reference only dropped columns.
-- Stated because the previous migration in this series assumed a cascade it had
-- not checked, and the check costs one sentence.

BEGIN;

ALTER TABLE asset_addresses
    DROP COLUMN presence,
    DROP COLUMN presence_reason,
    DROP COLUMN presence_decided_at;

COMMIT;
