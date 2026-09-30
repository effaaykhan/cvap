-- Remove the delivery fact 0053 added.
--
-- The column, both CHECK constraints and the partial index go with it: Postgres
-- drops a constraint and an index that reference only a dropped column. Stated
-- rather than assumed, because 0050's first draft assumed a cascade it had not
-- checked.
--
-- What rolling back loses is real and not re-derivable: `delivered_at` records
-- whether a secret actually reached a scan point, and nothing else in the schema
-- holds that fact — `delivered_to_fingerprint` is the intended recipient, fixed
-- at issue. A rollback therefore returns the database to the state where
-- "issued but never delivered" cannot be expressed, which is the state B52
-- measured as wrong. That is acceptable for a schema rollback and is NOT
-- acceptable as a resting state.

BEGIN;

ALTER TABLE credential_grants DROP COLUMN delivered_at;

COMMIT;
