-- Down: the 'advisory' engine_kind value is deliberately LEFT in place.
--
-- Postgres has no ALTER TYPE DROP VALUE, and recreating the enum without it would
-- mean dropping every column that uses engine_kind. Leaving an unused enum value
-- is harmless, and the up's ADD VALUE IF NOT EXISTS makes a re-up a no-op. A full
-- rollback drops the type entirely via 0002's down, so migrate-verify still round
-- trips. Same pattern as 0034 leaving the knowledge-import role when it cannot be
-- dropped cleanly.
SELECT 1;
