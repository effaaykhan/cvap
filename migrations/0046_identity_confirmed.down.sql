-- Down migration for 0046_identity_confirmed
--
-- PostgreSQL cannot drop an enum value, so the type is rebuilt without it —
-- with the SIX labels 0045 left: a later migration that adds a seventh must
-- extend this list, or a rollback of 0046 drops that label silently. A
-- 'confirmed' key was an operator's decision: relabelled 'attach' it stays
-- trust material under 0045's reads (only rotation/lapsed are excluded), which
-- is what the operator chose; the decision itself survives in audit_events.

BEGIN;

ALTER TABLE asset_resolution_queue DROP CONSTRAINT IF EXISTS asset_resolution_queue_keyed_has_source;
ALTER TABLE asset_resolution_queue DROP COLUMN IF EXISTS source;

UPDATE asset_identity_keys SET provenance = 'attach' WHERE provenance::text = 'confirmed';

ALTER TYPE identity_key_provenance RENAME TO identity_key_provenance_old;
CREATE TYPE identity_key_provenance AS ENUM ('merge', 'new_asset', 'attach', 'unknown', 'rotation', 'lapsed');
ALTER TABLE asset_identity_keys
    ALTER COLUMN provenance TYPE identity_key_provenance
    USING provenance::text::identity_key_provenance;
DROP TYPE identity_key_provenance_old;

COMMIT;
