-- Down migration for 0045_rotation_states
--
-- PostgreSQL cannot drop an enum value, so each type is rebuilt without it.
-- Rows carrying the new value are rewritten first to the nearest older word:
-- a 'rotation' key was recorded by an ATTACH verdict; a 'rotated' queue item
-- has resolved_asset_id set (the asset it attached to), which is what 'merged'
-- requires (asset_resolution_queue_merged_has_asset).

BEGIN;

-- A rotation-recorded key is excluded from the credentialed trust root BY its
-- provenance (ADR-096). Relabelled as 'attach' it would silently become trust
-- material at two sightings on the next upgrade, so it is RETIRED first: the
-- next scan re-records whatever answers, as a first sighting. The relabel
-- below is then lineage only.
UPDATE asset_identity_keys SET valid_to = now() WHERE provenance::text IN ('rotation', 'lapsed') AND valid_to IS NULL;
UPDATE asset_identity_keys SET provenance = 'attach' WHERE provenance::text = 'rotation';
UPDATE asset_identity_keys SET provenance = 'new_asset' WHERE provenance::text = 'lapsed';

ALTER TYPE identity_key_provenance RENAME TO identity_key_provenance_old;
CREATE TYPE identity_key_provenance AS ENUM ('merge', 'new_asset', 'attach', 'unknown');
ALTER TABLE asset_identity_keys
    ALTER COLUMN provenance TYPE identity_key_provenance
    USING provenance::text::identity_key_provenance;
DROP TYPE identity_key_provenance_old;

-- Compared as text so the rewrite also runs on a database that applied an
-- earlier draft of this migration without one of the labels.
UPDATE asset_resolution_queue SET state = 'merged' WHERE state::text = 'rotated';
-- An expired item chose nothing; 'discarded' (evidence unusable) is the nearest
-- older word. resolved_by NULL is the tell that no operator did it.
UPDATE asset_resolution_queue SET state = 'discarded' WHERE state::text = 'expired';

-- The partial indexes and the two CHECK constraints name the column against a
-- literal of the old type; a column type change cannot carry them, so they are
-- dropped and recreated exactly as 0013 and 0044 wrote them.
DROP INDEX IF EXISTS asset_identity_keys_one_live_per_port_uidx;
-- An item naming no candidate cannot exist under 0013's CHECK: it is DELETED
-- (its observations stay unresolved and are re-swept by the older code).
DELETE FROM asset_resolution_queue WHERE cardinality(candidate_asset_ids) = 0;
ALTER TABLE asset_resolution_queue
    DROP CONSTRAINT IF EXISTS asset_resolution_queue_candidates_non_empty,
    ADD CONSTRAINT asset_resolution_queue_candidates_non_empty
        CHECK (cardinality(candidate_asset_ids) > 0);
DROP INDEX IF EXISTS asset_resolution_queue_pending_address_idx;
ALTER TABLE asset_resolution_queue DROP COLUMN IF EXISTS address;
DROP INDEX IF EXISTS asset_resolution_queue_pending_idx;
DROP INDEX IF EXISTS asset_resolution_queue_pending_obs_idx;
ALTER TABLE asset_resolution_queue
    DROP CONSTRAINT IF EXISTS asset_resolution_queue_rotated_has_asset,
    DROP CONSTRAINT IF EXISTS asset_resolution_queue_resolution_consistent,
    DROP CONSTRAINT IF EXISTS asset_resolution_queue_merged_has_asset;

ALTER TYPE resolution_state RENAME TO resolution_state_old;
CREATE TYPE resolution_state AS ENUM ('pending', 'merged', 'new_asset', 'discarded');
ALTER TABLE asset_resolution_queue
    ALTER COLUMN state DROP DEFAULT,
    ALTER COLUMN state TYPE resolution_state USING state::text::resolution_state,
    ALTER COLUMN state SET DEFAULT 'pending';
DROP TYPE resolution_state_old;

ALTER TABLE asset_resolution_queue
    ADD CONSTRAINT asset_resolution_queue_resolution_consistent
        CHECK ((state = 'pending') = (resolved_at IS NULL)),
    ADD CONSTRAINT asset_resolution_queue_merged_has_asset
        CHECK (state <> 'merged' OR resolved_asset_id IS NOT NULL);

CREATE INDEX asset_resolution_queue_pending_idx
    ON asset_resolution_queue (tenant_id, enqueued_at)
    WHERE state = 'pending';
CREATE INDEX asset_resolution_queue_pending_obs_idx
    ON asset_resolution_queue (tenant_id, observation_id)
    WHERE state = 'pending';

COMMIT;
