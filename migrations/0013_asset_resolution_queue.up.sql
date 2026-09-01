-- 0013_asset_resolution_queue
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- ADR-007's unresolved queue. Not in the v2 ERD; recorded in ADR-029.
--
-- Conflicting or insufficient identity evidence sends the observation here for
-- operator review rather than guessing. That is the whole point of the ranked-
-- key scheme: a wrong merge corrupts history — findings, exposures and
-- timelines from two hosts are interleaved, and after the fact nobody can tell
-- which is which. The unresolved queue costs operator attention; a wrong merge
-- costs trust in the inventory.
--
-- A table and not a column on observations, for three reasons:
--   - Observations are immutable. Adjudication state changes.
--   - Observations are ephemeral. An unworked queue item that vanishes after 90
--     days has not been resolved, it has been forgotten.
--   - "asset_id IS NULL" means "not yet correlated", which is the normal state
--     of a freshly ingested row. It does not mean "correlation failed and needs
--     a human", and conflating the two makes the queue unreadable.
--
-- After findings, because it is operator-facing surface rather than part of the
-- ingest or correlation path.

BEGIN;

CREATE TYPE resolution_state AS ENUM (
    'pending',      -- awaiting operator adjudication
    'merged',       -- operator chose a candidate
    'new_asset',    -- operator judged this a distinct asset
    'discarded'     -- operator judged the evidence unusable
);

CREATE TABLE asset_resolution_queue (
    resolution_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK to the resolved asset (ADR-017);
    -- see users.tenant_id in 0001. Here it also bounds the candidate set: an
    -- operator adjudicating a merge must never be shown a candidate from
    -- another tenant, and the FK on resolved_asset_id makes choosing one
    -- impossible rather than merely unlikely.
    tenant_id              uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    -- Soft reference, no FK, for the same reason evidence.observation_id is one
    -- (ADR-016): the observation's partition drops on the 90-day clock and a
    -- hard FK would block or fail that drop.
    observation_id         uuid,

    -- ...so the evidence is COPIED here at enqueue time, exactly as ADR-007
    -- copies merge evidence into asset_identity_keys. A queue item must remain
    -- adjudicable after the observation that raised it has aged out, or the
    -- queue silently empties itself of anything older than 90 days.
    --
    -- Redact this copy to the same standard as the observation it came from.
    observed_payload       jsonb NOT NULL,

    -- What was seen, and what it conflicted with. Both copied, not referenced.
    key_type               identity_key_type NOT NULL,
    key_value              text NOT NULL,

    -- The assets this evidence could plausibly belong to. An array rather than
    -- a child table: the set is small, written once at enqueue, and read whole.
    -- Not a foreign key — an array cannot carry one — so the adjudication path
    -- must re-check each candidate still exists and is in this tenant. The
    -- composite FK on resolved_asset_id is what enforces the tenant bound at
    -- the moment the decision is committed, which is the moment that matters.
    candidate_asset_ids    uuid[] NOT NULL,

    -- Why it could not be decided automatically. Free text is right here: this
    -- is read by a human deciding a judgement call, not matched on.
    conflict_reason        text NOT NULL,

    state                  resolution_state NOT NULL DEFAULT 'pending',
    resolved_asset_id      uuid,
    resolved_by            uuid,
    enqueued_at            timestamptz NOT NULL DEFAULT now(),
    resolved_at            timestamptz,

    CONSTRAINT asset_resolution_queue_tenant_resolution_key
        UNIQUE (tenant_id, resolution_id),

    CONSTRAINT asset_resolution_queue_resolved_asset_fk
        FOREIGN KEY (tenant_id, resolved_asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE SET NULL (resolved_asset_id),

    -- Column-list SET NULL (Postgres 15+); a bare SET NULL would null tenant_id
    -- too. A departed operator must not erase who adjudicated a merge.
    CONSTRAINT asset_resolution_queue_resolved_by_fk
        FOREIGN KEY (tenant_id, resolved_by)
        REFERENCES users (tenant_id, user_id) ON DELETE SET NULL (resolved_by),

    CONSTRAINT asset_resolution_queue_candidates_non_empty
        CHECK (cardinality(candidate_asset_ids) > 0),

    -- Pending means undecided; anything else means decided, by someone, at a
    -- time. An item that claims resolution without a timestamp is one nobody
    -- can audit.
    CONSTRAINT asset_resolution_queue_resolution_consistent
        CHECK ((state = 'pending') = (resolved_at IS NULL)),

    -- Only a merge picks an asset.
    CONSTRAINT asset_resolution_queue_merged_has_asset
        CHECK (state <> 'merged' OR resolved_asset_id IS NOT NULL)
);

COMMENT ON TABLE asset_resolution_queue IS
    'ADR-007 unresolved merge queue. Not drawn in the v2 ERD; see ADR-029. Evidence is copied at enqueue, not referenced, so an item outlives the observation partition that raised it (ADR-016).';

-- The queue itself: what needs a human, oldest first.
CREATE INDEX asset_resolution_queue_pending_idx
    ON asset_resolution_queue (tenant_id, enqueued_at)
    WHERE state = 'pending';

-- "Has this key already been queued" — checked before enqueuing another item
-- for the same evidence, so one flapping key does not become a thousand queue
-- entries.
CREATE INDEX asset_resolution_queue_by_key_idx
    ON asset_resolution_queue (tenant_id, key_type, key_value);

ALTER TABLE asset_resolution_queue ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_resolution_queue FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_resolution_queue_tenant_isolation ON asset_resolution_queue
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE ON asset_resolution_queue TO cvap_app;

COMMIT;
