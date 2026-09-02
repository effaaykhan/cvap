-- 0020_observation_pending_state
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- A third ingest state, and a ratchet.
--
-- ============================================================================
-- Why two states were not enough.
-- ============================================================================
--
-- A submission arrives in chunks, and its lease epoch can be superseded midway:
-- chunk 0 checks out, chunk 5 arrives after a reassignment. With only accepted
-- and quarantined, chunk 0's observations are inserted as ACCEPTED and the
-- finding pipeline — which filters exactly on that — can read them before chunk
-- 5 ever arrives. Quarantining retrospectively narrows the window; it does not
-- close it, because the pipeline may already have run.
--
-- So chunks land as PENDING. The terminal ack promotes the whole submission to
-- accepted or quarantined in one statement, inside the same transaction as the
-- final epoch check. The pipeline filters `accepted`, so an in-flight submission
-- is invisible to it WITHOUT the pipeline knowing submissions exist — no join to
-- remember on the largest table in the system, and no window to narrow.
--
-- The ratchet: pending may become either. accepted and quarantined are terminal.
-- That keeps the property migration 0016 was protecting — the pipeline cannot
-- clear the flag it filters on — while letting ingest set it.
--
-- Consequence, stated here because it is real and permanent: an abandoned upload
-- leaves rows pending forever. That is CORRECT — the results were never
-- attested complete, and deleting them would discard the record of what a job
-- touched (ADR-026). It needs a metric rather than a cleanup, and
-- Observations.PendingOlderThan is that metric's query.

BEGIN;

DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION 'Role cvap_app can bypass RLS (ADR-002). Fix: ALTER ROLE cvap_app NOBYPASSRLS NOSUPERUSER;';
    END IF;
END
$$;

-- ADD VALUE cannot run in a transaction block that created the type, but this
-- type was created in migration 0009, so it is fine here. BEFORE 'accepted'
-- only for readability in \dT+; enum order carries no meaning in this schema.
ALTER TYPE observation_ingest_state ADD VALUE IF NOT EXISTS 'pending' BEFORE 'accepted';

COMMIT;

-- A new enum value is not usable in the same transaction that added it, so the
-- ratchet and the default land in a second one.
BEGIN;

-- Chunks land pending. The default changes so that an INSERT which forgets to
-- name the column is invisible to the pipeline rather than visible to it — the
-- safe direction for the value that decides what gets processed.
ALTER TABLE observations ALTER COLUMN ingest_state SET DEFAULT 'pending';

CREATE OR REPLACE FUNCTION observations_ingest_state_ratchet()
RETURNS trigger
LANGUAGE plpgsql
SET search_path = pg_catalog, public
AS $$
BEGIN
    -- pending -> anything is the promotion ingest performs.
    IF OLD.ingest_state = 'pending' THEN
        RETURN NEW;
    END IF;

    -- Terminal states never move. This is the whole control: the finding
    -- pipeline runs as the same database role as ingest, so a grant alone
    -- cannot express "ingest may set this and the pipeline may not". A ratchet
    -- can, because un-quarantining is not an operation anything legitimately
    -- performs.
    IF NEW.ingest_state IS DISTINCT FROM OLD.ingest_state THEN
        RAISE EXCEPTION
            'observations.ingest_state is a ratchet: % -> % is not permitted (ADR-026). '
            'pending may be promoted once; accepted and quarantined are terminal.',
            OLD.ingest_state, NEW.ingest_state
            USING ERRCODE = 'check_violation';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER observations_ingest_state_ratchet
    BEFORE UPDATE OF ingest_state ON observations
    FOR EACH ROW
    EXECUTE FUNCTION observations_ingest_state_ratchet();

COMMENT ON COLUMN observations.ingest_state IS
    'pending on insert; promoted once to accepted or quarantined by the terminal ack, in the same transaction as the final epoch check. A ratchet trigger refuses every other transition, so the finding pipeline cannot clear the flag it filters on (ADR-026). An abandoned upload stays pending forever, which is correct — see Observations.PendingOlderThan.';

-- Widened by exactly one column from migration 0016. asset_id for correlation,
-- ingest_state for the promotion; payload, zone_id and observed_at stay
-- unwritable, because an immutable record whose content can be edited is not
-- evidence.
GRANT UPDATE (asset_id, ingest_state) ON observations TO cvap_app;

-- The pending backlog: what a health surface counts to notice an ingest that
-- stopped halfway.
CREATE INDEX observations_pending_idx ON observations (tenant_id, observed_at)
    WHERE ingest_state = 'pending';

COMMIT;
