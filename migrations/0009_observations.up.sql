-- 0009_observations
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- The growth vector of the entire system, and the only partitioned table in it.
--
-- Partitioned by month from creation, because retrofitting partitioning onto a
-- populated table means downtime and there is no second chance (ADR-016). Raw
-- observations retain 90 days by default; pruning is a partition drop, not a
-- bulk delete.
--
-- The governing rule this table sits under:
--
--   Observations are ephemeral. Anything that must outlive them is copied at
--   the moment it becomes load-bearing.
--
-- Which is why asset_identity_keys copies its merge payload (0007) and evidence
-- copies its finding payload (0012), rather than either referencing a row here.

BEGIN;

-- Closed set. The wire contract deliberately carries observation_type as an
-- open string — engines are extensible by design (ADR-027) and a closed wire
-- enum would make every new observation type a protocol change — and Core
-- validates the string against THIS type at ingest, returning
-- REJECTED_MALFORMED for an unknown one. That arrangement is spelled out in
-- ingest.proto, which also says: do not tighten the wire field to an enum
-- later. This type is the closed half of it.
CREATE TYPE observation_type AS ENUM (
    'host', 'port', 'service', 'banner', 'package', 'config', 'verdict'
);

-- ADR-026: accepted_quarantined means stored, withheld from the finding
-- pipeline, operator-surfaced. This is the flag the pipeline filters on.
CREATE TYPE observation_ingest_state AS ENUM ('accepted', 'quarantined');

CREATE TABLE observations (
    -- Generated at the scan point and stable across retries. uuid rather than
    -- the wire's string because the ERD types it so and ingest validates it;
    -- a non-UUID value is REJECTED_MALFORMED, the same handling an unknown
    -- observation_type gets. (result_submissions.submission_id is text for the
    -- opposite reason: the ERD does not type it, and a scan point's local
    -- submission counter need not be a UUID.)
    observation_id   uuid NOT NULL,

    tenant_id        uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    -- The idempotency boundary. Note what this column does NOT do: a unique
    -- index on a partitioned table must contain the partition key, so
    -- observation_id cannot be made globally unique here. Deduplication happens
    -- at the submission boundary against result_submissions.submission_id
    -- instead, which is precisely why ADR-026 puts idempotency at the boundary
    -- rather than downstream.
    submission_id    text NOT NULL,

    -- The unit of attribution (ADR-011). Every observation traces to a task,
    -- every task to a job, every job to a scan.
    task_id          uuid NOT NULL,

    scan_point_id    uuid NOT NULL,

    -- Vantage point, and the reason there is no zone column on assets
    -- (ADR-008). What has a vantage point is the act of seeing, not the thing
    -- seen. Exposure is derived from which zones saw what.
    --
    -- Self-asserted on the wire, and the field where that matters most: a scan
    -- point free to name its own zone could rewrite the derived exposure of
    -- every asset it reports. Core MUST validate this against the zones the
    -- authenticated scan point was enrolled into; a mismatch quarantines, and
    -- is never silently re-zoned.
    zone_id          uuid NOT NULL,

    -- Nullable until resolved. NULL is the normal state on arrival: correlation
    -- runs after ingest, and a scan point never resolves an asset — it emits
    -- observations and nothing else (ADR-006).
    asset_id         uuid,

    observation_type observation_type NOT NULL,
    payload          jsonb NOT NULL,
    confidence       numeric(4,3),
    observed_at      timestamptz NOT NULL,

    -- Written at INSERT and never updated. Observations are immutable, so this
    -- is a fact about how the row arrived rather than mutable state — do not
    -- add an UPDATE path for it. The reason for a quarantine lives once on
    -- result_submissions, not repeated across every row of a chunk stream.
    ingest_state     observation_ingest_state NOT NULL DEFAULT 'accepted',

    -- The partition key must be in the primary key. observation_id alone is not
    -- available for that reason; see the submission_id note above.
    PRIMARY KEY (observation_id, observed_at),

    CONSTRAINT observations_submission_fk FOREIGN KEY (tenant_id, submission_id)
        REFERENCES result_submissions (tenant_id, submission_id) ON DELETE CASCADE,

    CONSTRAINT observations_task_fk FOREIGN KEY (tenant_id, task_id)
        REFERENCES scan_tasks (tenant_id, task_id) ON DELETE CASCADE,

    CONSTRAINT observations_scan_point_fk FOREIGN KEY (tenant_id, scan_point_id)
        REFERENCES scan_points (tenant_id, scan_point_id) ON DELETE RESTRICT,

    CONSTRAINT observations_zone_fk FOREIGN KEY (tenant_id, zone_id)
        REFERENCES scan_zones (tenant_id, zone_id) ON DELETE RESTRICT,

    -- Column-list SET NULL (Postgres 15+): a bare SET NULL on a composite FK
    -- would null tenant_id too, which is NOT NULL. An asset deleted after a
    -- merge correction leaves its observations behind, unresolved, which is the
    -- correct outcome — the observation is still a true record of what was seen.
    CONSTRAINT observations_asset_fk FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE SET NULL (asset_id),

    CONSTRAINT observations_confidence_range
        CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1)
) PARTITION BY RANGE (observed_at);

COMMENT ON TABLE observations IS
    'Immutable, ephemeral, partitioned monthly. 90-day default retention, pruned by partition drop (ADR-016). Written only by ingest; never updated.';

-- ---------------------------------------------------------------------------
-- Indexes
-- ---------------------------------------------------------------------------
-- Declared on the parent; Postgres propagates them to every partition,
-- existing and future.

-- Ingest attribution, and the skill's named must-have.
CREATE INDEX observations_task_observed_idx ON observations (task_id, observed_at);

-- Correlation: everything seen about this asset, newest first.
CREATE INDEX observations_asset_idx ON observations (tenant_id, asset_id, observed_at DESC);

-- Exposure derivation (ADR-008): which vantage points saw what, and when.
CREATE INDEX observations_zone_idx ON observations (tenant_id, zone_id, observed_at DESC);

-- The unresolved backlog correlation walks. Partial, because resolved rows are
-- the overwhelming majority once correlation has run.
CREATE INDEX observations_unresolved_idx ON observations (tenant_id, observed_at)
    WHERE asset_id IS NULL;

-- The operator queue. Small set, human-read.
CREATE INDEX observations_quarantined_idx ON observations (tenant_id, observed_at DESC)
    WHERE ingest_state = 'quarantined';

-- ---------------------------------------------------------------------------
-- Partitions
-- ---------------------------------------------------------------------------
-- Seeded six months ahead. Partition creation MUST be automated: a missing
-- future partition is an ingest outage, which is the failure mode ADR-016 names
-- explicitly.
--
-- The DEFAULT partition is a safety net, not a destination. It catches rows
-- that would otherwise fail to insert, and monitoring should alert if it is
-- ever non-empty — note that attaching a new partition whose range overlaps
-- rows sitting in the default requires a full scan of the default and will
-- fail if any conflict, so a non-empty default makes the next month's partition
-- creation harder, not easier.

CREATE TABLE observations_2026_09 PARTITION OF observations
    FOR VALUES FROM ('2026-09-01 00:00:00+00') TO ('2026-10-01 00:00:00+00');
CREATE TABLE observations_2026_10 PARTITION OF observations
    FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');
CREATE TABLE observations_2026_11 PARTITION OF observations
    FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');
CREATE TABLE observations_2026_12 PARTITION OF observations
    FOR VALUES FROM ('2026-12-01 00:00:00+00') TO ('2027-01-01 00:00:00+00');
CREATE TABLE observations_2027_01 PARTITION OF observations
    FOR VALUES FROM ('2027-01-01 00:00:00+00') TO ('2027-02-01 00:00:00+00');
CREATE TABLE observations_2027_02 PARTITION OF observations
    FOR VALUES FROM ('2027-02-01 00:00:00+00') TO ('2027-03-01 00:00:00+00');

CREATE TABLE observations_default PARTITION OF observations DEFAULT;

-- ---------------------------------------------------------------------------
-- RLS
-- ---------------------------------------------------------------------------
-- On the parent AND on every partition.
--
-- Not belt-and-braces: a policy on the parent applies when a query goes through
-- the parent, but a query naming a partition directly is governed by that
-- partition's own policies. Application code goes through the parent, so the
-- parent policy is what normally runs — but "normally" is not a security
-- boundary, and a maintenance query or a future reader that touches a partition
-- by name would otherwise be unfiltered.
--
-- The loop below is also the template the partition-creation automation must
-- follow. A new monthly partition without these four statements is a partition
-- with no tenant isolation.

ALTER TABLE observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE observations FORCE ROW LEVEL SECURITY;
CREATE POLICY observations_tenant_isolation ON observations
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

DO $$
DECLARE
    part text;
BEGIN
    FOR part IN
        SELECT c.relname
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        JOIN pg_class p ON p.oid = i.inhparent
        WHERE p.relname = 'observations'
    LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', part);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', part);
        EXECUTE format(
            'CREATE POLICY %I ON %I '
            'USING (tenant_id = current_setting(''app.tenant_id'')::uuid) '
            'WITH CHECK (tenant_id = current_setting(''app.tenant_id'')::uuid)',
            part || '_tenant_isolation', part);
    END LOOP;
END
$$;

-- No DELETE and no UPDATE. Observations are immutable, and they are pruned by
-- dropping a partition — which is a migration-role operation, not something the
-- application does row by row. Withholding UPDATE is also what keeps
-- ingest_state a fact about arrival rather than mutable state.
GRANT SELECT, INSERT ON observations TO cvap_app;

COMMIT;
