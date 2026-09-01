-- 0005_scan_execution
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- ADR-011's three-level decomposition — scan, job, task — plus targets and the
-- lease ledger.
--
-- One file because these are one referential cluster: scan_tasks references
-- both scan_jobs and scan_targets, so splitting the file leaves dispatch unable
-- to decompose anything. Every observation is attributable to a task, every
-- task to a job, every job to a scan.

BEGIN;

CREATE TYPE scan_status AS ENUM (
    'pending', 'planning', 'running', 'completed', 'failed', 'cancelled', 'killed'
);

CREATE TYPE scan_target_type AS ENUM ('cidr', 'host', 'url', 'repo', 'cloud_account');

CREATE TYPE job_status AS ENUM (
    'queued',      -- decomposed, awaiting a scan point
    'assigned',    -- leased, not yet started
    'running',
    'completed',
    'failed',
    'quarantined', -- results held from the finding pipeline (ADR-012, ADR-026)
    'cancelled',
    'killed'
);

CREATE TYPE task_status AS ENUM (
    'pending', 'running', 'completed', 'failed', 'skipped'
);

-- Shared with the wire contract (common.proto TerminationReason). Values match
-- the proto names lowercased. ADR-022 makes that enum additive-only, so this
-- type is additive-only too, or Core cannot store a reason a scan point sent.
CREATE TYPE termination_reason AS ENUM (
    'completed',
    'lease_lost',            -- renewal failed; self-abort (ADR-012)
    'cancelled',             -- per-scan cancellation (ADR-024)
    'killed',                -- global kill switch (ADR-024)
    'engine_failure',        -- engine process died or refused the job (ADR-027)
    'window_expired',
    'scope_violation_halt'   -- scan-point-side scope check refused a target
);

CREATE TYPE lease_state AS ENUM ('granted', 'lost', 'expired', 'released');

-- ---------------------------------------------------------------------------
-- scans
-- ---------------------------------------------------------------------------

CREATE TABLE scans (
    scan_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    policy_id    uuid NOT NULL,

    -- Nullable: a scheduled or system-initiated scan has no requesting user,
    -- and a user who leaves should not take their scan history with them.
    requested_by uuid,

    -- Free text, not an enum, and deliberately. Scan types follow engines, which
    -- are extensible by design (ADR-027) — the same reason observation_type and
    -- engine are open on the wire. Core validates this against the scan types it
    -- can actually plan; an enum here would make every new engine an ALTER TYPE
    -- against a live cluster, and enumerating the set now would be guessing at
    -- the ones MVP scope has not built yet.
    scan_type    text NOT NULL,

    status       scan_status NOT NULL DEFAULT 'pending',
    created_at   timestamptz NOT NULL DEFAULT now(),
    started_at   timestamptz,
    completed_at timestamptz,

    CONSTRAINT scans_tenant_scan_key UNIQUE (tenant_id, scan_id),

    CONSTRAINT scans_policy_fk FOREIGN KEY (tenant_id, policy_id)
        REFERENCES scan_policies (tenant_id, policy_id) ON DELETE RESTRICT,

    -- Column-list SET NULL (Postgres 15+). A bare ON DELETE SET NULL on a
    -- composite FK nulls every referencing column, including tenant_id, which
    -- is NOT NULL — so the delete would fail at runtime rather than at migrate
    -- time. Naming the column confines the null to requested_by.
    CONSTRAINT scans_requested_by_fk FOREIGN KEY (tenant_id, requested_by)
        REFERENCES users (tenant_id, user_id) ON DELETE SET NULL (requested_by),

    CONSTRAINT scans_completed_after_started
        CHECK (completed_at IS NULL OR started_at IS NULL OR completed_at >= started_at)
);

CREATE INDEX scans_tenant_created_idx ON scans (tenant_id, created_at DESC);
CREATE INDEX scans_active_idx ON scans (tenant_id, status)
    WHERE status IN ('pending', 'planning', 'running');

ALTER TABLE scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE scans FORCE ROW LEVEL SECURITY;
CREATE POLICY scans_tenant_isolation ON scans
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- scan_targets
-- ---------------------------------------------------------------------------

CREATE TABLE scan_targets (
    target_id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK (ADR-017); see users.tenant_id in
    -- 0001. On this table in particular: a target that could point at a scan in
    -- another tenant is a scan authorised against the wrong customer's network.
    tenant_id              uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    scan_id                uuid NOT NULL,
    target_type            scan_target_type NOT NULL,
    target_value           text NOT NULL,

    -- Execution-plan 8 risk 6: no authorization framework is legal exposure,
    -- potentially criminal. Defaults false. Dispatch must refuse to decompose a
    -- target where this is false; the CHECK cannot express that, so it is
    -- enforced in planning and again at the scan point (ADR-024).
    authorization_verified boolean NOT NULL DEFAULT false,
    verified_at            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scan_targets_tenant_target_key UNIQUE (tenant_id, target_id),
    CONSTRAINT scan_targets_scan_fk FOREIGN KEY (tenant_id, scan_id)
        REFERENCES scans (tenant_id, scan_id) ON DELETE CASCADE,

    -- A verified target must record when. An unverified one must not claim a
    -- verification time.
    CONSTRAINT scan_targets_verification_consistent
        CHECK (authorization_verified = (verified_at IS NOT NULL))
);

CREATE INDEX scan_targets_by_scan_idx ON scan_targets (tenant_id, scan_id);

ALTER TABLE scan_targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_targets FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_targets_tenant_isolation ON scan_targets
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- scan_jobs
-- ---------------------------------------------------------------------------
-- One unit assigned to one scan point, one engine, roughly minutes of work.
-- The unit of leasing, retry and progress.

CREATE TABLE scan_jobs (
    job_id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    scan_id            uuid NOT NULL,

    -- Nullable while queued: a job exists before dispatch picks a scan point
    -- for it (ADR-003's SKIP LOCKED claim).
    scan_point_id      uuid,

    engine             engine_kind NOT NULL,
    status             job_status NOT NULL DEFAULT 'queued',
    attempt            int NOT NULL DEFAULT 0,

    -- ADR-012: governs RETRY, not retention. Results from a job that lost its
    -- lease are persisted unconditionally (ADR-026); this decides only whether
    -- the work re-runs. Orthogonal to scan_policies.safety_mode (ADR-021) —
    -- active DAST is safe-mode-permitted and not reassign_safe, while an
    -- intrusive port sweep may well be reassign_safe. Neither implies the other.
    --
    -- Defaults false: duplicating work is assumed harmful until a job type is
    -- shown to be safe to duplicate.
    reassign_safe      boolean NOT NULL DEFAULT false,

    termination_reason termination_reason,
    created_at         timestamptz NOT NULL DEFAULT now(),
    completed_at       timestamptz,

    CONSTRAINT scan_jobs_tenant_job_key UNIQUE (tenant_id, job_id),

    CONSTRAINT scan_jobs_scan_fk FOREIGN KEY (tenant_id, scan_id)
        REFERENCES scans (tenant_id, scan_id) ON DELETE CASCADE,

    CONSTRAINT scan_jobs_scan_point_fk FOREIGN KEY (tenant_id, scan_point_id)
        REFERENCES scan_points (tenant_id, scan_point_id) ON DELETE RESTRICT,

    CONSTRAINT scan_jobs_attempt_non_negative CHECK (attempt >= 0)
);

-- The dispatch claim: oldest queued job for an engine this tenant can run.
-- Backs the SKIP LOCKED scan in ADR-003.
CREATE INDEX scan_jobs_dispatch_queue_idx
    ON scan_jobs (tenant_id, engine, created_at)
    WHERE status = 'queued';

CREATE INDEX scan_jobs_by_scan_idx ON scan_jobs (tenant_id, scan_id, status);

-- The operator's question after a fleet incident: what is this scan point
-- holding.
CREATE INDEX scan_jobs_by_scan_point_idx
    ON scan_jobs (tenant_id, scan_point_id)
    WHERE status IN ('assigned', 'running');

ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_jobs_tenant_isolation ON scan_jobs
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- job_leases
-- ---------------------------------------------------------------------------
-- Append-only: one row per lease generation, not one row per job.
--
-- This departs from the ERD, which draws SCAN_JOB ||--o| JOB_LEASE — at most
-- one lease per job. The reason for the departure: ADR-012 makes the epoch a
-- fencing token, and the case you need the table for is a fencing failure —
-- two scan points both believing they hold the same job. Overwriting the row on
-- reassignment destroys exactly the history that investigation needs. The
-- current lease is the row with the highest epoch.
--
-- Monotonicity of the epoch is enforced in dispatch, not here: a CHECK cannot
-- see other rows, and a trigger doing the lookup would sit on the assignment
-- path. UNIQUE (tenant_id, job_id, epoch) is what the schema can guarantee, and
-- it is enough to make a duplicate epoch impossible.

CREATE TABLE job_leases (
    lease_id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    job_id            uuid NOT NULL,

    -- Monotonically increasing per job. Reassignment issues a new, higher epoch
    -- and only after demonstrable expiry (ADR-012).
    epoch             bigint NOT NULL,

    holder_scan_point uuid NOT NULL,
    state             lease_state NOT NULL DEFAULT 'granted',
    granted_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    renewed_at        timestamptz,

    CONSTRAINT job_leases_tenant_lease_key UNIQUE (tenant_id, lease_id),

    -- One row per (job, epoch). A duplicate epoch would make the fencing token
    -- ambiguous, which is the whole failure ADR-012 exists to prevent.
    CONSTRAINT job_leases_job_epoch_key UNIQUE (tenant_id, job_id, epoch),

    CONSTRAINT job_leases_job_fk FOREIGN KEY (tenant_id, job_id)
        REFERENCES scan_jobs (tenant_id, job_id) ON DELETE CASCADE,

    CONSTRAINT job_leases_holder_fk FOREIGN KEY (tenant_id, holder_scan_point)
        REFERENCES scan_points (tenant_id, scan_point_id) ON DELETE RESTRICT,

    CONSTRAINT job_leases_epoch_positive CHECK (epoch > 0),
    CONSTRAINT job_leases_expiry_after_grant CHECK (expires_at > granted_at)
);

-- "What is the current lease for this job" — the ingest epoch check on every
-- submission, so it is on a hot path.
CREATE INDEX job_leases_current_idx ON job_leases (tenant_id, job_id, epoch DESC);

-- The expiry sweep: leases past their expiry that are still marked granted.
--
-- Deliberately NOT tenant_id-first, which every other index in this schema is.
-- The sweep is a platform-wide background job asking "which leases anywhere
-- have expired", not a tenant-scoped query — leading with tenant_id would make
-- it one index scan per tenant instead of one ordered scan of a small partial
-- index. It runs as a migration-role identity for that reason; an application
-- connection could not see across tenants to run it even if it wanted to.
CREATE INDEX job_leases_expiry_sweep_idx ON job_leases (expires_at)
    WHERE state = 'granted';

ALTER TABLE job_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_leases FORCE ROW LEVEL SECURITY;
CREATE POLICY job_leases_tenant_isolation ON job_leases
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- scan_tasks
-- ---------------------------------------------------------------------------
-- Individual target work inside a job. The unit of observation attribution.

CREATE TABLE scan_tasks (
    task_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    job_id       uuid NOT NULL,

    -- Nullable: a task may be expanded from a range rather than traced to one
    -- declared target row, and a target deleted from a scan should not delete
    -- the record of work already done against it.
    target_id    uuid,

    task_target  text NOT NULL,
    status       task_status NOT NULL DEFAULT 'pending',
    progress_pct int NOT NULL DEFAULT 0,
    started_at   timestamptz,
    completed_at timestamptz,

    CONSTRAINT scan_tasks_tenant_task_key UNIQUE (tenant_id, task_id),

    CONSTRAINT scan_tasks_job_fk FOREIGN KEY (tenant_id, job_id)
        REFERENCES scan_jobs (tenant_id, job_id) ON DELETE CASCADE,

    -- Column-list SET NULL; see scans_requested_by_fk above.
    CONSTRAINT scan_tasks_target_fk FOREIGN KEY (tenant_id, target_id)
        REFERENCES scan_targets (tenant_id, target_id) ON DELETE SET NULL (target_id),

    CONSTRAINT scan_tasks_progress_range CHECK (progress_pct BETWEEN 0 AND 100)
);

CREATE INDEX scan_tasks_by_job_idx ON scan_tasks (tenant_id, job_id, status);

ALTER TABLE scan_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_tasks FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_tasks_tenant_isolation ON scan_tasks
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON scans, scan_targets, scan_jobs, job_leases, scan_tasks TO cvap_app;

COMMIT;
