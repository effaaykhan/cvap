-- 0025_cancel_acks
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Per-scan cancellation, made measurable (ADR-024 control 4).
--
-- ADR-024 requires KillAck for a stated reason: "a 10-second bound Core cannot
-- measure is not a control". That argument does not weaken when the blast radius
-- narrows. The kill switch got two tables in 0019 and cancellation got nothing,
-- so "cancellation sent" was the last thing Core knew about a runaway scan: a
-- scan point that dropped the message looked exactly like one that halted.
--
-- The shape is kill_acks', deliberately. The question an operator asks during an
-- incident is the same one — which scan points have NOT acknowledged — and it
-- has to be a query rather than a scan over a text-keyed log.
--
-- Not drawn in the v2 ERD. ADR-029 enumerates the tables the ERD lacks as of
-- migration 0019 and is Accepted, so it is not edited; this table is the same
-- class as the kill_acks entry in it, for the same ADR-024 reason.

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

-- ---------------------------------------------------------------------------
-- scans.cancel_requested_at — the instant the bound is measured from
-- ---------------------------------------------------------------------------
-- kill_switches.issued_at is what makes the kill switch's 10 s bound
-- measurable. Cancellation had no equivalent: scans.status is a state with no
-- timestamp, and completed_at is set when the scan ends rather than when the
-- operator asked. Measuring from the moment Core happened to send the message
-- would hide the dispatch poll interval, which is part of the propagation the
-- bound is about.
--
-- Set by KillSwitches.Issue for a scan-scoped kill, in the same statement that
-- marks the scan killed. Whatever eventually sets scans.status = 'cancelled' —
-- the operator API, a later session — must do the same: a writer that stops a
-- scan and leaves this NULL makes the ADR-024 bound unmeasurable for the only
-- path that exists. Core reports an unmeasured latency as absent rather than as
-- zero, because a gate that silently passes is worse than one that fails.

ALTER TABLE scans
    ADD COLUMN cancel_requested_at timestamptz;

COMMENT ON COLUMN scans.cancel_requested_at IS
    'When an operator asked for this scan to stop. Set in the same statement that sets status to cancelled. The instant ADR-024 cancellation latency is measured from, as kill_switches.issued_at is for the kill switch.';

-- ---------------------------------------------------------------------------
-- cancel_acks
-- ---------------------------------------------------------------------------

CREATE TABLE cancel_acks (
    job_id        uuid NOT NULL,

    -- Denormalised tenant_id + composite FKs (ADR-017); see users.tenant_id
    -- in 0001.
    tenant_id     uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    scan_point_id uuid NOT NULL,

    -- Which incarnation was halted, echoed from CancelJob (ADR-012). An
    -- acknowledgement under a stale epoch halted work Core was no longer asking
    -- about, and an operator needs to see that rather than count it as the
    -- cancellation succeeding.
    lease_epoch   bigint NOT NULL,

    acked_at      timestamptz NOT NULL DEFAULT now(),
    tasks_halted  int NOT NULL DEFAULT 0,

    -- One ack per scan point per job. A scan point that reconnects and acks
    -- again must not produce a second row, or "how many acknowledged" stops
    -- meaning anything. Same reasoning as kill_acks.
    PRIMARY KEY (tenant_id, job_id, scan_point_id),

    CONSTRAINT cancel_acks_job_fk FOREIGN KEY (tenant_id, job_id)
        REFERENCES scan_jobs (tenant_id, job_id) ON DELETE CASCADE,

    CONSTRAINT cancel_acks_scan_point_fk FOREIGN KEY (tenant_id, scan_point_id)
        REFERENCES scan_points (tenant_id, scan_point_id) ON DELETE CASCADE,

    CONSTRAINT cancel_acks_tasks_halted_non_negative CHECK (tasks_halted >= 0),
    CONSTRAINT cancel_acks_epoch_positive CHECK (lease_epoch > 0)
);

COMMENT ON TABLE cancel_acks IS
    'One row per scan point per cancelled job. The unacknowledged set — jobs still assigned or running under a cancelled or killed scan with no row here — is what makes ADR-024''s per-scan cancellation a control rather than a button. Not drawn in the v2 ERD; same class as kill_acks in ADR-029.';

ALTER TABLE cancel_acks ENABLE ROW LEVEL SECURITY;
ALTER TABLE cancel_acks FORCE ROW LEVEL SECURITY;
CREATE POLICY cancel_acks_tenant_isolation ON cancel_acks
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- No DELETE and no UPDATE. Who acknowledged a cancellation, and when, is
-- incident evidence — not the application's to tidy away or to revise. Same
-- grant as kill_acks.
GRANT SELECT, INSERT ON cancel_acks TO cvap_app;

COMMIT;
