-- 0019_kill_switches
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- The kill switch and its acknowledgements (ADR-024).
--
-- ADR-024 requires propagation to the fleet within 10 seconds and requires
-- KillAck, for a stated reason: "a 10-second bound Core cannot measure is not a
-- control". Two tables rather than a pair of audit rows, because the question an
-- operator asks during an incident is "which scan points have NOT acknowledged",
-- and that has to be a query rather than a scan over a text-keyed log.
--
-- Not in the v2 ERD; recorded in ADR-029.

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

CREATE TYPE kill_scope AS ENUM (
    'tenant',      -- every scan point in the tenant
    'zone',        -- one vantage point
    'scan'         -- one scan's jobs
);

CREATE TABLE kill_switches (
    kill_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    scope           kill_scope NOT NULL,

    -- Which zone or scan, when the scope narrows it. NULL for a tenant-wide
    -- kill. Deliberately NOT foreign keys: a kill is a record of an operator
    -- action, and it must survive the deletion of whatever it was aimed at —
    -- the same reasoning audit_events uses for actor_id and resource_id.
    scope_zone_id   uuid,
    scope_scan_id   uuid,

    issued_by       uuid,
    issued_at       timestamptz NOT NULL DEFAULT now(),

    -- Operator-facing, and surfaced in the audit log. A kill switch with no
    -- stated reason is an outage nobody can explain afterwards.
    reason          text NOT NULL,

    -- When Core stopped expecting acknowledgements. NULL while live.
    resolved_at     timestamptz,

    CONSTRAINT kill_switches_tenant_kill_key UNIQUE (tenant_id, kill_id),

    -- Column-list SET NULL (Postgres 15+); a bare SET NULL would null tenant_id.
    CONSTRAINT kill_switches_issued_by_fk FOREIGN KEY (tenant_id, issued_by)
        REFERENCES users (tenant_id, user_id) ON DELETE SET NULL (issued_by),

    -- The scope narrowing must match the scope.
    CONSTRAINT kill_switches_scope_consistent CHECK (
        (scope = 'tenant' AND scope_zone_id IS NULL AND scope_scan_id IS NULL) OR
        (scope = 'zone'   AND scope_zone_id IS NOT NULL AND scope_scan_id IS NULL) OR
        (scope = 'scan'   AND scope_scan_id IS NOT NULL AND scope_zone_id IS NULL)
    )
);

COMMENT ON TABLE kill_switches IS
    'ADR-024 kill switch. Propagation is bounded at 10s and that bound is measured against kill_acks, because a bound Core cannot measure is not a control. Not drawn in the v2 ERD; see ADR-029.';

CREATE INDEX kill_switches_live_idx ON kill_switches (tenant_id, issued_at DESC)
    WHERE resolved_at IS NULL;

ALTER TABLE kill_switches ENABLE ROW LEVEL SECURITY;
ALTER TABLE kill_switches FORCE ROW LEVEL SECURITY;
CREATE POLICY kill_switches_tenant_isolation ON kill_switches
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

CREATE TABLE kill_acks (
    kill_id       uuid NOT NULL,

    -- Denormalised tenant_id + composite FKs (ADR-017); see users.tenant_id
    -- in 0001.
    tenant_id     uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    scan_point_id uuid NOT NULL,
    acked_at      timestamptz NOT NULL DEFAULT now(),
    tasks_halted  int NOT NULL DEFAULT 0,

    -- One ack per scan point per kill. A scan point that reconnects and acks
    -- again must not produce a second row, or "how many acked" stops meaning
    -- anything.
    PRIMARY KEY (tenant_id, kill_id, scan_point_id),

    CONSTRAINT kill_acks_kill_fk FOREIGN KEY (tenant_id, kill_id)
        REFERENCES kill_switches (tenant_id, kill_id) ON DELETE CASCADE,

    CONSTRAINT kill_acks_scan_point_fk FOREIGN KEY (tenant_id, scan_point_id)
        REFERENCES scan_points (tenant_id, scan_point_id) ON DELETE CASCADE,

    CONSTRAINT kill_acks_tasks_halted_non_negative CHECK (tasks_halted >= 0)
);

COMMENT ON TABLE kill_acks IS
    'One row per scan point per kill. The unacknowledged set — scan points online at issue with no row here — is what makes ADR-024''s 10s bound measurable.';

ALTER TABLE kill_acks ENABLE ROW LEVEL SECURITY;
ALTER TABLE kill_acks FORCE ROW LEVEL SECURITY;
CREATE POLICY kill_acks_tenant_isolation ON kill_acks
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- No DELETE on either. A kill switch and who acknowledged it is incident
-- evidence, not the application's to tidy away.
GRANT SELECT, INSERT, UPDATE ON kill_switches TO cvap_app;
GRANT SELECT, INSERT ON kill_acks TO cvap_app;

COMMIT;
