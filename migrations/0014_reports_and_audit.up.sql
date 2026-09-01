-- 0014_reports_and_audit
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Reports and the audit log. Last, because nothing references them.

BEGIN;

CREATE TYPE actor_type AS ENUM ('user', 'scan_point', 'system');

-- ---------------------------------------------------------------------------
-- reports
-- ---------------------------------------------------------------------------

CREATE TABLE reports (
    report_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    -- Free text, not an enum. The reporting engine is out of MVP scope
    -- (execution-plan 2), so enumerating report types now would be inventing a
    -- set nobody has designed. Revisit when that engine lands — at which point
    -- the set is knowable and an enum becomes the right shape.
    report_type      text NOT NULL,
    parameters       jsonb NOT NULL DEFAULT '{}'::jsonb,

    -- Same object store as evidence, same reasoning (ADR-015): a generated
    -- report does not belong in the transactional database that also serves
    -- dashboards. NULL while generation is in flight.
    object_store_ref text,

    requested_by     uuid,
    generated_at     timestamptz,
    created_at       timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT reports_tenant_report_key UNIQUE (tenant_id, report_id),

    -- Column-list SET NULL (Postgres 15+); a bare SET NULL would null tenant_id
    -- too.
    CONSTRAINT reports_requested_by_fk FOREIGN KEY (tenant_id, requested_by)
        REFERENCES users (tenant_id, user_id) ON DELETE SET NULL (requested_by),

    -- A generated report has an artefact; an ungenerated one has neither.
    CONSTRAINT reports_generation_consistent
        CHECK ((generated_at IS NULL) = (object_store_ref IS NULL))
);

CREATE INDEX reports_tenant_created_idx ON reports (tenant_id, created_at DESC);

ALTER TABLE reports ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports FORCE ROW LEVEL SECURITY;
CREATE POLICY reports_tenant_isolation ON reports
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- audit_events
-- ---------------------------------------------------------------------------
-- Execution-plan 5 requires an audit event for every credential release, scope
-- change, policy edit and scan start.

CREATE TABLE audit_events (
    audit_event_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    -- Deliberately NOT a foreign key to users. An actor may be a scan point or
    -- Core itself, and more importantly an audit record must survive the
    -- deletion of whatever it refers to — a FK with ON DELETE SET NULL would
    -- quietly erase who did something, which is the one thing this table exists
    -- to remember. actor_type says how to interpret it.
    actor_id       uuid,
    actor_type     actor_type NOT NULL,

    -- Free text, and this one should stay that way. An audit vocabulary grows
    -- with every feature that audits something, and an enum would mean a
    -- migration before a new action could be recorded — which is precisely the
    -- pressure that leads to an action going unrecorded. A log that cannot
    -- represent a new event is worse than one with an untidy vocabulary.
    action         text NOT NULL,

    -- Same reasoning: the referenced resource may be gone. This is a record of
    -- what happened, not a live link. Free text for the same reason `action` is
    -- — and additionally because it must be able to name a resource type that
    -- no longer exists in the schema at all.
    resource_type  text NOT NULL,
    resource_id    uuid,

    detail         jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT audit_events_tenant_event_key UNIQUE (tenant_id, audit_event_id)
);

COMMENT ON TABLE audit_events IS
    'Append-only. actor_id and resource_id are deliberately not foreign keys: an audit record must outlive the rows it describes. Credential releases, scope changes, policy edits, intrusive-mode selection and scan starts all land here.';

CREATE INDEX audit_events_tenant_occurred_idx ON audit_events (tenant_id, occurred_at DESC);

-- "Everything that happened to this resource" — the investigation query.
CREATE INDEX audit_events_by_resource_idx
    ON audit_events (tenant_id, resource_type, resource_id, occurred_at DESC);

-- "Everything this actor did" — the other investigation query.
CREATE INDEX audit_events_by_actor_idx
    ON audit_events (tenant_id, actor_id, occurred_at DESC);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_events_tenant_isolation ON audit_events
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON reports TO cvap_app;

-- Append-only. No UPDATE, no DELETE: an audit log the application can rewrite
-- is not an audit log. Retention is a migration-role operation.
GRANT SELECT, INSERT ON audit_events TO cvap_app;

COMMIT;
