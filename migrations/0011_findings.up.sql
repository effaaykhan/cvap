-- 0011_findings
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Findings and the three tables hanging off them.
--
-- Evidence is deliberately NOT here — it is in 0012, on its own, because its
-- non-partitioning is the schema decision most likely to be questioned and it
-- should be somewhere a reviewer can find it.

BEGIN;

CREATE TYPE finding_status AS ENUM (
    'open',
    'confirmed',
    'false_positive',
    'accepted_risk',
    'remediated',
    'closed'
);

-- ADR-010: dedup keys are source-specific because no single key works across
-- sources. Recorded on the row so the pipeline's keying path is auditable and
-- so a later change of key definition can be scoped to one source rather than
-- migrating every finding.
CREATE TYPE finding_source AS ENUM (
    'network',       -- asset, port, protocol, rule
    'credentialed',  -- asset, package or component identity, rule
    'dast',          -- target, NORMALISED url path, parameter name, rule
    'api',           -- endpoint, method, parameter, rule
    'sast',          -- repository, file path, ENCLOSING SYMBOL, rule
    'config',        -- asset, setting path, rule
    'cloud'          -- resource ARN or equivalent, rule
);

CREATE TYPE remediation_status AS ENUM (
    'proposed', 'assigned', 'in_progress', 'verified', 'rejected'
);

-- ---------------------------------------------------------------------------
-- findings
-- ---------------------------------------------------------------------------

CREATE TABLE findings (
    finding_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    asset_id         uuid NOT NULL,

    -- ADR-009: mandatory. Every finding is explainable by the rule that raised
    -- it, whether or not a CVE exists. Plain FK, not composite: rules is a
    -- global knowledge table with no tenant_id, which is correct (ADR-017).
    rule_id          uuid NOT NULL REFERENCES rules (rule_id) ON DELETE RESTRICT,

    -- ADR-009: nullable, and nothing may key off its presence. Most of what
    -- this platform reports has no CVE — DAST, API, configuration and SAST
    -- findings have a rule and a CWE and nothing else.
    vuln_def_id      uuid REFERENCES vulnerability_defs (vuln_def_id) ON DELETE SET NULL,

    source           finding_source NOT NULL,

    -- Computed by the finding pipeline per the ADR-010 table, keyed to `source`
    -- above. Two rules are non-negotiable and cannot be expressed here, so they
    -- are stated where the column is defined:
    --
    --   SAST keys on the enclosing function or symbol, NEVER the line number.
    --   Line numbers shift on every unrelated edit above them, so a whitespace
    --   change would close and reopen every finding in the file, destroying
    --   age, triage state and any measure of remediation progress.
    --
    --   DAST normalises the URL before keying. One vulnerable template behind
    --   /users/{id}/profile otherwise produces one finding per traversed ID.
    --
    -- Changing a key definition later migrates or orphans existing findings, so
    -- each is effectively frozen once findings exist.
    dedup_key        text NOT NULL,

    instance_locator text,
    severity         severity NOT NULL,
    confidence       numeric(4,3) NOT NULL,
    status           finding_status NOT NULL DEFAULT 'open',
    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),
    resolved_at      timestamptz,

    CONSTRAINT findings_tenant_finding_key UNIQUE (tenant_id, finding_id),

    CONSTRAINT findings_asset_fk FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE CASCADE,

    CONSTRAINT findings_confidence_range CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT findings_last_seen_after_first CHECK (last_seen >= first_seen)
);

COMMENT ON TABLE findings IS
    'Findings retain indefinitely; observations do not (ADR-016). The same issue on the same asset seen from two vantage points is ONE finding with two finding_exposure rows, never two findings (ADR-008, ADR-010).';

-- The dedup lookup, and the constraint that makes counts mean anything. Unique
-- per tenant: if two rows could share a key the backlog would double-count, and
-- remediation tracking would lose the finding's age on every scan.
CREATE UNIQUE INDEX findings_dedup_key_uidx ON findings (tenant_id, dedup_key);

-- The finding list API, p95 < 500ms at 50k findings (execution-plan 5).
CREATE INDEX findings_tenant_last_seen_idx ON findings (tenant_id, last_seen DESC);

-- The open backlog, which is what the dashboard actually shows.
CREATE INDEX findings_open_idx ON findings (tenant_id, severity, last_seen DESC)
    WHERE status IN ('open', 'confirmed');

CREATE INDEX findings_by_asset_idx ON findings (tenant_id, asset_id);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;
CREATE POLICY findings_tenant_isolation ON findings
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- finding_exposure
-- ---------------------------------------------------------------------------
-- A separate table keyed to zone, not columns on findings (ADR-008). This is
-- where multi-vantage-point exposure — the product's differentiator — falls out
-- of the data model rather than being bolted on.
--
-- One finding, many exposures. One finding per vantage point was rejected: it
-- inflates the critical count by the number of vantage points, which is the
-- first number an executive looks at, and fragments remediation across rows
-- describing the same defect.

CREATE TABLE finding_exposure (
    exposure_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK (ADR-017); see users.tenant_id in
    -- 0001.
    tenant_id          uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    finding_id         uuid NOT NULL,
    zone_id            uuid NOT NULL,
    internet_reachable boolean NOT NULL DEFAULT false,
    auth_required      boolean NOT NULL DEFAULT false,

    -- Exposure is derived, so it has a freshness characteristic the UI must
    -- present honestly. Stale exposure after a network change is a real failure
    -- mode, and this column is what makes it visible rather than silent.
    last_confirmed     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT finding_exposure_tenant_exposure_key UNIQUE (tenant_id, exposure_id),

    CONSTRAINT finding_exposure_finding_fk FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, finding_id) ON DELETE CASCADE,

    CONSTRAINT finding_exposure_zone_fk FOREIGN KEY (tenant_id, zone_id)
        REFERENCES scan_zones (tenant_id, zone_id) ON DELETE CASCADE,

    -- One row per finding per zone. A second row for the same pair would be the
    -- inflated count this table exists to prevent.
    CONSTRAINT finding_exposure_one_per_zone UNIQUE (tenant_id, finding_id, zone_id)
);

-- The exposure dashboard: what is internet-reachable, worst first.
CREATE INDEX finding_exposure_internet_idx
    ON finding_exposure (tenant_id, last_confirmed DESC)
    WHERE internet_reachable;

ALTER TABLE finding_exposure ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_exposure FORCE ROW LEVEL SECURITY;
CREATE POLICY finding_exposure_tenant_isolation ON finding_exposure
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- finding_history
-- ---------------------------------------------------------------------------
-- A STATE-CHANGE log: one row per transition, never a row per finding per scan
-- (ADR-016). A weekly scan of 10,000 findings must not write 10,000 rows a
-- week. If a scan that changes nothing writes here, that is the defect.

CREATE TABLE finding_history (
    history_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    finding_id  uuid NOT NULL,

    -- NULL only for the creating transition.
    from_status finding_status,
    to_status   finding_status NOT NULL,

    -- NULL when Core made the change rather than a person.
    changed_by  uuid,

    reason      text,
    changed_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT finding_history_tenant_history_key UNIQUE (tenant_id, history_id),

    CONSTRAINT finding_history_finding_fk FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, finding_id) ON DELETE CASCADE,

    -- Column-list SET NULL (Postgres 15+); a bare SET NULL would null tenant_id
    -- too. A departed user must not erase the transitions they made.
    CONSTRAINT finding_history_changed_by_fk FOREIGN KEY (tenant_id, changed_by)
        REFERENCES users (tenant_id, user_id) ON DELETE SET NULL (changed_by),

    -- A transition must transition. A row where from and to match is the
    -- row-per-scan anti-pattern arriving by another route.
    CONSTRAINT finding_history_is_a_transition
        CHECK (from_status IS NULL OR from_status <> to_status)
);

CREATE INDEX finding_history_by_finding_idx
    ON finding_history (tenant_id, finding_id, changed_at DESC);

ALTER TABLE finding_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE finding_history FORCE ROW LEVEL SECURITY;
CREATE POLICY finding_history_tenant_isolation ON finding_history
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- remediations
-- ---------------------------------------------------------------------------

CREATE TABLE remediations (
    remediation_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    finding_id        uuid NOT NULL,
    description       text NOT NULL,
    assigned_to       text,
    status            remediation_status NOT NULL DEFAULT 'proposed',
    due_at            timestamptz,
    verified_at       timestamptz,

    -- The scan that proved the fix. Nullable: a remediation may be recorded
    -- before any verifying scan has run.
    verifying_scan_id uuid,

    created_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT remediations_tenant_remediation_key UNIQUE (tenant_id, remediation_id),

    CONSTRAINT remediations_finding_fk FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, finding_id) ON DELETE CASCADE,

    -- Column-list SET NULL; see finding_history_changed_by_fk above.
    CONSTRAINT remediations_verifying_scan_fk FOREIGN KEY (tenant_id, verifying_scan_id)
        REFERENCES scans (tenant_id, scan_id) ON DELETE SET NULL (verifying_scan_id),

    -- The ERD draws FINDING ||--o| REMEDIATION: at most one per finding.
    CONSTRAINT remediations_one_per_finding UNIQUE (tenant_id, finding_id),

    -- Verified means verified by something.
    CONSTRAINT remediations_verification_consistent
        CHECK ((status = 'verified') = (verified_at IS NOT NULL))
);

CREATE INDEX remediations_open_idx ON remediations (tenant_id, due_at)
    WHERE status IN ('proposed', 'assigned', 'in_progress');

ALTER TABLE remediations ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediations FORCE ROW LEVEL SECURITY;
CREATE POLICY remediations_tenant_isolation ON remediations
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON findings, finding_exposure, remediations TO cvap_app;

-- No DELETE on finding_history. A transition log the application can rewrite is
-- not a log, and finding age and triage state are what remediation tracking is
-- measured on.
GRANT SELECT, INSERT ON finding_history TO cvap_app;

COMMIT;
