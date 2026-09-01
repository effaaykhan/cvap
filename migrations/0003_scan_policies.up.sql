-- 0003_scan_policies
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Scan policies and their scope rules.
--
-- Before scans, because a scan is governed by a policy. Separate from scans
-- because a policy outlives every scan that ran under it.

BEGIN;

-- ADR-021: safe is the default for every policy; intrusive means disruption,
-- not compromise, and requires explicit per-scan opt-in plus an audit event.
-- Neither mode permits exploitation, data extraction or shells — that line is
-- a property of the detection logic and is not expressible here.
CREATE TYPE safety_mode AS ENUM ('safe', 'intrusive');

CREATE TYPE scope_rule_effect AS ENUM ('allow', 'deny');
CREATE TYPE scope_match_type AS ENUM ('cidr', 'hostname', 'url', 'tag');

-- ---------------------------------------------------------------------------
-- scan_policies
-- ---------------------------------------------------------------------------

CREATE TABLE scan_policies (
    policy_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    name            text NOT NULL,
    safety_mode     safety_mode NOT NULL DEFAULT 'safe',

    -- ADR-024 is the authority for platform defaults and this column may only
    -- ever LOWER them, never raise. The ceiling itself is deliberately NOT
    -- stored here: three copies of a number is how numbers drift, and ADR-024
    -- says so explicitly. The CHECK below bounds the column at the current
    -- platform default (1,000 pps per scan point) so a policy cannot be written
    -- above it, but the authoritative comparison happens in Core against the
    -- configured ceiling, and again at the scan point before packets leave.
    -- A ceiling enforced in only one place is decorative.
    max_rate_pps    int,

    time_windows    jsonb NOT NULL DEFAULT '[]'::jsonb,
    allowed_engines jsonb NOT NULL DEFAULT '[]'::jsonb,
    allowed_zones   jsonb NOT NULL DEFAULT '[]'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scan_policies_tenant_policy_key UNIQUE (tenant_id, policy_id),
    CONSTRAINT scan_policies_name_per_tenant_key UNIQUE (tenant_id, name),
    CONSTRAINT scan_policies_rate_lower_only
        CHECK (max_rate_pps IS NULL OR (max_rate_pps > 0 AND max_rate_pps <= 1000))
);

COMMENT ON COLUMN scan_policies.max_rate_pps IS
    'NULL means "platform default". Lower-only against the ADR-024 ceiling; see docs/adr/024-scan-blast-radius-controls.md for the authoritative table.';

ALTER TABLE scan_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_policies_tenant_isolation ON scan_policies
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- policy_scope_rules
-- ---------------------------------------------------------------------------
-- Half of ADR-024's duplicated scope enforcement: this table is what Core
-- validates against during planning. The scan point checks again before packets
-- leave, from the constraints it was sent. Neither side trusts the other, and
-- that duplication is deliberate.

CREATE TABLE policy_scope_rules (
    scope_rule_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK (ADR-017); see users.tenant_id in
    -- 0001. A scope rule leaking across tenants would be a scan authorised
    -- against someone else's network, which is the failure this schema is most
    -- concerned with.
    tenant_id     uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    policy_id     uuid NOT NULL,
    effect        scope_rule_effect NOT NULL,
    match_type    scope_match_type NOT NULL,
    match_value   text NOT NULL,

    -- Ordering for evaluation. Exclusions take precedence over allows (ADR-024)
    -- regardless of precedence value; precedence orders within an effect.
    precedence    int NOT NULL DEFAULT 100,
    created_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT policy_scope_rules_tenant_rule_key UNIQUE (tenant_id, scope_rule_id),
    CONSTRAINT policy_scope_rules_policy_fk FOREIGN KEY (tenant_id, policy_id)
        REFERENCES scan_policies (tenant_id, policy_id) ON DELETE CASCADE,
    CONSTRAINT policy_scope_rules_no_duplicates
        UNIQUE (tenant_id, policy_id, effect, match_type, match_value)
);

-- Planning reads every rule for one policy in evaluation order.
CREATE INDEX policy_scope_rules_evaluation_idx
    ON policy_scope_rules (tenant_id, policy_id, effect, precedence);

ALTER TABLE policy_scope_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_scope_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY policy_scope_rules_tenant_isolation ON policy_scope_rules
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON scan_policies, policy_scope_rules TO cvap_app;

COMMIT;
