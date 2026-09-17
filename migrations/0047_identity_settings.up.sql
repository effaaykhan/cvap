-- 0047_identity_settings
--
-- The sighting window — how long an observed sighting counts toward the
-- credentialed trust root (ADR-091/094) and how long an address is evidence of
-- the same host (ADR-096) — becomes a per-tenant setting instead of two equal
-- constants (B39's second slice, ADR-100). One row per tenant, absent means the
-- default (7 days). Bounded in the schema: shorter than a day makes every
-- second sighting a first sighting; longer than 90 days makes a stale key a
-- trust root.
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Run schema-auditor before merging.

BEGIN;

CREATE TABLE identity_settings (
    tenant_id        uuid PRIMARY KEY REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    sighting_window  interval NOT NULL DEFAULT interval '7 days',
    updated_at       timestamptz NOT NULL DEFAULT now(),
    -- Who last set it. Deliberately not a foreign key: the record outlives the user.
    updated_by       uuid,
    CONSTRAINT identity_settings_window_bounded
        CHECK (sighting_window >= interval '1 day' AND sighting_window <= interval '90 days')
);

COMMENT ON TABLE identity_settings IS
    'Per-tenant identity tuning (ADR-100). sighting_window: how long a sighting counts toward observed trust and an address is evidence of the same host. Absent row = 7 days.';

ALTER TABLE identity_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_settings_tenant_isolation ON identity_settings
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE ON identity_settings TO cvap_app;

COMMIT;
