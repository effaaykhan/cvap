-- 0002_scan_zones_and_points
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Zones and the scan points that sit in them.
--
-- This lands before observations because a zone is the vantage point an
-- observation is tagged with, and exposure is derived from which vantage points
-- saw what (ADR-008). It lands before scan_execution because jobs are assigned
-- to scan points.

BEGIN;

CREATE TYPE zone_type AS ENUM ('external', 'dmz', 'internal', 'branch', 'cloud', 'mgmt');

CREATE TYPE scan_point_status AS ENUM (
    'pending',   -- enrolled, not yet seen
    'online',
    'offline',   -- heartbeat timeout exceeded (90s, execution-plan 5)
    'disabled',  -- operator-disabled
    'revoked'    -- certificate revoked; may not re-enrol on the same identity
);

-- Closed set, validated at ingest and dispatch. Note this is deliberately
-- narrower than the wire contract: dispatch.proto carries `engine` as an open
-- string because engines are extensible by design (ADR-027) and a closed wire
-- enum would make every new engine a protocol change. Core validates the string
-- against this type, which is the same arrangement observation_type has.
--
-- The first three are the engine processes that exist (internal/engines/). The
-- rest are the ERD's set; they are out of MVP scope (execution-plan 2) and
-- carry no code. They are listed so that adding one is a capability row rather
-- than an ALTER TYPE against a live cluster.
CREATE TYPE engine_kind AS ENUM (
    'discovery', 'fingerprint', 'rules',
    'host', 'dast', 'api', 'sast', 'cloud'
);

-- ---------------------------------------------------------------------------
-- scan_zones
-- ---------------------------------------------------------------------------

CREATE TABLE scan_zones (
    zone_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    name        text NOT NULL,
    zone_type   zone_type NOT NULL,
    trust_level int NOT NULL,
    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scan_zones_tenant_zone_key UNIQUE (tenant_id, zone_id),
    CONSTRAINT scan_zones_name_per_tenant_key UNIQUE (tenant_id, name),
    CONSTRAINT scan_zones_trust_level_range CHECK (trust_level BETWEEN 0 AND 100)
);

ALTER TABLE scan_zones ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_zones FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_zones_tenant_isolation ON scan_zones
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- network_ranges
-- ---------------------------------------------------------------------------

CREATE TABLE network_ranges (
    range_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK (ADR-017). See users.tenant_id in
    -- 0001 for why the pair is one mechanism and neither half works alone.
    tenant_id      uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    zone_id        uuid NOT NULL,
    cidr           cidr NOT NULL,

    -- ADR-024 / execution-plan 8 risk 6: an unauthorised range is a legal
    -- problem, not a bug. Defaults false so a range is out of scope until
    -- somebody says otherwise.
    is_authorized  boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT network_ranges_tenant_range_key UNIQUE (tenant_id, range_id),
    CONSTRAINT network_ranges_zone_fk FOREIGN KEY (tenant_id, zone_id)
        REFERENCES scan_zones (tenant_id, zone_id) ON DELETE CASCADE,
    CONSTRAINT network_ranges_unique_per_zone UNIQUE (tenant_id, zone_id, cidr)
);

ALTER TABLE network_ranges ENABLE ROW LEVEL SECURITY;
ALTER TABLE network_ranges FORCE ROW LEVEL SECURITY;
CREATE POLICY network_ranges_tenant_isolation ON network_ranges
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- scan_points
-- ---------------------------------------------------------------------------

CREATE TABLE scan_points (
    scan_point_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    zone_id          uuid NOT NULL,
    hostname         text NOT NULL,
    agent_version    text NOT NULL,
    protocol_version text NOT NULL,
    status           scan_point_status NOT NULL DEFAULT 'pending',
    last_heartbeat   timestamptz,

    -- Globally unique, not per-tenant, and deliberately so: a certificate
    -- fingerprint identifies a peer at the TLS layer before any tenant context
    -- exists (ADR-005, ADR-018). Two tenants claiming the same fingerprint
    -- would make enrolment ambiguous at exactly the point where it must not be.
    cert_fingerprint text NOT NULL UNIQUE,

    enrolled_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scan_points_tenant_point_key UNIQUE (tenant_id, scan_point_id),
    CONSTRAINT scan_points_zone_fk FOREIGN KEY (tenant_id, zone_id)
        REFERENCES scan_zones (tenant_id, zone_id) ON DELETE RESTRICT
);

COMMENT ON COLUMN scan_points.zone_id IS
    'Zones this scan point is enrolled into. Core MUST validate Observation.zone_id against this at ingest: a scan point free to name its own zone could rewrite the derived exposure of every asset it reports (ingest.proto, ADR-008). Mismatches quarantine, never re-zone.';

-- Heartbeat sweep: find scan points whose last_heartbeat has aged past the 90s
-- timeout. Ordered scan over the live set, per tenant.
CREATE INDEX scan_points_tenant_heartbeat_idx
    ON scan_points (tenant_id, last_heartbeat DESC NULLS LAST);

ALTER TABLE scan_points ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_points FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_points_tenant_isolation ON scan_points
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- scan_point_capabilities
-- ---------------------------------------------------------------------------
-- The capability handshake on connect. Core never dispatches a job type or rule
-- format the scan point cannot run, which means dispatch reads this table
-- before it assigns.

CREATE TABLE scan_point_capabilities (
    capability_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id      uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    scan_point_id  uuid NOT NULL,
    engine         engine_kind NOT NULL,
    engine_version text NOT NULL,
    enabled        boolean NOT NULL DEFAULT true,
    declared_at    timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT scan_point_capabilities_tenant_capability_key
        UNIQUE (tenant_id, capability_id),
    CONSTRAINT scan_point_capabilities_point_fk FOREIGN KEY (tenant_id, scan_point_id)
        REFERENCES scan_points (tenant_id, scan_point_id) ON DELETE CASCADE,
    CONSTRAINT scan_point_capabilities_one_per_engine
        UNIQUE (tenant_id, scan_point_id, engine)
);

-- Dispatch's question: which scan points in this tenant can run this engine.
CREATE INDEX scan_point_capabilities_dispatch_idx
    ON scan_point_capabilities (tenant_id, engine) WHERE enabled;

ALTER TABLE scan_point_capabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_point_capabilities FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_point_capabilities_tenant_isolation ON scan_point_capabilities
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON scan_zones, network_ranges, scan_points, scan_point_capabilities
    TO cvap_app;

COMMIT;
