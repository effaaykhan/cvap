-- 0007_assets
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Assets and everything derived onto them.
--
-- Every table in this file is written by Core, never by a scan point. Scan
-- points emit observations and nothing else (ADR-006); assets, services,
-- software components and identity keys are derived from them. The grants at
-- the foot of this file are to cvap_app, which is Core — there is no scan point
-- database role, because a scan point has no database.
--
-- Before observations, because observations carry a nullable asset_id for the
-- resolved-to link.

BEGIN;

CREATE TYPE asset_criticality AS ENUM ('unknown', 'low', 'medium', 'high', 'critical');

CREATE TYPE identity_key_type AS ENUM (
    -- Strong (3): a single one of these justifies a merge.
    'agent_uuid', 'cloud_id', 'dmi_uuid', 'tpm_cert_fp', 'host_cert_fp',
    -- Moderate (2): corroboration required.
    'ssh_hostkey', 'service_cert_fp', 'hostname_domain_os',
    -- Weak (1): never merges alone.
    'mac', 'netbios', 'ip_window'
);

CREATE TYPE component_source AS ENUM ('package_manager', 'registry', 'binary', 'sbom');

CREATE TYPE asset_relationship_type AS ENUM ('routes_to', 'fronts', 'depends_on', 'hosts');

-- ---------------------------------------------------------------------------
-- assets
-- ---------------------------------------------------------------------------

CREATE TABLE assets (
    asset_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id        uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    primary_hostname text,
    os_family        text,
    os_version       text,
    device_type      text,
    vendor           text,
    criticality      asset_criticality NOT NULL DEFAULT 'unknown',
    environment      text,
    owner            text,

    -- ADR-024 control 3. A first-class asset attribute, not a policy setting:
    -- it caps rate and suppresses aggressive checks regardless of what the
    -- policy permits, and it reaches the scan point per Task on the wire
    -- because it is a Core-held attribute the scan point cannot derive.
    fragile          boolean NOT NULL DEFAULT false,

    first_seen       timestamptz NOT NULL DEFAULT now(),
    last_seen        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT assets_tenant_asset_key UNIQUE (tenant_id, asset_id),
    CONSTRAINT assets_last_seen_after_first CHECK (last_seen >= first_seen)

    -- There is deliberately NO zone column here, and adding one is a blocker
    -- (ADR-008). Assets move: a laptop is on the corporate LAN, then home wifi,
    -- then a hotel network. A stored zone is wrong shortly after it is written,
    -- and wrong in the specific way that produces incorrect exposure reporting.
    -- Zone is a property of the observation — what has a vantage point is the
    -- act of seeing, not the thing seen — and exposure is derived and
    -- materialised per finding in finding_exposure.
    --
    -- Nor is there a current-IP column. See asset_addresses below.
);

COMMENT ON TABLE assets IS
    'Derived by Core from observations (ADR-006). Never written by a scan point. No zone column: exposure is derived (ADR-008).';

COMMENT ON COLUMN assets.fragile IS
    'Caps scan rate and suppresses aggressive checks regardless of policy (ADR-024). Travels to the scan point per Task.';

-- The asset list API, p95 < 300ms at 10k assets (execution-plan 5).
CREATE INDEX assets_tenant_last_seen_idx ON assets (tenant_id, last_seen DESC);

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
CREATE POLICY assets_tenant_isolation ON assets
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- asset_addresses
-- ---------------------------------------------------------------------------
-- An IP is a time-bounded relationship, never a column on the asset. DHCP, NAT,
-- ephemeral cloud addressing and reused private ranges make it so (ADR-007,
-- ADR-008). Current state is `valid_to IS NULL`.

CREATE TABLE asset_addresses (
    address_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK (ADR-017); see users.tenant_id in
    -- 0001 for why the column and the constraint are one mechanism.
    tenant_id   uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    asset_id    uuid NOT NULL,
    ip_address  inet,
    mac_address macaddr,
    valid_from  timestamptz NOT NULL DEFAULT now(),

    -- NULL means current. Closing an interval is an UPDATE setting this, never
    -- a DELETE: the history is what makes an old finding's locator meaningful.
    valid_to    timestamptz,

    CONSTRAINT asset_addresses_tenant_address_key UNIQUE (tenant_id, address_id),
    CONSTRAINT asset_addresses_asset_fk FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE CASCADE,
    CONSTRAINT asset_addresses_interval_ordered
        CHECK (valid_to IS NULL OR valid_to > valid_from),
    CONSTRAINT asset_addresses_has_an_address
        CHECK (ip_address IS NOT NULL OR mac_address IS NOT NULL)
);

-- Current addresses for an asset — the common read, and the reason valid_to is
-- in the predicate rather than the key.
CREATE INDEX asset_addresses_current_idx
    ON asset_addresses (tenant_id, asset_id) WHERE valid_to IS NULL;

-- Reverse lookup during correlation: which asset currently holds this IP.
CREATE INDEX asset_addresses_by_ip_idx
    ON asset_addresses (tenant_id, ip_address) WHERE valid_to IS NULL;

ALTER TABLE asset_addresses ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_addresses FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_addresses_tenant_isolation ON asset_addresses
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- asset_identity_keys
-- ---------------------------------------------------------------------------

CREATE TABLE asset_identity_keys (
    identity_key_id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                  uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    asset_id                   uuid NOT NULL,
    key_type                   identity_key_type NOT NULL,
    key_value                  text NOT NULL,

    -- 1 weak, 2 moderate, 3 strong (ADR-007). Stored rather than derived from
    -- key_type so that a re-ranking is a data migration with an audit trail
    -- rather than a silent change in meaning of every historical merge.
    strength                   int NOT NULL,

    -- Soft reference. NO foreign key, deliberately: observations are
    -- partitioned monthly and pruned by dropping the partition (ADR-016), so a
    -- hard FK here would either block the drop or fail it. The column is
    -- expected to point at a row that no longer exists.
    merge_evidence_observation uuid,

    -- ...which is why the payload is COPIED here at merge time rather than
    -- referenced (ADR-007). Merge evidence is a distinct retention class from
    -- bulk observations: it must outlive the 90-day window, and copying rather
    -- than pinning the source partition is what lets ADR-016 keep pruning by
    -- partition drop. Pinning would hold an entire month alive for one merge.
    --
    -- Consequence carried by whoever writes the merge path: this copy is
    -- duplicated data that must be redacted to the same standard as the
    -- observation it came from, because it now outlives the retention window
    -- that would otherwise have removed it.
    merge_evidence_payload     jsonb,

    valid_from                 timestamptz NOT NULL DEFAULT now(),
    valid_to                   timestamptz,

    CONSTRAINT asset_identity_keys_tenant_key_key UNIQUE (tenant_id, identity_key_id),
    CONSTRAINT asset_identity_keys_asset_fk FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE CASCADE,
    CONSTRAINT asset_identity_keys_strength_range CHECK (strength BETWEEN 1 AND 3),
    CONSTRAINT asset_identity_keys_interval_ordered
        CHECK (valid_to IS NULL OR valid_to > valid_from),

    -- A merge that recorded an observation must have copied its payload. Half
    -- the evidence is worse than none, because it looks complete.
    CONSTRAINT asset_identity_keys_evidence_complete
        CHECK ((merge_evidence_observation IS NULL) = (merge_evidence_payload IS NULL))
);

COMMENT ON COLUMN asset_identity_keys.merge_evidence_observation IS
    'Soft reference with no FK. Goes stale when the observation partition drops (ADR-016); the payload beside it is the durable copy.';

-- Correlation's central lookup: does this key already identify an asset.
-- A live key value is unique per tenant and type — two assets holding the same
-- strong key at the same time is the wrong-merge state this exists to prevent.
CREATE UNIQUE INDEX asset_identity_keys_live_value_key
    ON asset_identity_keys (tenant_id, key_type, key_value) WHERE valid_to IS NULL;

CREATE INDEX asset_identity_keys_by_asset_idx
    ON asset_identity_keys (tenant_id, asset_id) WHERE valid_to IS NULL;

ALTER TABLE asset_identity_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_identity_keys FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_identity_keys_tenant_isolation ON asset_identity_keys
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- services
-- ---------------------------------------------------------------------------

CREATE TABLE services (
    service_id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id          uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    asset_id           uuid NOT NULL,
    port               int NOT NULL,
    protocol           text NOT NULL,
    service_name       text,
    product            text,
    version            text,

    -- Confidence is first-class, not an afterthought. A version inferred from a
    -- banner is not a version read from a package database, and the finding
    -- pipeline needs to know which it has.
    version_confidence numeric(4,3),

    first_seen         timestamptz NOT NULL DEFAULT now(),
    last_seen          timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT services_tenant_service_key UNIQUE (tenant_id, service_id),
    CONSTRAINT services_asset_fk FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE CASCADE,
    CONSTRAINT services_port_range CHECK (port BETWEEN 1 AND 65535),
    CONSTRAINT services_confidence_range
        CHECK (version_confidence IS NULL OR version_confidence BETWEEN 0 AND 1),

    -- One row per listening endpoint. The network dedup key (ADR-010) is
    -- asset+port+protocol+rule, so two service rows for the same endpoint would
    -- split findings that should be one.
    CONSTRAINT services_endpoint_key UNIQUE (tenant_id, asset_id, port, protocol)
);

CREATE INDEX services_by_asset_idx ON services (tenant_id, asset_id);

ALTER TABLE services ENABLE ROW LEVEL SECURITY;
ALTER TABLE services FORCE ROW LEVEL SECURITY;
CREATE POLICY services_tenant_isolation ON services
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- software_components
-- ---------------------------------------------------------------------------

CREATE TABLE software_components (
    component_id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    asset_id          uuid NOT NULL,
    source            component_source NOT NULL,

    -- The distro release, e.g. ubuntu2204, rhel9. Load-bearing for ADR-014:
    -- advisory matching is per distro release and backport-aware, so a
    -- component with no release cannot be matched against an advisory and must
    -- fall back to the flagged, lower-confidence CPE path.
    distro            text,

    package_name      text NOT NULL,
    installed_version text NOT NULL,

    -- Named _guess deliberately. NVD CPE matching is a fallback only, flagged
    -- as lower confidence in the model and the UI (ADR-014). Never match an
    -- installed distro package version against an NVD upstream range —
    -- backports make that wrong.
    cpe_guess         text,

    first_seen        timestamptz NOT NULL DEFAULT now(),
    last_seen         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT software_components_tenant_component_key UNIQUE (tenant_id, component_id),
    CONSTRAINT software_components_asset_fk FOREIGN KEY (tenant_id, asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE CASCADE,

    -- The credentialed dedup key is asset + component identity + rule
    -- (ADR-010), so component identity must be unique per asset.
    CONSTRAINT software_components_identity_key
        UNIQUE (tenant_id, asset_id, source, package_name)
);

-- Advisory matching walks components by distro release and package name.
CREATE INDEX software_components_matching_idx
    ON software_components (tenant_id, distro, package_name);

CREATE INDEX software_components_by_asset_idx
    ON software_components (tenant_id, asset_id);

ALTER TABLE software_components ENABLE ROW LEVEL SECURITY;
ALTER TABLE software_components FORCE ROW LEVEL SECURITY;
CREATE POLICY software_components_tenant_isolation ON software_components
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- asset_relationships
-- ---------------------------------------------------------------------------

CREATE TABLE asset_relationships (
    relationship_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    source_asset_id   uuid NOT NULL,
    target_asset_id   uuid NOT NULL,
    relationship_type asset_relationship_type NOT NULL,
    confidence        numeric(4,3) NOT NULL,
    first_seen        timestamptz NOT NULL DEFAULT now(),
    last_seen         timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT asset_relationships_tenant_relationship_key
        UNIQUE (tenant_id, relationship_id),

    -- Both ends tenant-qualified. A relationship is the one shape that could
    -- otherwise stitch two tenants' inventories together.
    CONSTRAINT asset_relationships_source_fk FOREIGN KEY (tenant_id, source_asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE CASCADE,
    CONSTRAINT asset_relationships_target_fk FOREIGN KEY (tenant_id, target_asset_id)
        REFERENCES assets (tenant_id, asset_id) ON DELETE CASCADE,

    CONSTRAINT asset_relationships_confidence_range CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT asset_relationships_not_self CHECK (source_asset_id <> target_asset_id),
    CONSTRAINT asset_relationships_distinct
        UNIQUE (tenant_id, source_asset_id, target_asset_id, relationship_type)
);

CREATE INDEX asset_relationships_by_target_idx
    ON asset_relationships (tenant_id, target_asset_id);

ALTER TABLE asset_relationships ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_relationships FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_relationships_tenant_isolation ON asset_relationships
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON assets, asset_addresses, asset_identity_keys, services,
       software_components, asset_relationships
    TO cvap_app;

COMMIT;
