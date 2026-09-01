-- 0010_knowledge
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Global knowledge tables.
--
-- NONE of these carry tenant_id and none has an RLS policy. That is deliberate
-- and correct (ADR-017 names these five by name): rule packs, rules, CVE
-- records and vendor advisories are the same for every tenant, and giving them
-- a tenant_id would mean either duplicating the CVE corpus per tenant or
-- writing a policy that always evaluates true. An auditor reading this file
-- should not flag the absence.
--
-- ADR-009's four-entity split lives here. v1 had a single CVE-shaped
-- Vulnerability entity; most of what this platform reports has no CVE.
--
--   Rule              detection logic, versioned, in a signed pack. Always
--                     present on a finding.
--   VulnerabilityDef  a CVE record. OPTIONAL on a finding.
--   VendorAdvisory    USN, RHSA, DSA, MSRC — the authority for whether a
--                     distro package is actually vulnerable (ADR-014).
--   Finding           the observed instance (0011).

BEGIN;

CREATE TYPE severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');

-- ADR-013's detection split: request-coupled detection runs at the scan point,
-- evidence-based detection runs at Core over submitted observations.
CREATE TYPE execution_site AS ENUM ('scan_point', 'core');

-- Version comparison semantics. dpkg and rpm order versions differently, and
-- using the wrong one silently produces wrong answers on epochs and on
-- tilde/caret suffixes.
CREATE TYPE version_comparator AS ENUM ('dpkg', 'rpm');

-- ---------------------------------------------------------------------------
-- rule_packs
-- ---------------------------------------------------------------------------

CREATE TABLE rule_packs (
    rule_pack_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name         text NOT NULL,
    version      text NOT NULL,

    -- ADR-019: knowledge data is signed, and import verifies before writing.
    -- NOT NULL, so an unsigned pack cannot be represented at all.
    signature    text NOT NULL,

    published_at timestamptz NOT NULL,
    imported_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT rule_packs_name_version_key UNIQUE (name, version)
);

-- ---------------------------------------------------------------------------
-- rules
-- ---------------------------------------------------------------------------

CREATE TABLE rules (
    rule_id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_pack_id          uuid NOT NULL REFERENCES rule_packs (rule_pack_id) ON DELETE RESTRICT,
    name                  text NOT NULL,
    category              text NOT NULL,
    engine                engine_kind NOT NULL,
    execution_site        execution_site NOT NULL,
    default_severity      severity NOT NULL,

    -- Confidence is a first-class field on rules, not an afterthought. When in
    -- doubt, lower the confidence rather than raising the severity: a missed
    -- finding is a gap, a false finding loses the customer.
    base_confidence       numeric(4,3) NOT NULL,

    -- Present even when there is no CVE, which is the point of ADR-009. A DAST
    -- or config finding has a rule and a CWE and nothing else.
    cwe                   text,

    detection_logic       jsonb NOT NULL,
    evidence_requirements jsonb NOT NULL DEFAULT '{}'::jsonb,
    remediation_template  text,
    version               int NOT NULL DEFAULT 1,

    CONSTRAINT rules_base_confidence_range CHECK (base_confidence BETWEEN 0 AND 1),
    CONSTRAINT rules_pack_name_version_key UNIQUE (rule_pack_id, name, version)
);

COMMENT ON COLUMN rules.version IS
    'A months-old scan point emits months-old verdicts, and Core must know which rule version to attribute them to (ADR-013). Rule versions are therefore kept, not overwritten.';

CREATE INDEX rules_by_pack_idx ON rules (rule_pack_id);
CREATE INDEX rules_by_engine_idx ON rules (engine, execution_site);

-- ---------------------------------------------------------------------------
-- vulnerability_defs
-- ---------------------------------------------------------------------------

CREATE TABLE vulnerability_defs (
    vuln_def_id  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id       text NOT NULL UNIQUE,
    title        text NOT NULL,
    description  text,
    cvss_base    numeric(3,1),
    cvss_vector  text,
    in_kev       boolean NOT NULL DEFAULT false,
    epss_score   numeric(5,4),

    -- The NVD fallback path (ADR-014). Flagged lower-confidence wherever it is
    -- used: never match an installed distro package version against one of
    -- these ranges — backports make that wrong.
    cpe_ranges   jsonb NOT NULL DEFAULT '[]'::jsonb,

    published_at timestamptz,

    CONSTRAINT vulnerability_defs_cvss_range
        CHECK (cvss_base IS NULL OR cvss_base BETWEEN 0 AND 10),
    CONSTRAINT vulnerability_defs_epss_range
        CHECK (epss_score IS NULL OR epss_score BETWEEN 0 AND 1)
);

-- Risk ranking reads these two together.
CREATE INDEX vulnerability_defs_kev_idx ON vulnerability_defs (in_kev) WHERE in_kev;

-- ---------------------------------------------------------------------------
-- rule_vuln_map
-- ---------------------------------------------------------------------------
-- Many-to-many in both directions, deliberately (ADR-009). One rule commonly
-- detects a family of CVEs from a single vulnerable version banner, and one CVE
-- is commonly detected by several rules at different confidence — a
-- credentialed package match versus a banner inference. A one-to-one mapping
-- was rejected in both directions.

CREATE TABLE rule_vuln_map (
    map_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id          uuid NOT NULL REFERENCES rules (rule_id) ON DELETE CASCADE,
    vuln_def_id      uuid NOT NULL REFERENCES vulnerability_defs (vuln_def_id) ON DELETE CASCADE,
    match_confidence numeric(4,3) NOT NULL,

    CONSTRAINT rule_vuln_map_pair_key UNIQUE (rule_id, vuln_def_id),
    CONSTRAINT rule_vuln_map_confidence_range CHECK (match_confidence BETWEEN 0 AND 1)
);

CREATE INDEX rule_vuln_map_by_vuln_idx ON rule_vuln_map (vuln_def_id);

-- ---------------------------------------------------------------------------
-- vendor_advisories
-- ---------------------------------------------------------------------------

CREATE TABLE vendor_advisories (
    advisory_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_ref   text NOT NULL UNIQUE,   -- USN-1234-1, RHSA-2024:0001
    vendor         text NOT NULL,
    distro_release text,
    severity       severity,
    issued_at      timestamptz
);

-- Advisories reference the CVEs they address. Many-to-many per the ERD's
-- VULNERABILITY_DEF }o--o{ VENDOR_ADVISORY: one advisory commonly fixes several
-- CVEs, and one CVE is commonly addressed by an advisory per distro release.
CREATE TABLE advisory_vuln_map (
    advisory_id uuid NOT NULL REFERENCES vendor_advisories (advisory_id) ON DELETE CASCADE,
    vuln_def_id uuid NOT NULL REFERENCES vulnerability_defs (vuln_def_id) ON DELETE CASCADE,
    PRIMARY KEY (advisory_id, vuln_def_id)
);

CREATE INDEX advisory_vuln_map_by_vuln_idx ON advisory_vuln_map (vuln_def_id);

-- ---------------------------------------------------------------------------
-- advisory_fixed_packages
-- ---------------------------------------------------------------------------
-- The authority for backport-aware matching (ADR-014). This table is the reason
-- advisories are a separate entity from CVEs at all: an advisory's fixed
-- version is per distro release and backport-aware, which a CVE's upstream
-- version range cannot express.

CREATE TABLE advisory_fixed_packages (
    fixed_pkg_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    advisory_id    uuid NOT NULL REFERENCES vendor_advisories (advisory_id) ON DELETE CASCADE,
    distro_release text NOT NULL,
    package_name   text NOT NULL,
    fixed_version  text NOT NULL,
    comparator     version_comparator NOT NULL,

    CONSTRAINT advisory_fixed_packages_key
        UNIQUE (advisory_id, distro_release, package_name)
);

-- The matching hot path: given an installed component's distro release and
-- package name, find the advisories that fix it.
CREATE INDEX advisory_fixed_packages_matching_idx
    ON advisory_fixed_packages (distro_release, package_name);

-- ---------------------------------------------------------------------------
-- Grants
-- ---------------------------------------------------------------------------
-- SELECT only, and deliberately.
--
-- The decision and its reasoning are ADR-030, which is the authority. Summary:
-- ADR-019 makes knowledge data signed and verified at import. If the role that
-- serves tenant queries can also INSERT a rule, then an application-layer
-- defect becomes a path to injecting detection content — and detection content
-- decides what the product tells a customer is wrong with their estate.
--
-- The write path is the signed-import identity, which lands with the importer
-- rather than being granted speculatively here. Until then, knowledge content
-- is loaded by the migration role.
--
-- This WILL fail the rule-pack importer the first time it runs. That is
-- intended. The fix is a distinct role in the importer's own migration, with
-- the same NOBYPASSRLS/NOSUPERUSER assertion 0001 applies to cvap_app — NOT
-- widening this grant. See ADR-030, which exists precisely so that widening it
-- is a visible reversal rather than a one-line diff.

GRANT SELECT ON rule_packs, rules, vulnerability_defs, rule_vuln_map,
                vendor_advisories, advisory_vuln_map, advisory_fixed_packages
    TO cvap_app;

COMMIT;
