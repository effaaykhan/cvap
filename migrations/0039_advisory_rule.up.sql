-- 0039: the advisory-version-match rule (ADR-070). Uses the 'advisory' engine kind
-- added in 0038 — a separate migration because Postgres forbids using a new enum
-- value in the transaction that added it.
--
-- ONE rule carries the detection logic; the CVE is the vuln_def_id per finding
-- (ADR-009's split: the rule is the logic, the vuln def is the CVE), never one rule
-- per advisory. Seeded into the built-in pack (0032), trusted by provenance — the
-- same trust root as the schema, not a wire/offline signature (ADR-019).
BEGIN;

INSERT INTO rules (
    rule_pack_id, name, category, engine, execution_site,
    default_severity, base_confidence, cwe, detection_logic, evidence_requirements,
    remediation_template
) VALUES (
    '00000000-0000-0000-0000-0000000000c6',
    'advisory-version-match', 'advisory', 'advisory', 'core',
    -- Fallback severity when the CVE carries no CVSS; the finding's severity is
    -- taken from the CVE's CVSS band where present (ADR-070). base_confidence is
    -- banner-level (medium): the installed version came from an unauthenticated
    -- banner, not a credentialed read (ADR-014). A Phase 4 credentialed match of
    -- the same package supersedes this at high confidence on the shared dedup key.
    'medium', 0.500, NULL,
    '{"matcher": "advisory.version", "authority": "vendor-advisory", "comparator": "per-advisory (dpkg|rpm), Go-authoritative (ADR-062)"}',
    '{"needs": ["service.product", "service.version", "asset.distro_release", "advisory.fixed_version", "advisory.comparator"]}',
    'Update the package to at least the fixed version named by the advisory. The installed version is at or below the version that fixes this CVE.'
)
ON CONFLICT (rule_pack_id, name, version) DO NOTHING;

COMMIT;
