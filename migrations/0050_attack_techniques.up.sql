-- 0050_attack_techniques (ADR-105)
--
-- MITRE ATT&CK as a knowledge feed, on the same terms as the others: a pinned
-- corpus version, ingested by cvap_knowledge_import (ADR-063), freshness in
-- knowledge_feed_status, global and untenanted (ADR-030). Three tables, because
-- ADR-105 decision 2 gives findings two anchors and a technique catalogue has to
-- exist for either of them to name anything.
--
-- WHAT A ROW HERE IS. Every mapping in these tables is an INFERENCE about a
-- weakness — someone reasoning about what an adversary COULD do — never a record
-- of anything observed. Non-negotiable #9 has CVAP establishing evidence without
-- achieving impact, so it is in no position to report how anything WAS exploited.
-- Decision 3 makes the labelling part of the contract rather than a UI choice,
-- which is why `source` is NOT NULL on both mapping tables: a technique that
-- cannot say where it came from must not be storable.
--
-- WHY cve_techniques KEYS ON cve_id AND NOT vuln_def_id. ADR-105 decision 2 says
-- `vuln_def -> technique`, and this is that anchor spelled the way `kev` and
-- `epss` already spell it (0037): keyed on the CVE id, joined rather than
-- referenced. The feed describes CVEs, not the subset of CVEs this installation
-- happens to have ingested. An FK would mean silently discarding every mapping
-- for a CVE not yet in vulnerability_defs and re-importing the feed whenever the
-- advisory set grew. Absence of a row is "we have no mapping" (decision 4), and
-- that has to stay distinguishable from "the feed had one and we dropped it".
--
-- COVERAGE, MEASURED BEFORE BUILDING RATHER THAN DISCOVERED AFTER. The published
-- source is the Center for Threat-Informed Defense's Mappings Explorer, whose
-- KEV->ATT&CK dataset carries 1,183 mappings over 419 CVEs and 155 techniques.
-- Of those 419 CVEs, **0 are among the 6,028 this installation has ingested**.
-- That is not a defect in either dataset: CVAP's CVEs come from Ubuntu USN
-- advisories (archive packages) and CISA KEV is Adobe, Citrix, Chromium, Windows
-- and network appliances. The two sets are about different software. ADR-105
-- predicted the mapped fraction would be low and made decision 4 -- coverage is
-- STATED, never implied by absence -- exactly so this reads as a measured fact
-- rather than an empty feature. The rule anchor is what carries value today.
--
-- RETIREMENT, NOT DELETION. ADR-105's consequences require that a technique which
-- disappears from a later corpus is retired with its history rather than removed:
-- a finding that cited T1234 last quarter must still be able to explain itself.
-- So `deprecated` and `revoked_by` are columns, the importer only ever INSERTs
-- and UPDATEs, and nothing in this schema gives it a reason to DELETE.

BEGIN;

-- The technique catalogue. One row per ATT&CK technique or sub-technique, from
-- the pinned enterprise corpus.
CREATE TABLE attack_techniques (
    technique_id     text PRIMARY KEY,                      -- T1190, or T1190.001
    name             text NOT NULL,
    tactics          text[] NOT NULL DEFAULT '{}',          -- kill-chain phase shortnames
    description      text,
    url              text,                                  -- the MITRE page an operator opens
    is_subtechnique  boolean NOT NULL DEFAULT false,
    parent_id        text,                                  -- T1190 for T1190.001
    deprecated       boolean NOT NULL DEFAULT false,
    revoked_by       text,                                  -- the technique that replaced it
    attack_version   text NOT NULL,                         -- pinned corpus, e.g. '16.1'
    last_fetched_at  timestamptz NOT NULL,

    CONSTRAINT attack_techniques_id_shape
        CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    -- A sub-technique has a parent and a plain technique does not. Stated as a
    -- constraint because the importer derives both from the same STIX field, and
    -- a parser change that got it wrong would otherwise land silently.
    CONSTRAINT attack_techniques_parent_agrees
        CHECK ((is_subtechnique AND parent_id IS NOT NULL)
            OR (NOT is_subtechnique AND parent_id IS NULL))
);

-- Anchor 1 (ADR-105 decision 2): CVE -> technique, from a published dataset.
-- source_confidence is nullable and stays NULL for a source that publishes none.
-- The temptation is to fill it with something reasonable; decision 1 forbids it
-- in as many words -- "never a number this project invents" -- because a score
-- CVAP made up is indistinguishable downstream from one the source stood behind.
-- What this source DOES publish is mapping_type, its own qualification of the
-- relationship, and that is carried verbatim.
CREATE TABLE cve_techniques (
    cve_id             text NOT NULL,
    technique_id       text NOT NULL,
    mapping_type       text NOT NULL,        -- the SOURCE's qualifier, carried verbatim
    source             text NOT NULL,        -- 'ctid-mappings-explorer'
    source_version     text NOT NULL,        -- 'kev-07.28.2025'
    attack_version     text NOT NULL,        -- '16.1'
    source_confidence  numeric(4,3),         -- NULL = the source publishes none
    comments           text,                 -- the source's own rationale
    last_fetched_at    timestamptz NOT NULL,

    PRIMARY KEY (cve_id, technique_id, mapping_type),
    CONSTRAINT cve_techniques_confidence_range
        CHECK (source_confidence IS NULL OR source_confidence BETWEEN 0 AND 1)
);

-- Anchor 2 (ADR-105 decision 2): rule -> technique, curated. Evaluator findings
-- carry a rule_id and no CVE at all (non-negotiable #4), so the CVE anchor cannot
-- reach them. Fourteen rules is a hand-curatable number and six thousand CVEs is
-- not, which is the whole reason the two anchors differ in kind.
--
-- `rationale` is NOT NULL on purpose. A curated row is a person's judgement, and
-- one that cannot say why it was made is not reviewable -- which would make it
-- exactly the unauditable mapping ADR-105 rejected language models for producing.
--
-- No FK to attack_techniques: the catalogue is a FEED, so a fresh database has
-- these curated rows and an empty catalogue until someone runs the import, and a
-- migration that could not apply before a network fetch would be the wrong
-- dependency. The check is not skipped, only moved -- the importer refuses a
-- corpus that does not contain every curated technique, so a typo here surfaces
-- loudly the first time the catalogue is present rather than as a silent join
-- that returns nothing.
CREATE TABLE rule_techniques (
    rule_id       uuid NOT NULL REFERENCES rules(rule_id) ON DELETE CASCADE,
    technique_id  text NOT NULL,
    source        text NOT NULL DEFAULT 'cvap-curated',
    rationale     text NOT NULL,

    PRIMARY KEY (rule_id, technique_id),
    CONSTRAINT rule_techniques_id_shape
        CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3})?$'),
    CONSTRAINT rule_techniques_rationale_present
        CHECK (length(btrim(rationale)) > 0)
);

CREATE INDEX cve_techniques_by_technique_idx ON cve_techniques (technique_id);
CREATE INDEX rule_techniques_by_technique_idx ON rule_techniques (technique_id);

COMMENT ON TABLE attack_techniques IS
    'MITRE ATT&CK technique catalogue at a pinned corpus version (ADR-105). Global knowledge. Retired, never deleted: a finding that cited a technique must still explain itself after the technique leaves the corpus.';
COMMENT ON TABLE cve_techniques IS
    'CVE -> ATT&CK technique from a published dataset (ADR-105 anchor 1). An INFERENCE about a weakness, never an observation of an attack. Joined to vulnerability_defs on cve_id, deliberately not an FK.';
COMMENT ON TABLE rule_techniques IS
    'Rule -> ATT&CK technique, curated per rule (ADR-105 anchor 2), for evaluator findings which carry no CVE. Each row states its rationale so the judgement is reviewable.';

-- The injection guarantee (ADR-063), re-asserted because this migration grants to
-- the write role. Same block as 0037.
DO $$
DECLARE r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_knowledge_import';
    IF r.rolbypassrls THEN
        RAISE EXCEPTION 'cvap_knowledge_import holds BYPASSRLS (ADR-063). Fix: ALTER ROLE cvap_knowledge_import NOBYPASSRLS;';
    END IF;
    IF r.rolsuper THEN
        RAISE EXCEPTION 'cvap_knowledge_import is SUPERUSER (ADR-063). Fix: ALTER ROLE cvap_knowledge_import NOSUPERUSER;';
    END IF;
END $$;

-- These three are global knowledge and must carry no tenant scope. Asserted
-- rather than assumed, the way 0048 and 0049 do it: if one ever grows a
-- tenant_id it needs RLS, FORCE and a policy in the migration that changed it
-- (non-negotiable #3), and this migration should stop being the thing that
-- created it without one.
DO $$
DECLARE tenanted text;
BEGIN
    SELECT string_agg(table_name, ', ') INTO tenanted
      FROM information_schema.columns
     WHERE table_schema = 'public'
       AND table_name IN ('attack_techniques', 'cve_techniques', 'rule_techniques')
       AND column_name = 'tenant_id';
    IF tenanted IS NOT NULL THEN
        RAISE EXCEPTION 'tenant_id appeared on global knowledge table(s): %. ATT&CK mappings are global facts (ADR-105 decision 1); a tenant-scoped one needs RLS + FORCE + a policy in the same migration (non-negotiable #3).', tenanted;
    END IF;
END $$;

GRANT SELECT ON attack_techniques, cve_techniques, rule_techniques TO cvap_app;
-- The importer writes the two FEED tables. rule_techniques is curated content on
-- the rule-pack path (ADR-030's separate identity), migration-seeded like `rules`
-- itself, so the import role gets no write on it.
GRANT SELECT, INSERT, UPDATE ON attack_techniques, cve_techniques TO cvap_knowledge_import;
-- SELECT only, and only because the importer VALIDATES against this table: after
-- loading a corpus it refuses if any curated technique id is absent from it (the
-- check that would have been an FK if the catalogue were not a feed). Found by
-- running the importer, which failed with "permission denied for table
-- rule_techniques" -- the grant above reads as complete until something actually
-- exercises the check. No write: curated content stays on the migration path.
GRANT SELECT ON rule_techniques TO cvap_knowledge_import;

COMMIT;
