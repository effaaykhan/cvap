-- 0012_evidence
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Evidence. NOT PARTITIONED, and this file exists on its own so that decision
-- is somewhere a reviewer will look for it.
--
-- ============================================================================
-- Read this before adding PARTITION BY to this table.
-- ============================================================================
--
-- architecture-v2 9.1 says EVIDENCE is partitioned by month. execution-plan
-- 4.3 said the same. **ADR-016 supersedes both**, explicitly and by name. The
-- reasoning, because it is the kind of thing that gets quietly "fixed" back:
--
--   Partitioning earns its keep when you bulk-drop by time. Evidence is not
--   dropped by time — it follows its finding (ADR-015). Evidence on an open
--   finding is retained as long as the finding; evidence on a closed finding
--   drops 90 days after closure, row and object-store artefact together.
--   There is therefore no partition key that matches how this table is
--   actually pruned, and partitioning by capture time would buy a mechanism
--   we never use while fixing the wrong key permanently.
--
--   Volume does not justify it either: ADR-015 puts large artefacts in the
--   object store, so rows here are small, and evidence exists per finding
--   rather than per probe — low hundreds of thousands of rows against millions
--   of observations at MVP scale.
--
-- The instinct to partition anything that might grow is a reasonable one, and
-- it is why 9.1 said what it said. It is answered above. ADR-016's review
-- trigger is Phase 4, with measured row counts from credentialed assessment —
-- not an estimate, and not before.
--
-- ============================================================================

BEGIN;

CREATE TYPE evidence_type AS ENUM (
    'banner', 'response', 'package_version', 'config_value', 'code_span'
);

CREATE TABLE evidence (
    evidence_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK (ADR-017). ADR-017 names EVIDENCE
    -- as one of the two tables where the rejected alternative — an RLS policy
    -- with an EXISTS subquery up to the parent — would have degraded worst,
    -- because the subquery is re-evaluated per row and cannot be pushed into an
    -- index scan. The column plus the constraint below gives the same guarantee
    -- as a static constraint rather than a per-query cost.
    tenant_id         uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    finding_id        uuid NOT NULL,

    -- ============================================================================
    -- Nullable SOFT REFERENCE. No foreign key, deliberately.
    -- ============================================================================
    -- Observations are partitioned monthly and pruned by dropping the partition
    -- (ADR-016). A hard FK here is the dangling-reference bug: it would either
    -- block the partition drop or fail it.
    --
    -- This column is EXPECTED to go null when the source partition drops. That
    -- is not data loss, because the content below was copied at finding
    -- creation rather than referenced — which is the whole of ADR-016's rule:
    --
    --   Observations are ephemeral. Anything that must outlive them is copied
    --   at the moment it becomes load-bearing.
    --
    -- Provenance therefore degrades rather than persists, and the UI must
    -- present that honestly: "the observation that proved this has aged out" is
    -- a true and useful statement; silently showing a broken link is not.
    --
    -- Do not add a FOREIGN KEY here. Do not add ON DELETE anything. There is
    -- nothing to cascade from.
    observation_id    uuid,

    evidence_type     evidence_type NOT NULL,

    -- The summary, sufficient for display and correlation (ADR-015). Copied
    -- from the observation at finding creation, and for a verdict observation
    -- (ADR-006) this is where the verdict payload lands — which is why verdict
    -- observations need no exemption from the 90-day clock.
    --
    -- This copy must be redacted to the same standard as the observation it
    -- came from, because it now outlives the retention window that would
    -- otherwise have removed it.
    data              jsonb NOT NULL,

    -- Pointer to the full artefact in the S3-compatible object store. NULL when
    -- the summary is the whole of it.
    --
    -- Postgres cannot enforce integrity across this boundary, so orphaned refs
    -- and orphaned objects are both possible and a reconciliation sweep is
    -- required rather than optional (ADR-015) — the same sweep that expires
    -- closed findings' artefacts. The row and the artefact expire together;
    -- neither is removed without the other.
    object_store_ref  text,

    captured_at       timestamptz NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT evidence_tenant_evidence_key UNIQUE (tenant_id, evidence_id),

    CONSTRAINT evidence_finding_fk FOREIGN KEY (tenant_id, finding_id)
        REFERENCES findings (tenant_id, finding_id) ON DELETE CASCADE
);

COMMENT ON TABLE evidence IS
    'NOT partitioned (ADR-016, superseding architecture-v2 9.1 and execution-plan 4.3). Pruned by finding status, not by time: evidence on an open finding is retained as long as the finding; evidence on a closed finding drops 90 days after closure, row and object-store artefact together.';

COMMENT ON COLUMN evidence.observation_id IS
    'Nullable soft reference for provenance. No FK: the observation partition drops on the 90-day clock and this goes null (ADR-016). The content was copied into data, not referenced.';

-- The finding detail view: everything proving this finding.
CREATE INDEX evidence_by_finding_idx ON evidence (tenant_id, finding_id);

-- The object-store reconciliation sweep walks refs that exist. Partial, since
-- most evidence at MVP scale is summary-only.
CREATE INDEX evidence_object_ref_idx ON evidence (tenant_id, created_at)
    WHERE object_store_ref IS NOT NULL;

ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY evidence_tenant_isolation ON evidence
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- DELETE is granted: the reconciliation sweep that expires closed findings'
-- evidence runs as the application, and it must remove the row and the artefact
-- together.
GRANT SELECT, INSERT, UPDATE, DELETE ON evidence TO cvap_app;

COMMIT;
