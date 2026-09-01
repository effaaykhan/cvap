-- 0008_result_submissions
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- ADR-026's idempotency ledger. Not in the v2 ERD; recorded in ADR-029.
--
-- Why this table is not optional: ingest deduplicates on submission_id, so the
-- ID needs a row to be deduplicated against. Without it, at-least-once
-- submission becomes at-least-twice ingestion, and there is no FK target for
-- observations.submission_id in 0009. Idempotency has to be at the boundary —
-- the finding dedup key (ADR-010) is computed downstream of correlation, by
-- which point duplicate observations have already been merged into assets.
--
-- This lands before observations for that reason. It is not a table that can be
-- added later, because an earlier migration would already depend on it.

BEGIN;

-- Mirrors SubmitStatus in ingest.proto. Five outcomes, because two are not
-- enough to tell a scan point what to do with its buffer.
CREATE TYPE submit_status AS ENUM (
    'accepted',              -- processed normally
    'accepted_quarantined',  -- stored, withheld from the finding pipeline,
                             -- operator-surfaced. Never dropped (ADR-012).
    'rejected_duplicate',    -- submission_id already ingested
    'rejected_malformed',    -- unparseable, or unknown observation_type
    'retry_later'            -- transient Core-side failure
);

CREATE TABLE result_submissions (
    -- Generated at the scan point and stable across retries, which is what
    -- makes a retried submission deduplicate rather than double-ingest. Text
    -- rather than uuid: the wire type is a string (ingest.proto) and Core does
    -- not get to reinterpret what a scan point sent.
    submission_id       text PRIMARY KEY,

    -- Denormalised tenant_id + composite FK (ADR-017); see users.tenant_id in
    -- 0001. Note it is also what makes the dedup lookup a tenant-local index
    -- probe on the ingest hot path rather than a global one.
    tenant_id           uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    job_id              uuid NOT NULL,

    -- Checked at ingest against the current lease (ADR-012). A superseded epoch
    -- yields accepted_quarantined: stored and escalated, never discarded. The
    -- epoch is recorded here rather than only compared, because the operator
    -- investigating a fencing failure needs to know which epoch submitted.
    lease_epoch         bigint NOT NULL,

    status              submit_status NOT NULL,

    -- Chunk resumption state. last_chunk_accepted is the resume point returned
    -- in SubmitAck; a scan point resumes from it rather than restarting.
    chunks_received     int NOT NULL DEFAULT 0,
    last_chunk_accepted int,

    -- Set from ResultChunk.incomplete, which arrives on EVERY chunk and not
    -- only the final one: with resumption Core may process chunks before it
    -- ever sees final, and a flag that arrives last cannot stop the finding
    -- pipeline from having already run.
    --
    -- The pipeline must honour this. Storing results the pipeline must not
    -- process is a rule enforced in code rather than by the schema (ADR-026),
    -- which is exactly why it is worth stating here.
    incomplete          boolean NOT NULL DEFAULT false,

    termination_reason  termination_reason,

    -- Written once per submission, and this is the only place it lives. It is
    -- deliberately NOT on observations: the reason is a property of the
    -- submission and identical for every observation in a chunk stream, so
    -- carrying it per row would widen the largest table in the system to avoid
    -- a join the finding pipeline does not need. Observations carry
    -- ingest_state — the flag the pipeline filters on — and nothing more.
    quarantine_reason   text,

    received_at         timestamptz NOT NULL DEFAULT now(),
    completed_at        timestamptz,

    CONSTRAINT result_submissions_tenant_submission_key
        UNIQUE (tenant_id, submission_id),

    CONSTRAINT result_submissions_job_fk FOREIGN KEY (tenant_id, job_id)
        REFERENCES scan_jobs (tenant_id, job_id) ON DELETE CASCADE,

    CONSTRAINT result_submissions_chunks_non_negative CHECK (chunks_received >= 0),

    -- A quarantine reason without a quarantine status is a reason nobody will
    -- look for; a quarantine without a reason is an escalation an operator
    -- cannot action, which defeats the point of not dropping the data.
    CONSTRAINT result_submissions_quarantine_reason_paired
        CHECK ((status = 'accepted_quarantined') = (quarantine_reason IS NOT NULL))
);

COMMENT ON TABLE result_submissions IS
    'ADR-026 idempotency ledger. Not drawn in the v2 ERD; see ADR-029. Results are always persisted — nothing is discarded, whatever the job''s reassign_safe value, which governs retry rather than retention.';

-- The operator queue: quarantined submissions awaiting review. Partial, because
-- this is a small set against a large table and it is read by a human, not a
-- hot path.
CREATE INDEX result_submissions_quarantined_idx
    ON result_submissions (tenant_id, received_at DESC)
    WHERE status = 'accepted_quarantined';

-- "What did this job submit" — asked when a non-reassign_safe job dies
-- mid-flight and the operator needs the account of what was touched.
CREATE INDEX result_submissions_by_job_idx
    ON result_submissions (tenant_id, job_id, received_at DESC);

ALTER TABLE result_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE result_submissions FORCE ROW LEVEL SECURITY;
CREATE POLICY result_submissions_tenant_isolation ON result_submissions
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE ON result_submissions TO cvap_app;

COMMIT;
