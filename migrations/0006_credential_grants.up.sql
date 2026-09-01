-- 0006_credential_grants
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Credential grants: the record of every release of credential material to a
-- scan point (ADR-020).
--
-- Its own file deliberately. This is the credential-release audit surface, and
-- a reviewer asking "what does Core hand out, to whom, scoped to what, for how
-- long" should find the whole answer in one place rather than buried among
-- fifteen other tables. It depends on both 0004 (profiles) and 0005 (jobs).
--
-- What is NOT here, and must never be added: the credential material itself.
-- Material is fetched from the vault at grant time, delivered just-in-time with
-- the job, held in memory only on the scan point, and zeroised on completion,
-- abort or lease loss. This table records that a release happened. It is not a
-- place to cache what was released.

BEGIN;

-- Mirrors CredKind in dispatch.proto. Every grant declares one: the preferred
-- secret-free mechanisms carry structurally different material, and overloading
-- one opaque field to mean different things per protocol is the semantic drift
-- ADR-022 forbids. Additive-only, for the same reason the proto enum is.
CREATE TYPE cred_kind AS ENUM (
    'session_handle',   -- preferred: the secret never leaves Core
    'kerberos_ticket',
    'ssh_cert',
    'derived_token',
    'raw_secret'        -- last resort
);

CREATE TABLE credential_grants (
    grant_id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Denormalised tenant_id + composite FK (ADR-017); see users.tenant_id in
    -- 0001. The composite FKs below are load-bearing here in a way they are not
    -- elsewhere: without them, a grant row could pair tenant A's job with
    -- tenant B's credential profile, and the object this table exists to
    -- account for is the release of a secret. RLS alone would hide the row; the
    -- constraint prevents it existing.
    tenant_id                uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,

    credential_profile_id    uuid NOT NULL,
    job_id                   uuid NOT NULL,
    cred_kind                cred_kind NOT NULL,

    -- Scoped to this job's targets, never a bulk sync (ADR-020). Recorded so an
    -- auditor can answer "what could this material have been used against"
    -- without reconstructing the job's task list, which may have been pruned.
    target_scope             jsonb NOT NULL,

    -- Who received it. The scan point's certificate fingerprint rather than its
    -- ID, because the fingerprint is what the TLS layer actually authenticated.
    delivered_to_fingerprint text NOT NULL,

    issued_at                timestamptz NOT NULL DEFAULT now(),
    expires_at               timestamptz NOT NULL,

    -- Set when the scan point confirms zeroisation, or when Core observes the
    -- job terminate. NULL means "we have no confirmation", which is an
    -- operator-visible state and not the same as "still valid".
    zeroised_at              timestamptz,

    CONSTRAINT credential_grants_tenant_grant_key UNIQUE (tenant_id, grant_id),

    CONSTRAINT credential_grants_profile_fk
        FOREIGN KEY (tenant_id, credential_profile_id)
        REFERENCES credential_profiles (tenant_id, credential_profile_id)
        ON DELETE RESTRICT,

    CONSTRAINT credential_grants_job_fk FOREIGN KEY (tenant_id, job_id)
        REFERENCES scan_jobs (tenant_id, job_id) ON DELETE RESTRICT,

    -- Short-TTL is the point (ADR-020). A grant that never expires is a bulk
    -- sync with extra steps.
    CONSTRAINT credential_grants_expiry_after_issue CHECK (expires_at > issued_at)
);

COMMENT ON TABLE credential_grants IS
    'Audit record of credential releases (ADR-020). Never stores credential material. RESTRICT on both parents: a grant record must outlive routine cleanup of the job or profile it refers to, because it is the account of a secret having left Core.';

-- The auditor question: everything released against this profile, newest first.
CREATE INDEX credential_grants_by_profile_idx
    ON credential_grants (tenant_id, credential_profile_id, issued_at DESC);

-- The incident question: what is still live, and what never confirmed
-- zeroisation.
CREATE INDEX credential_grants_unconfirmed_idx
    ON credential_grants (tenant_id, expires_at)
    WHERE zeroised_at IS NULL;

ALTER TABLE credential_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_grants FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_grants_tenant_isolation ON credential_grants
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- No DELETE. An audit record of a credential release is not the application's
-- to remove; retention is an operator decision executed by a migration role.
GRANT SELECT, INSERT, UPDATE ON credential_grants TO cvap_app;

COMMIT;
