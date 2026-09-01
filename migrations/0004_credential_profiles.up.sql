-- 0004_credential_profiles
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- Credential profiles, and the join table implementing the ERD's
-- SCAN_POLICY }o--o{ CREDENTIAL_PROFILE many-to-many (ADR-029).
--
-- Grants are not here: a grant references a job, and jobs land in 0005. This
-- file holds only what a policy authorises, never what was released.

BEGIN;

CREATE TYPE credential_type AS ENUM ('ssh', 'winrm', 'snmp', 'cloud', 'api');

-- ---------------------------------------------------------------------------
-- credential_profiles
-- ---------------------------------------------------------------------------

CREATE TABLE credential_profiles (
    credential_profile_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id             uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    name                  text NOT NULL,
    cred_type             credential_type NOT NULL,

    -- A vault pointer. Never plaintext, never a ciphertext blob, never a
    -- passphrase (ADR-020). The schema cannot enforce "this is a reference and
    -- not a secret" — the CHECK below rejects the obviously-wrong shapes, and
    -- security-reviewer is the real gate. It is a text column named to make the
    -- wrong thing look wrong in review.
    secret_ref            text NOT NULL,

    scope_constraints     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT credential_profiles_tenant_profile_key
        UNIQUE (tenant_id, credential_profile_id),
    CONSTRAINT credential_profiles_name_per_tenant_key UNIQUE (tenant_id, name),

    -- A vault pointer has a scheme. This will not stop a determined mistake but
    -- it stops the careless one, and it makes the intent unambiguous to the
    -- next person who reads the column.
    CONSTRAINT credential_profiles_secret_ref_is_a_pointer
        CHECK (secret_ref ~ '^[a-z][a-z0-9+.-]*://')
);

COMMENT ON COLUMN credential_profiles.secret_ref IS
    'Vault pointer, never plaintext (ADR-020). Material is fetched at grant time, delivered just-in-time with the job, held in memory only on the scan point, and zeroised on completion, abort or lease loss.';

COMMENT ON COLUMN credential_profiles.scope_constraints IS
    'Limits which targets this profile may ever be released against. Narrowed further per grant: a grant is scoped to one job''s targets, never a bulk sync (ADR-020).';

ALTER TABLE credential_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_profiles_tenant_isolation ON credential_profiles
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- ---------------------------------------------------------------------------
-- scan_policy_credential_profiles
-- ---------------------------------------------------------------------------
-- The ERD draws this many-to-many as a line and names no table. Mermaid can do
-- that; a relational schema cannot. Recorded in ADR-029 so the table does not
-- read as an invention when someone diffs schema against diagram.
--
-- Both composite FKs are tenant-qualified, so a policy in tenant A cannot
-- authorise a credential profile in tenant B even if application code confuses
-- the two IDs.

CREATE TABLE scan_policy_credential_profiles (
    tenant_id             uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    policy_id             uuid NOT NULL,
    credential_profile_id uuid NOT NULL,
    authorized_at         timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (tenant_id, policy_id, credential_profile_id),

    CONSTRAINT scan_policy_credential_profiles_policy_fk
        FOREIGN KEY (tenant_id, policy_id)
        REFERENCES scan_policies (tenant_id, policy_id) ON DELETE CASCADE,

    CONSTRAINT scan_policy_credential_profiles_profile_fk
        FOREIGN KEY (tenant_id, credential_profile_id)
        REFERENCES credential_profiles (tenant_id, credential_profile_id) ON DELETE CASCADE
);

-- Reverse lookup: which policies authorise this profile. Asked when a profile
-- is revoked or its scope narrowed.
CREATE INDEX scan_policy_credential_profiles_by_profile_idx
    ON scan_policy_credential_profiles (tenant_id, credential_profile_id);

ALTER TABLE scan_policy_credential_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_policy_credential_profiles FORCE ROW LEVEL SECURITY;
CREATE POLICY scan_policy_credential_profiles_tenant_isolation
    ON scan_policy_credential_profiles
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE
    ON credential_profiles, scan_policy_credential_profiles TO cvap_app;

COMMIT;
