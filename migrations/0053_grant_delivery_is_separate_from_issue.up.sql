-- 0053_grant_delivery_is_separate_from_issue
--
-- A credential grant's ISSUE and its DELIVERY are two facts, and until now the
-- row and the audit recorded only the first while asserting the second.
--
-- Measured (B52, 4 of 9 trials): `credential.granted` is written inside
-- offerWork's transaction and COMMITS. The send happens afterwards, and when the
-- outbound queue is full `trySend` fails, `discard()` erases the material, and
-- the committed audit still says the grant went to a fingerprint that never
-- received it. The record is not lost — it is WRONG, which is worse on the
-- credential path: a missing audit is a gap, a wrong one is evidence pointing at
-- the wrong conclusion, and "the audit said granted" is the sentence that matters
-- in an incident.
--
-- WHY A COLUMN AND NOT A SECOND EVENT ALONE. "Issued but never delivered" is a
-- state an operator will ask about, and a state that can only be derived by
-- joining one audit event against the absence of another is one that every
-- caller re-derives slightly differently — and that a compliance export, a
-- `grep credential.`, or a count of grants gets wrong. `zeroised_at` already sets
-- the precedent: the lifecycle fact lives on the row, and the audit event
-- narrates it.
--
-- `delivered_to_fingerprint` keeps its name and its NOT NULL. It is, and always
-- was, the INTENDED recipient, fixed at issue; `delivered_at` is now the only
-- thing that says the material actually went. The name overclaims on its own and
-- the comment below says so, which is cheaper than a rename that would touch the
-- zeroisation path for no behavioural gain.

BEGIN;

ALTER TABLE credential_grants
    ADD COLUMN delivered_at timestamptz;

ALTER TABLE credential_grants
    -- Delivery cannot precede issue, and a grant cannot be zeroised on a scan
    -- point it never reached. The second half is the invariant the split exists
    -- to make checkable: before this column, "zeroised but never delivered" was
    -- not expressible and so was never wrong.
    ADD CONSTRAINT credential_grants_delivery_after_issue
        CHECK (delivered_at IS NULL OR delivered_at >= issued_at),
    ADD CONSTRAINT credential_grants_zeroised_implies_delivered
        CHECK (zeroised_at IS NULL OR delivered_at IS NOT NULL);

-- The question an operator asks: which grants were issued and never went out?
-- Partial, because the answer set is small by design and the table is written on
-- every credentialed dispatch.
CREATE INDEX credential_grants_undelivered_idx
    ON credential_grants (tenant_id, issued_at DESC) WHERE delivered_at IS NULL;

COMMENT ON COLUMN credential_grants.delivered_to_fingerprint IS
    'The INTENDED recipient, fixed when the grant is issued. On its own this name overclaims: it says nothing about whether the material was sent. `delivered_at` is the fact (0053).';
COMMENT ON COLUMN credential_grants.delivered_at IS
    'When the grant material actually reached the outbound stream. NULL means issued and never delivered — the state B52 measured at 4 of 9 trials when the outbound queue was full.';

-- credential_grants is tenant-scoped; this migration only adds columns, but the
-- house rule (0048, 0049, 0052) is to state what it believes about the table''s
-- protection rather than assume it.
DO $$
DECLARE rls boolean; force boolean; pols integer;
BEGIN
    SELECT relrowsecurity, relforcerowsecurity INTO rls, force
      FROM pg_class WHERE oid = 'credential_grants'::regclass;
    SELECT count(*) INTO pols
      FROM pg_policies
     WHERE schemaname = 'public' AND tablename = 'credential_grants'
       AND qual IS NOT NULL
       AND qual LIKE '%current_setting(''app.tenant_id''::text)%'
       AND qual NOT LIKE '%app.tenant_id''::text, %';
    IF NOT rls OR NOT force THEN
        RAISE EXCEPTION
            'credential_grants lost row level security (rls=%, force=%) — a grant is a record of a secret''s release and must never be readable across tenants (ADR-002).', rls, force;
    END IF;
    IF pols = 0 THEN
        RAISE EXCEPTION
            'credential_grants has no public-schema policy over the ONE-argument current_setting(''app.tenant_id''). The two-argument form returns NULL when unset, which makes the predicate NULL and reads return nothing instead of raising (ADR-002).';
    END IF;
    RAISE NOTICE 'credential_grants: RLS forced, % policy(ies)', pols;
END
$$;

GRANT UPDATE (delivered_at) ON credential_grants TO cvap_app;

COMMIT;
