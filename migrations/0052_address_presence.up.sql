-- 0052_address_presence (ADR-108)
--
-- Whether a host EXISTS at an address becomes a recorded verdict instead of an
-- implicit yes.
--
-- The discovery engine is not broken. It probes an address, something completes a
-- TCP handshake, and it emits an honest observation saying so; correlation
-- promotes it to an asset exactly as ADR-006 requires. What was missing is a
-- layer: nothing decided whether an answer meant a host was THERE. The judgement
-- was implicit and always "yes", which is why it was never visibly wrong — until
-- two /24s produced exactly 512 assets, 2x256, every address in both ranges,
-- including the four that cannot be hosts at all (10.200.11.0 carried five open
-- ports).
--
-- WHY ON THE ADDRESS AND NOT THE ASSET (ADR-108 decision 2). One middlebox
-- answering for 500 addresses is one device, and the addresses it covers are not
-- assets. Putting the verdict on the address leaves ADR-007's merge rules
-- untouched, and lets a host that later proves itself real at that address be
-- promoted without unpicking an asset identity.
--
-- NOTHING IS DELETED (decision 5). `responder` suppresses an address from the
-- estate; it does not remove a row. Two reasons, and the second is the one that
-- matters: a verdict about a live network can be wrong, and a deletion cannot be
-- reviewed. Same shape as a retired ATT&CK technique (ADR-105) and a seen-only
-- port (ADR-103) — the row survives and its meaning is labelled.
--
-- THE REASON IS NOT NULL FOR A PRESENT/RESPONDER VERDICT (decision 6). A
-- suppression an operator cannot interrogate is not stated, it is just a smaller
-- wrong number. `unknown` carries no reason because it is the absence of a
-- judgement rather than one.

BEGIN;

ALTER TABLE asset_addresses
    ADD COLUMN presence            text NOT NULL DEFAULT 'unknown',
    ADD COLUMN presence_reason     text,
    ADD COLUMN presence_decided_at timestamptz;

ALTER TABLE asset_addresses
    ADD CONSTRAINT asset_addresses_presence_known
        CHECK (presence = ANY (ARRAY['present', 'responder', 'unknown'])),
    -- A verdict has either been decided or it has not, and the reason travels
    -- with the timestamp either way. This is deliberately NOT keyed to the
    -- presence value: `unknown` is a real verdict with a real reason (it arrives
    -- two different ways -- no port evidence at all, or ports that answered
    -- anonymously without carrying a responder signature) and an operator asking
    -- why an address is unjudged deserves the same answer as one asking why it
    -- was suppressed. What the constraint forbids is a half-recorded verdict: a
    -- reason with no timestamp, or a timestamp with no reason.
    ADD CONSTRAINT asset_addresses_presence_is_explained
        CHECK ((presence_reason IS NULL AND presence_decided_at IS NULL)
            OR (length(btrim(coalesce(presence_reason, ''))) > 0
                AND presence_decided_at IS NOT NULL));

-- The estate read is "addresses that are not suppressed", so that is the index.
-- Partial on the live interval, matching asset_addresses_current_idx: a closed
-- interval is history and is never part of the estate count.
CREATE INDEX asset_addresses_presence_idx
    ON asset_addresses (tenant_id, presence) WHERE valid_to IS NULL;

COMMENT ON COLUMN asset_addresses.presence IS
    'ADR-108: present | responder | unknown. `responder` means the answers here carry the signature of one device answering for a range — NOT that nothing is there, a claim the rule is not entitled to make. `unknown` means no evidence either way; an address with no port evidence lands here and is never suppressed, because "every port is an artefact" is vacuously true with no ports.';

-- asset_addresses is tenant-scoped, and this migration only adds columns — but
-- the house rule (0048, 0049) is to state what it believes about the table's
-- protection rather than assume it, so a regression is caught by the migration
-- that introduces it rather than by a review that might not run.
DO $$
DECLARE rls boolean; force boolean; pols integer;
BEGIN
    SELECT relrowsecurity, relforcerowsecurity INTO rls, force
      FROM pg_class WHERE oid = 'asset_addresses'::regclass;
    -- schemaname pinned, and the predicate TEXT inspected rather than counted:
    -- the two-argument current_setting returns NULL when unset, which makes the
    -- predicate NULL so reads silently return nothing instead of raising
    -- (ADR-002, and CLAUDE.md says it twice).
    SELECT count(*) INTO pols
      FROM pg_policies
     WHERE schemaname = 'public' AND tablename = 'asset_addresses'
       AND qual IS NOT NULL AND with_check IS NOT NULL
       AND qual       LIKE '%current_setting(''app.tenant_id''::text)%'
       AND with_check LIKE '%current_setting(''app.tenant_id''::text)%'
       AND qual       NOT LIKE '%app.tenant_id''::text, %'
       AND with_check NOT LIKE '%app.tenant_id''::text, %';

    IF NOT rls OR NOT force THEN
        RAISE EXCEPTION
            'asset_addresses lost row level security (rls=%, force=%) — every tenant policy on it is inert (ADR-002).', rls, force;
    END IF;
    IF pols = 0 THEN
        RAISE EXCEPTION
            'asset_addresses has no public-schema policy carrying BOTH USING and WITH CHECK over the ONE-argument current_setting(''app.tenant_id''). A presence verdict is a statement about a tenant''s estate and must not be readable or writable across tenants (ADR-002).';
    END IF;
    RAISE NOTICE 'asset_addresses: RLS forced, % policy(ies) with USING + WITH CHECK', pols;
END
$$;

-- The app role decides presence during correlation, so it needs the column.
-- Narrow: no DELETE is granted here and none is wanted — decision 5 is that
-- nothing is deleted.
GRANT UPDATE (presence, presence_reason, presence_decided_at) ON asset_addresses TO cvap_app;

COMMIT;
