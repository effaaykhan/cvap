-- 0045_rotation_states
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.
--
-- ADR-096: a same-service SSH host-key contradiction at a held address that
-- classifies as a KEY ROTATION (the newcomer seen on two distinct scans, the
-- held key on none since, every previously seen product still answering on its
-- port, the OS family agreeing) attaches instead of parking. Two enum values
-- record that outcome honestly rather than borrowing a neighbour's word:
--
--   identity_key_provenance 'rotation' / 'lapsed' — which verdict recorded
--     the key. Both are EXCLUDED from ADR-091's observed trust root until an
--     operator pins or confirms: on banner data neither outcome can tell a
--     rotation or a lapse from a takeover of the SSH port.
--   resolution_state 'rotated' — a pending item the SYSTEM closed because the
--     contradiction it parked classified as a rotation on a later scan;
--     'expired' — one the SYSTEM closed because the contradiction went stale.
--     resolved_asset_id is the asset the observations then attach to;
--     resolved_by stays NULL, because no operator chose. 'merged' means an
--     operator chose a candidate and is left meaning that.
--
-- No new table, no new column: nothing here needs a policy or a grant. ADD
-- VALUE is transactional on PostgreSQL 16 as long as the value is not used in
-- the same transaction, and nothing here uses it.

BEGIN;

ALTER TYPE identity_key_provenance ADD VALUE IF NOT EXISTS 'rotation';
-- 'lapsed': recorded when a new asset displaced an address holder whose key
-- had been silent for a full window under a fresh contest (ADR-096). Like
-- 'rotation', EXCLUDED from the credentialed trust root: the review measured
-- one window of holding tcp/22 against a live host buying the trust root
-- under 'new_asset' — cheaper than the rotation it preempted.
ALTER TYPE identity_key_provenance ADD VALUE IF NOT EXISTS 'lapsed';
ALTER TYPE resolution_state        ADD VALUE IF NOT EXISTS 'rotated';
-- 'expired': the SYSTEM closed the item because no contradicting key had been
-- seen at the address for a full window while the held host kept answering —
-- a park with no expiry is a detection denial of service with a one-packet
-- trigger (ADR-096 step 1 §2). resolved_by NULL, no asset: nothing was chosen.
ALTER TYPE resolution_state        ADD VALUE IF NOT EXISTS 'expired';

-- A rotated item names the asset the system attached its observations to, as
-- a merged item names the one the operator chose (0013's merged_has_asset).
-- Compared as text: the enum literal cannot be used in the transaction that
-- adds it, and the constraint must land with the value.
ALTER TABLE asset_resolution_queue
    ADD CONSTRAINT asset_resolution_queue_rotated_has_asset
        CHECK (state::text <> 'rotated' OR resolved_asset_id IS NOT NULL);

-- The queue is now read BY ADDRESS on every sweep of a held address (is a
-- contradiction pending here?), on every health read (how many addresses are
-- contested?) and by CloseStale (does this address stay held?). The address is
-- normalised ONCE, at write, into an inet column — every read compares inet
-- to inet. The first draft compared the copied payload's text to host(inet)
-- and the security review measured a non-canonical spelling
-- ("2001:0db8:0077:0000:..." or "10.77.6.010") ageing the occupant out and
-- handing the address, and the credentialed trust root, to the newcomer.
-- Existing rows are backfilled from the copied payload (or, for an ip_window
-- item, the key value); a value that does not parse stays NULL and counts for
-- nothing rather than aborting the migration.
ALTER TABLE asset_resolution_queue ADD COLUMN address inet;

DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN SELECT resolution_id,
                    coalesce(observed_payload ->> 'address',
                             CASE WHEN key_type = 'ip_window' THEN key_value END) AS a
               FROM asset_resolution_queue
              WHERE address IS NULL
    LOOP
        BEGIN
            UPDATE asset_resolution_queue SET address = host(r.a::inet)::inet WHERE resolution_id = r.resolution_id;
        EXCEPTION WHEN OTHERS THEN
            NULL; -- unparseable: left NULL, counts for nothing
        END;
    END LOOP;
END $$;

CREATE INDEX asset_resolution_queue_pending_address_idx
    ON asset_resolution_queue (tenant_id, address)
    WHERE state = 'pending';

-- Rows written before the bare-host normalisation may carry a mask, and inet
-- equality includes it: '10.44.3.10/24' = '10.44.3.10' is FALSE, so such a row
-- is invisible to every by-address read and can coexist with a bare live row
-- under 0031's unique index. Rewrite them bare; where a bare live row already
-- exists, the masked duplicate is CLOSED (it was never the one being read).
DO $$
DECLARE r RECORD;
BEGIN
    FOR r IN SELECT tenant_id, asset_id, ip_address FROM asset_addresses
              WHERE masklen(ip_address) NOT IN (32, 128)
    LOOP
        BEGIN
            UPDATE asset_addresses SET ip_address = host(ip_address)::inet
             WHERE tenant_id = r.tenant_id AND asset_id = r.asset_id AND ip_address = r.ip_address;
        EXCEPTION WHEN unique_violation THEN
            UPDATE asset_addresses SET valid_to = coalesce(valid_to, now())
             WHERE tenant_id = r.tenant_id AND asset_id = r.asset_id AND ip_address = r.ip_address;
        END;
    END LOOP;
END $$;
UPDATE asset_identity_key_sightings SET address = host(address)::inet
 WHERE masklen(address) NOT IN (32, 128);

-- An item may name NO candidate (ADR-096): two hosts answering on one port at
-- an address nothing holds is unresolvable identity with nobody to choose
-- between, and it belongs in the queue as "unplaceable" rather than as one
-- asset holding two hosts' keys — which the review measured, after which the
-- asset's own key contradicted its other key on every scan and the park never
-- expired.
ALTER TABLE asset_resolution_queue DROP CONSTRAINT IF EXISTS asset_resolution_queue_candidates_non_empty;

-- ONE live key per (asset, type, port, protocol) — the domain's unit, the key's
-- Source ("22/tcp"); an index on the port alone was measured refusing a
-- legitimate second protocol on one port and retrying the group for ever.
-- domain.Resolve now queues a group carrying two values of one type from one
-- service; this is the backstop no caller can get past. Existing violators (probe leftovers, or two scan points
-- with overlapping private space landing two hosts on one asset) keep the
-- newest and retire the rest — the next sighting decides which is real.
UPDATE asset_identity_keys k SET valid_to = now()
 WHERE k.valid_to IS NULL
   AND k.merge_evidence_payload ? 'port'
   AND EXISTS (SELECT 1 FROM asset_identity_keys n
                WHERE n.tenant_id = k.tenant_id AND n.asset_id = k.asset_id AND n.key_type = k.key_type
                  AND n.valid_to IS NULL AND n.identity_key_id <> k.identity_key_id
                  AND n.merge_evidence_payload -> 'port' = k.merge_evidence_payload -> 'port'
                  AND coalesce(nullif(n.merge_evidence_payload ->> 'protocol', ''), 'tcp')
                      = coalesce(nullif(k.merge_evidence_payload ->> 'protocol', ''), 'tcp')
                  AND (n.valid_from, n.identity_key_id) > (k.valid_from, k.identity_key_id));
CREATE UNIQUE INDEX asset_identity_keys_one_live_per_port_uidx
    ON asset_identity_keys (tenant_id, asset_id, key_type, (merge_evidence_payload -> 'port'),
        (coalesce(nullif(merge_evidence_payload ->> 'protocol', ''), 'tcp')))
    WHERE valid_to IS NULL AND merge_evidence_payload ? 'port';

COMMIT;
