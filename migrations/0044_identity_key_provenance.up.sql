BEGIN;

-- ADR-094: a key CVAP observed is trust material at an address only once two
-- distinct scans have seen it there.
--
-- ADR-093 made the correlator record a host's moderate keys on an ATTACH — the
-- address-only verdict — so an asset discovered before it was fingerprinted
-- could ever gain a key. The security review of that change measured what it
-- widened: the ADR-091 observed-trust root for an address became "the first key
-- anyone presented there", and an attach can happen on any address handover.
-- Three further shapes fell to the same review once the count existed: a merge
-- re-recording the keys that justified it, one scan split across sweeps, and —
-- once the count was per address — a "new asset" at an address whose interval
-- had aged out, which is first sight again on a seven-day timer. So the rule
-- is one rule with no exemption: two distinct scans at the address, whatever
-- verdict recorded the key. Two sightings narrow the window; they do not
-- verify anything — the operator pin remains the answer, and this is the
-- default for fleets too large to pin.
--
-- Two things land here. `provenance` on asset_identity_keys records HOW a key
-- came to be held, for the audit trail (it does not decide trust). The
-- sightings table is the count, keyed by key AND address, because a scalar on
-- the key row can remember one address only and a dual-homed host lives at
-- two: the review measured a two-address host trusted at one address at best
-- and at neither when the scan order alternated.
--
-- This migration grants on a new table, so ADR-002's assertion is repeated.
DO $$
DECLARE
    r record;
BEGIN
    SELECT rolbypassrls, rolsuper INTO r FROM pg_roles WHERE rolname = 'cvap_app';
    IF NOT FOUND THEN
        RAISE EXCEPTION 'Role cvap_app does not exist (ADR-002)';
    END IF;
    IF r.rolbypassrls OR r.rolsuper THEN
        RAISE EXCEPTION 'Role cvap_app holds BYPASSRLS or SUPERUSER; tenant isolation would be silently lost (ADR-002)';
    END IF;
END
$$;

-- DEPLOY ORDER: once this commits, provenance has no default, so a Core still
-- running the pre-ADR-094 Record (an explicit column list without it) fails
-- every identity-key write. Migrate, then restart on the binary that carries
-- the new Record — not a rolling window with both binaries live. Loud by
-- design; the alternative is new merge keys landing as 'unknown' and losing
-- the record of how they were recorded.

CREATE TYPE identity_key_provenance AS ENUM (
    'merge',      -- recorded as the evidence that JUSTIFIED a merge (ADR-007)
    'new_asset',  -- recorded when the asset was created, seen with the key
    'attach',     -- recorded on an address-only attach (ADR-093 §1)
    'unknown'     -- held before this column existed
);

ALTER TABLE asset_identity_keys
    ADD COLUMN provenance identity_key_provenance NOT NULL DEFAULT 'unknown';

-- Existing rows: 'unknown' rather than a guess at 'merge'. Nothing reads
-- provenance to decide trust, so this is an honest label, not a downgrade.
ALTER TABLE asset_identity_keys ALTER COLUMN provenance DROP DEFAULT;

COMMENT ON COLUMN asset_identity_keys.provenance IS
    'How the key came to be held (which verdict recorded it). Audit only: trust is decided by asset_identity_key_sightings (ADR-094).';

-- ---------------------------------------------------------------------------
-- asset_identity_key_sightings: distinct scans that saw a key at an address.
-- ---------------------------------------------------------------------------
--
-- One row per (key, address, port). scans_seen counts DISTINCT SCANS — the occasion
-- is the scan, never a timestamp: two address groups in one sweep carry two
-- timestamps and the batch cut splits one scan across two sweeps, and each
-- inflated a timestamp-based count from a single scan. last_seen_scan is the
-- guard; last_seen_at orders concurrent scans. Any verdict counts, a merge
-- included: what keeps a merge from promoting the keys that justified it is
-- that its sighting counts once, at its own address.
--
-- A sighting also AGES: the trust query counts only rows seen inside the
-- address window (seven days, the same window that closes a stale address
-- interval), because a count that never decays makes the two-scan cost a
-- one-time payment — the review measured an attacker who paid it once,
-- left, and was trusted again on a single scan months later.
--
-- Existing keys have no sightings rows and are therefore trust material
-- nowhere until two post-migration scans see them at an address. The three
-- Phase 4 hosts pay two fingerprint sweeps; a backfill from asset_addresses
-- would re-create exactly the one-sighting trust this ADR refuses.
CREATE TABLE asset_identity_key_sightings (
    tenant_id        uuid NOT NULL REFERENCES tenants (tenant_id) ON DELETE CASCADE,
    identity_key_id  uuid NOT NULL,
    address          inet NOT NULL,
    -- The service the key was seen on. The credentialed engine dials one port
    -- and its trust root must be what was seen ON that port: a key row copies
    -- the evidence of the observation that first recorded it, so "the port in
    -- the payload" is where the key was first seen, not where it was seen at
    -- this address on this scan.
    port             int NOT NULL,
    scans_seen       int NOT NULL DEFAULT 1,
    -- Soft reference, no FK: this row must outlive the scan that raised it
    -- (the count IS the history), and a hard FK would either block a scan's
    -- deletion or cascade the count away with it — the same reasoning as
    -- merge_evidence_observation (ADR-016). Nothing deletes scans today.
    last_seen_scan   uuid NOT NULL,
    last_seen_at     timestamptz NOT NULL,

    CONSTRAINT asset_identity_key_sightings_pkey PRIMARY KEY (tenant_id, identity_key_id, address, port),
    CONSTRAINT asset_identity_key_sightings_key_fk FOREIGN KEY (tenant_id, identity_key_id)
        REFERENCES asset_identity_keys (tenant_id, identity_key_id) ON DELETE CASCADE,
    CONSTRAINT asset_identity_key_sightings_positive CHECK (scans_seen >= 1),
    CONSTRAINT asset_identity_key_sightings_port_range CHECK (port BETWEEN 1 AND 65535)
);

COMMENT ON TABLE asset_identity_key_sightings IS
    'ADR-094: distinct scans that saw an identity key at an address on a port. A key is ADR-091 observed-trust material at an address at scans_seen >= 2 on the dialled port, seen within the address window — a narrower window, not a verification.';

ALTER TABLE asset_identity_key_sightings ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_identity_key_sightings FORCE ROW LEVEL SECURITY;
CREATE POLICY asset_identity_key_sightings_tenant_isolation ON asset_identity_key_sightings
    USING      (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);

-- No DELETE, like asset_resolution_queue: rows leave only by cascade from the
-- key (which itself is closed, never deleted) or the tenant.
GRANT SELECT, INSERT, UPDATE ON asset_identity_key_sightings TO cvap_app;

-- ADR-094 parks an observation with a pending queue item out of the sweep;
-- ListUnresolved anti-joins the queue per observation, and the queue is
-- expected to grow (B39: nothing resolves an item yet).
CREATE INDEX asset_resolution_queue_pending_obs_idx
    ON asset_resolution_queue (tenant_id, observation_id)
    WHERE state = 'pending';

COMMIT;
