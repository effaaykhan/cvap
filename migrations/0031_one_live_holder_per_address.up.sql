-- 0031_one_live_holder_per_address
--
-- Every tenant-scoped table gets tenant_id, its own RLS policy and a
-- composite FK to its parent IN THIS FILE, never a follow-up (ADR-002, ADR-017).
-- Partitioning likewise belongs in the creating migration (ADR-016).
-- Run schema-auditor before merging.

-- One live holder per address, enforced by the database.
--
-- ============================================================================
-- The failure this prevents is AMBIGUITY, which is worse than being wrong.
-- ============================================================================
--
-- Correlation closes an address interval when a host moves and opens a new one
-- where it moved to. If the close is ever missed — a bug, a crash between two
-- statements, a code path nobody exercised — two assets both claim the address
-- and nothing complains. Every later correlation against that address then finds
-- two candidates and returns AMBIGUOUS rather than merging, which under ADR-007
-- means the observation goes to the unresolved queue.
--
-- Wrong announces itself. Ambiguous degrades merge quality quietly: assets that
-- should be one stay two, the queue fills with items nobody can adjudicate
-- because the underlying data is the problem, and the first symptom is somebody
-- noticing the inventory has doubled.
--
-- So the invariant is asserted where it cannot be skipped, in the same shape
-- `scan_point_certificates_one_live_key` uses in 0018: a partial unique index
-- over the live rows.
--
-- That is the ONLY prior art here. An earlier draft also cited "one active lease
-- per job", which an audit showed is a different mechanism entirely: `job_leases`
-- is deliberately append-only, uniqueness is (tenant_id, job_id, epoch), and
-- "current" is derived by MAX(epoch) because closing rows would destroy the
-- history a fencing-failure investigation needs. That concern does not apply
-- here — closing an interval is already an UPDATE of `valid_to` and never a
-- delete, so the history survives either way.
--
-- ---------------------------------------------------------------------------
-- What this assumes, stated because it is not free
-- ---------------------------------------------------------------------------
--
-- It assumes an IP address is unique within a tenant at an instant. That is true
-- of what this platform can currently produce and it is NOT true of every real
-- estate: two network segments behind NAT can both use 10.0.0.0/8, and the same
-- literal address in two zones can be two different hosts.
--
-- `asset_addresses` has no zone column and deliberately so — ADR-008 puts zone on
-- the observation, because what has a vantage point is the act of seeing rather
-- than the thing seen. Resolving overlapping private ranges properly needs an
-- address to carry a network scope. See below for what that change actually is:
-- smaller than it looks, and not a reopening of ADR-008.
--
-- Until then the constraint is the right trade: `ip_window` is a WEAK key that
-- never merges on its own precisely because an address is not an identity, and an
-- estate with overlapping ranges inside one tenant would be relying on the
-- ambiguous behaviour this index exists to prevent. If it fires in the field, the
-- answer is the scope column, not dropping the index.
--
-- And that fix is SMALLER than an earlier draft of this comment claimed, which
-- matters because overstating it is how a correct fix gets avoided. The pieces
-- already exist: `scan_zones` and `network_ranges (tenant_id, zone_id, cidr)`
-- from 0002, and `observations.zone_id NOT NULL` from 0009 — so every
-- observation that would open an interval already carries the zone it was seen
-- in. The change is a nullable `zone_id` on this table, populated from that
-- observation the way `merge_evidence_observation` already is, and a widened
-- index key.
--
-- It does NOT reopen ADR-008. That ADR forbids a zone column on `assets`,
-- because assets move and a stored zone is wrong shortly after it is written.
-- `asset_addresses` exists precisely because an address is a time-bounded
-- RELATIONSHIP rather than an asset attribute, and a relationship inheriting the
-- vantage of the observation that opened it is the same reasoning ADR-008 makes,
-- not an exception to it.

BEGIN;

-- The non-unique index from 0007 served the reverse lookup "which asset
-- currently holds this IP". A unique index serves that identically and asserts
-- the invariant as well, so it replaces rather than joins it.
DROP INDEX IF EXISTS asset_addresses_by_ip_idx;

-- `ip_address IS NOT NULL` is not what permits multiple mac-only rows — Postgres
-- treats NULLs as distinct in a unique index, so those are permitted either way,
-- and an audit confirmed it by building the index both ways. It is here because
-- it keeps the index to the rows that can actually serve the reverse lookup, and
-- because a predicate that states the intent is worth the line.
CREATE UNIQUE INDEX asset_addresses_one_live_holder_idx
    ON asset_addresses (tenant_id, ip_address)
    WHERE valid_to IS NULL AND ip_address IS NOT NULL;

COMMENT ON INDEX asset_addresses_one_live_holder_idx IS
    'Two assets holding one live address makes every later correlation ambiguous rather than wrong (ADR-007). Also serves the reverse lookup the non-unique index in 0007 was for.';

-- mac_address is deliberately NOT constrained the same way.
--
-- Not an oversight and not symmetry for its own sake: nothing collects a MAC
-- today, because ARP needs a raw socket and is deferred (ADR-047). An index
-- asserting an invariant over a column no code writes is one nobody has
-- exercised, and the first time it fires will be the first time it is tested.
-- It belongs in the session that makes `mac` reachable.

COMMIT;
