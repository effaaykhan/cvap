package store

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
)

// Asset identity: the time-bounded halves of ADR-007 and ADR-008.
//
// Addresses and identity keys both carry a validity interval and never a bare
// current value. Closing one is an UPDATE setting `valid_to`, never a DELETE:
// the history is what makes an old finding's locator meaningful, and it is what
// lets a merge be reviewed after the fact.

// AssetAddresses is the time-bounded address relationship (ADR-008).
type AssetAddresses struct{}

// LiveHolder returns the asset currently holding an address, and when it was
// last seen there.
//
// The "last seen there" is `valid_from`, refreshed by TouchLive below rather
// than by closing and reopening an interval. Reopening on every scan would turn
// one continuous tenancy into a row per scan, and the address history — the
// thing the interval exists for — would become a scan log.
func (AssetAddresses) LiveHolder(ctx context.Context, c *Conn, ip string) (uuid.UUID, time.Time, error) {
	const q = `
		SELECT asset_id, valid_from
		  FROM asset_addresses
		 WHERE tenant_id = $1 AND ip_address = $2::inet AND valid_to IS NULL`

	var (
		id   uuid.UUID
		from time.Time
	)
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), ip).Scan(&id, &from)
	if err != nil {
		return uuid.Nil, time.Time{}, mapError(err)
	}
	return id, from, nil
}

// Open starts an interval, closing any other asset's hold on the address first.
//
// ============================================================================
// The close and the open are ONE statement pair in ONE transaction, because a
// gap between them is the ambiguous state migration 0031 exists to prevent.
// ============================================================================
//
// If a DHCP move opened the new interval without closing the old one, two assets
// would claim the address and every later correlation would find two candidates
// and return ambiguous rather than merging. Wrong announces itself; ambiguous
// degrades merge quality until somebody notices the inventory has doubled.
//
// The unique index is the backstop, not the mechanism: it turns the bug into an
// error instead of a silent duplicate. Both are wanted — the caller orders the
// statements correctly, and the database refuses if it ever does not.
func (AssetAddresses) Open(ctx context.Context, c *Conn, assetID uuid.UUID, ip string, at time.Time) error {
	const closeOthers = `
		UPDATE asset_addresses
		   SET valid_to = $4
		 WHERE tenant_id = $1 AND ip_address = $2::inet AND valid_to IS NULL
		   AND asset_id <> $3`
	if _, err := c.Exec(ctx, closeOthers, c.Tenant().UUID(), ip, assetID, at); err != nil {
		return mapError(err)
	}

	const open = `
		INSERT INTO asset_addresses (tenant_id, asset_id, ip_address, valid_from)
		SELECT $1, $2, $3::inet, $4
		 WHERE NOT EXISTS (
		     SELECT 1 FROM asset_addresses
		      WHERE tenant_id = $1 AND asset_id = $2 AND ip_address = $3::inet
		        AND valid_to IS NULL)`
	if _, err := c.Exec(ctx, open, c.Tenant().UUID(), assetID, ip, at); err != nil {
		return mapError(err)
	}
	return nil
}

// TouchLive refreshes when an asset was last seen at an address it already
// holds, without opening a second interval.
func (AssetAddresses) TouchLive(ctx context.Context, c *Conn, assetID uuid.UUID, ip string, at time.Time) error {
	const q = `
		UPDATE asset_addresses
		   SET valid_from = $4
		 WHERE tenant_id = $1 AND asset_id = $2 AND ip_address = $3::inet
		   AND valid_to IS NULL AND valid_from < $4`
	_, err := c.Exec(ctx, q, c.Tenant().UUID(), assetID, ip, at)
	return mapError(err)
}

// CloseStale ends intervals for addresses that have stopped being observed.
//
// ============================================================================
// This is what makes an address time-bounded rather than merely dated.
// ============================================================================
//
// `Open` closes another ASSET's hold, because two assets on one live address is
// the ambiguous state migration 0031 refuses. It deliberately does NOT close the
// same asset's other addresses: a host with two interfaces legitimately holds
// two, and a scan that saw one of them is not evidence the other is gone.
//
// So an address that simply stops being seen would stay open forever, and
// `valid_to IS NULL` would come to mean "was here once" rather than "is here
// now". Aging is the mechanism that keeps the column honest, and the cutoff is
// the same window that gives `ip_window` its meaning — outside it, the address
// is evidence of nothing.
//
// Closing is an UPDATE. The row stays, because the history is what makes an old
// finding's locator meaningful.
func (AssetAddresses) CloseStale(ctx context.Context, c *Conn, before, at time.Time) (int64, error) {
	const q = `
		UPDATE asset_addresses
		   SET valid_to = $3
		 WHERE tenant_id = $1 AND valid_to IS NULL AND valid_from < $2`
	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), before, at)
	if err != nil {
		return 0, mapError(err)
	}
	return tag.RowsAffected(), nil
}

// AssetIdentityKeys is ADR-007's ranked-key table.
type AssetIdentityKeys struct{}

// LiveByValue finds the asset currently holding a key, if any.
//
// This is correlation's central lookup, served by the partial unique index in
// migration 0007: a live key value is unique per tenant and type, because two
// assets holding the same strong key at once is the wrong-merge state the whole
// scheme exists to prevent.
func (AssetIdentityKeys) LiveByValue(ctx context.Context, c *Conn, t domain.IdentityKeyType, value string) (uuid.UUID, error) {
	const q = `
		SELECT asset_id
		  FROM asset_identity_keys
		 WHERE tenant_id = $1 AND key_type = $2::identity_key_type
		   AND key_value = $3 AND valid_to IS NULL`

	var id uuid.UUID
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), string(t), value).Scan(&id); err != nil {
		return uuid.Nil, mapError(err)
	}
	return id, nil
}

// SSHHostKeyFingerprintsAt returns the SSH host-key fingerprints CVAP has observed
// for the asset currently at an address. They are the trust root the credentialed-
// host engine verifies against on the fleet path (ADR-086/090) when no operator
// override is pinned — the value stored is a SHA256 fingerprint (evidence copies
// k.Fingerprint), which the engine matches by computing the presented key's own
// fingerprint. Empty (not an error) when the address has no live asset or the asset
// has no observed host key: the caller decides whether to refuse the job or fall
// back to an operator-pinned known_hosts.
//
// A key is trust material at an address only once TWO DISTINCT SCANS have seen
// it there (ADR-094), whatever verdict recorded it. First sight is not an
// enrolment: an attach happens on any address handover, and a "new asset" is
// first sight again the day an address interval ages out. Two sightings narrow
// the window — the attacker must persist across scans at that address rather
// than time one — they do not verify the key. The operator pin (ADR-091 §4,
// `operator` lines win outright) remains the answer; this is the default for
// fleets too large to pin. Keys from before ADR-094 have no sightings and are
// trusted nowhere until seen twice.
//
// Scoped to the SERVICE the key was observed on: the engine dials one port, and
// a key from a second sshd on 2222 says nothing about the daemon on 22 — nor is
// a key on 2222 a "contradiction" of the one on 22 for domain.Resolve, so the
// handover rule could not catch a key planted on another port. The port is part
// of the SIGHTING (asset_identity_key_sightings.port, from the observation's
// own source), NOT the key row's copied evidence payload: that payload is the
// observation that first recorded the key, so its port is where the key was
// first seen, and reading it refused a host serving one key on 2222 and 22 on
// 22 forever.
//
// The count is PER ADDRESS (asset_identity_key_sightings), not "the asset at
// this address holds the key": an attacker whose own host was enrolled
// normally, answering once at a keyless victim's address, merges the victim's
// address onto their asset — the scan that moved the address counts once,
// there, and a second is needed there. A dual-homed host counts at each of its
// addresses independently.
//
// And a sighting AGES: only rows last seen within `within` count — the same
// window that closes a stale address interval — because a count that never
// decays makes the two-scan cost a one-time payment: an attacker who paid it,
// left, and returned months later would be trusted again on one scan.
func (AssetIdentityKeys) SSHHostKeyFingerprintsAt(ctx context.Context, c *Conn, ip string, port int, within time.Duration) ([]string, error) {
	const q = `
		SELECT DISTINCT k.key_value
		  FROM asset_addresses a
		  JOIN asset_identity_keys k
		    ON k.tenant_id = a.tenant_id AND k.asset_id = a.asset_id
		  JOIN asset_identity_key_sightings s
		    ON s.tenant_id = k.tenant_id AND s.identity_key_id = k.identity_key_id
		 WHERE a.tenant_id = $1 AND a.ip_address = $2::inet AND a.valid_to IS NULL
		   AND k.key_type = 'ssh_hostkey'::identity_key_type AND k.valid_to IS NULL
		   AND s.address = $2::inet AND s.port = $3 AND s.scans_seen >= 2
		   AND s.last_seen_at >= $4`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), ip, port, time.Now().Add(-within))
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, mapError(err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return out, nil
}

// ForAsset returns the live keys an asset holds, for the resolver's candidates.
func (AssetIdentityKeys) ForAsset(ctx context.Context, c *Conn, assetID uuid.UUID) ([]domain.IdentityKey, error) {
	// The SOURCE is derived from the copied evidence rather than stored beside
	// it, because there is no column for it and inventing one would be a
	// migration for something the payload already contains.
	//
	// It matters for conflict detection: `compare` treats a differing value as a
	// contradiction only when it came from the SAME service, so a host with two
	// certificates on two ports is not contradicting itself. With the source
	// blank on every held key, a rotated key on one port would look like a
	// different service rather than a conflict.
	const q = `
		SELECT key_type, key_value,
		       CASE WHEN merge_evidence_payload ? 'port'
		            THEN (merge_evidence_payload ->> 'port') || '/' ||
		                 coalesce(merge_evidence_payload ->> 'protocol', 'tcp')
		            ELSE '' END
		  FROM asset_identity_keys
		 WHERE tenant_id = $1 AND asset_id = $2 AND valid_to IS NULL`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), assetID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []domain.IdentityKey
	for rows.Next() {
		var k domain.IdentityKey
		if err := rows.Scan(&k.Type, &k.Value, &k.Source); err != nil {
			return nil, mapError(err)
		}
		out = append(out, k)
	}
	return out, mapError(rows.Err())
}

// SightingWindow is how long a sighting counts toward ADR-091 observed trust
// (ADR-094). It equals correlate.AddressWindow — the window inside which an
// address is evidence a host has not changed — and correlate's tests assert
// the two stay equal; a trust root that outlived the address relationship it
// rests on would trust a key at an address nobody has held for a week.
const SightingWindow = 7 * 24 * time.Hour

// KeyProvenance mirrors identity_key_provenance (migration 0044, ADR-094): how a
// key came to be held. Audit only — trust is decided by the sightings table,
// never by the verdict that first recorded the key.
type KeyProvenance string

const (
	KeyFromMerge    KeyProvenance = "merge"
	KeyFromNewAsset KeyProvenance = "new_asset"
	KeyFromAttach   KeyProvenance = "attach"
)

// Record writes a key with its merge evidence.
//
// ============================================================================
// The evidence payload is COPIED, not referenced (ADR-007).
// ============================================================================
//
// `merge_evidence_observation` is a soft reference with no foreign key, because
// observations are partitioned monthly and pruned by dropping the partition
// (ADR-016) — a hard FK would block or fail that drop. The column is expected to
// point at a row that no longer exists, which is why the payload sits beside it.
//
// Merge evidence is a distinct retention class from bulk observations: it must
// outlive the 90-day window, and copying rather than pinning the source
// partition is what lets ADR-016 keep pruning by partition drop. Pinning would
// hold an entire month alive for one merge.
//
// The consequence the schema comment names and this is the code that carries it:
// this copy is duplicated data that must be redacted to the same standard as the
// observation it came from, because it now outlives the retention window that
// would otherwise have removed it.
//
// provenance says how the verdict came to record it (ADR-094) — kept for the
// audit trail, never upgraded, and not what decides trust. The sighting is:
// scanID, address and port name the occasion — one row per (key, address, port)
// in asset_identity_key_sightings, scans_seen incremented only when the scan is
// DIFFERENT from the last one that saw the key there and later in time. The
// occasion is the scan, not a timestamp: two address groups in one sweep carry
// two timestamps and the batch cut splits one scan across two sweeps, and each
// inflated a timestamp-based count from a single scan. Any verdict counts, a
// merge included — its sighting counts once, at its own address, which is what
// keeps a merge from promoting the keys that justified it. A key another asset
// holds live is left where it is and gains no sighting here (the verdict that
// reached here was not a merge or a queue, so it cannot be this asset's).
//
// port is the service the key was seen on (from the key's source); a sighting
// is per (key, address, port), so a key seen only on 2222 is never trust for 22.
func (AssetIdentityKeys) Record(ctx context.Context, c *Conn, assetID uuid.UUID, k domain.IdentityKey, at time.Time, provenance KeyProvenance, scanID uuid.UUID, address string, port int) error {
	const insert = `
		INSERT INTO asset_identity_keys
		    (tenant_id, asset_id, key_type, key_value, strength,
		     merge_evidence_observation, merge_evidence_payload, valid_from, provenance)
		VALUES ($1, $2, $3::identity_key_type, $4, $5, $6, $7, $8, $9::identity_key_provenance)
		ON CONFLICT (tenant_id, key_type, key_value) WHERE valid_to IS NULL
		DO NOTHING`

	var obsID any
	if k.ObservationID != uuid.Nil {
		obsID = k.ObservationID
	}
	payload := k.Payload
	if obsID == nil {
		// The schema requires both or neither: half the evidence is worse than
		// none, because it looks complete.
		payload = nil
	}
	if _, err := c.Exec(ctx, insert, c.Tenant().UUID(), assetID, string(k.Type), k.Value,
		k.Type.Strength(), obsID, payload, at, string(provenance)); err != nil {
		return mapError(err)
	}
	if scanID == uuid.Nil || address == "" || port <= 0 || port > 65535 {
		return nil // no occasion to count
	}

	// The sighting, only for the live row THIS asset holds.
	const sight = `
		INSERT INTO asset_identity_key_sightings
		    (tenant_id, identity_key_id, address, port, scans_seen, last_seen_scan, last_seen_at)
		SELECT $1, k.identity_key_id, $5::inet, $8, 1, $3, $4
		  FROM asset_identity_keys k
		 WHERE k.tenant_id = $1 AND k.asset_id = $2 AND k.key_type = $6::identity_key_type
		   AND k.key_value = $7 AND k.valid_to IS NULL
		ON CONFLICT (tenant_id, identity_key_id, address, port)
		DO UPDATE SET scans_seen = CASE
		                  WHEN asset_identity_key_sightings.last_seen_at < EXCLUDED.last_seen_at - $9::interval THEN 1
		                  ELSE asset_identity_key_sightings.scans_seen + 1
		              END,
		              last_seen_scan = EXCLUDED.last_seen_scan,
		              last_seen_at = EXCLUDED.last_seen_at
		      WHERE EXCLUDED.last_seen_scan IS DISTINCT FROM asset_identity_key_sightings.last_seen_scan
		        AND EXCLUDED.last_seen_at > asset_identity_key_sightings.last_seen_at`
	// The count DECAYS with the window it is read at: a sighting more than
	// SightingWindow after the previous one starts over at 1, so an attacker
	// who paid the two-scan cost, left, and returned is not trusted on the
	// return — the review measured "at least two ever, and one recently" being
	// satisfied by exactly that. Anything scanned more often than its address
	// window never crosses the reset.
	_, err := c.Exec(ctx, sight, c.Tenant().UUID(), assetID, scanID, at, address, string(k.Type), k.Value, port,
		SightingWindow.String())
	return mapError(err)
}

// EstablishedAt reports whether the asset holds this key live and it has been
// seen at the address, on the port, by two distinct scans inside the window —
// the same bar the trust root sets. A key that agrees but is not established
// cannot corroborate a contradiction (ADR-094): an attach can write what the
// asset holds, so an attacker who planted a key one scan earlier would
// otherwise corroborate their own certificate with it the next.
func (AssetIdentityKeys) EstablishedAt(ctx context.Context, c *Conn, assetID uuid.UUID, k domain.IdentityKey, address string, port int, within time.Duration) (bool, error) {
	const q = `
		SELECT EXISTS (
		    SELECT 1 FROM asset_identity_keys k
		      JOIN asset_identity_key_sightings s
		        ON s.tenant_id = k.tenant_id AND s.identity_key_id = k.identity_key_id
		     WHERE k.tenant_id = $1 AND k.asset_id = $2 AND k.key_type = $3::identity_key_type
		       AND k.key_value = $4 AND k.valid_to IS NULL
		       AND s.address = $5::inet AND s.port = $6 AND s.scans_seen >= 2
		       AND s.last_seen_at >= $7)`
	var ok bool
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), assetID, string(k.Type), k.Value, address, port,
		time.Now().Add(-within)).Scan(&ok); err != nil {
		return false, mapError(err)
	}
	return ok, nil
}

// Retire closes the live key of one type the asset holds from one service
// (the port its evidence names), so a renewed value can take its place
// (ADR-094). Closing is an UPDATE of valid_to, never a DELETE: the history is
// what makes the old value's findings and merges reviewable. Returns how many
// rows closed — zero when the asset held nothing of that type from that port.
func (AssetIdentityKeys) Retire(ctx context.Context, c *Conn, assetID uuid.UUID, t domain.IdentityKeyType, port int, at time.Time) (int64, error) {
	const q = `
		UPDATE asset_identity_keys
		   SET valid_to = $5
		 WHERE tenant_id = $1 AND asset_id = $2 AND key_type = $3::identity_key_type
		   AND valid_to IS NULL
		   AND merge_evidence_payload -> 'port' = to_jsonb($4::int)`
	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), assetID, string(t), port, at)
	if err != nil {
		return 0, mapError(err)
	}
	return tag.RowsAffected(), nil
}

// ResolutionQueue is ADR-007's unresolved merge queue (migration 0013).
type ResolutionQueue struct{}

// Enqueue records evidence a human has to adjudicate.
//
// Like the identity keys above, the observed payload is COPIED rather than
// referenced: a queue item must stay adjudicable after the observation that
// raised it has aged out, or the queue silently empties itself of anything older
// than 90 days.
func (ResolutionQueue) Enqueue(ctx context.Context, c *Conn, v domain.Verdict, k domain.IdentityKey, at time.Time) error {
	// One pending item per (observation, key): migration 0013 built
	// asset_resolution_queue_by_key_idx for exactly this check and the check
	// was never written, so one flapping key became a queue entry per sweep.
	const q = `
		INSERT INTO asset_resolution_queue
		    (tenant_id, observation_id, observed_payload, key_type, key_value,
		     candidate_asset_ids, conflict_reason, enqueued_at)
		SELECT $1, $2, $3, $4::identity_key_type, $5, $6, $7, $8
		 WHERE NOT EXISTS (
		     SELECT 1 FROM asset_resolution_queue q
		      WHERE q.tenant_id = $1 AND q.observation_id IS NOT DISTINCT FROM $2::uuid
		        AND q.key_type = $4::identity_key_type AND q.key_value = $5
		        AND q.state = 'pending')`

	payload := k.Payload
	if len(payload) == 0 {
		// The column is NOT NULL: an item with no evidence cannot be
		// adjudicated, and an empty object says that honestly.
		payload = []byte(`{}`)
	}
	var obsID any
	if k.ObservationID != uuid.Nil {
		obsID = k.ObservationID
	}

	_, err := c.Exec(ctx, q, c.Tenant().UUID(), obsID, payload,
		string(k.Type), k.Value, v.Candidates, v.Reason, at)
	return mapError(err)
}

// PendingCount is what a health surface reports: a queue nobody works is a queue
// that is not doing its job, and the count is the cheapest way to notice.
func (ResolutionQueue) PendingCount(ctx context.Context, c *Conn) (int64, error) {
	const q = `SELECT count(*) FROM asset_resolution_queue
	            WHERE tenant_id = $1 AND state = 'pending'`
	var n int64
	err := c.QueryRow(ctx, q, c.Tenant().UUID()).Scan(&n)
	return n, mapError(err)
}
