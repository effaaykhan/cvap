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
		 WHERE tenant_id = $1 AND ip_address = host($2::inet)::inet AND valid_to IS NULL`

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
// The address is stored as a bare host (`host(x)::inet`): inet equality
// includes the mask, so `10.44.3.10/24` and `10.44.3.10` were two live rows
// under migration 0031's unique index, on two assets, and every by-address
// read keyed on the spelling (measured). Correlation canonicalises before it
// gets here; the write normalises again so no other caller can reintroduce it.
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
		 WHERE tenant_id = $1 AND ip_address = host($2::inet)::inet AND valid_to IS NULL
		   AND asset_id <> $3`
	if _, err := c.Exec(ctx, closeOthers, c.Tenant().UUID(), ip, assetID, at); err != nil {
		return mapError(err)
	}

	const open = `
		INSERT INTO asset_addresses (tenant_id, asset_id, ip_address, valid_from)
		SELECT $1, $2, host($3::inet)::inet, $4
		 WHERE NOT EXISTS (
		     SELECT 1 FROM asset_addresses
		      WHERE tenant_id = $1 AND asset_id = $2 AND ip_address = host($3::inet)::inet
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
		 WHERE tenant_id = $1 AND asset_id = $2 AND ip_address = host($3::inet)::inet
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
//
// A CONTESTED address does not age out (ADR-096): a park touches no address
// interval, so the occupant's hold on an address where a contradiction is
// pending would lapse after the window, and the next sighting of the
// contradicting host — no candidate by key, none by address — would become a
// NEW asset there, with a key the trust root does not exclude. The review
// measured exactly that: seven days of holding tcp/22 was cheaper than passing
// the classification. While an item PARKED INSIDE THE WINDOW names the holder,
// the address stays held and every later sighting there is judged against it.
// Bounded by the same window as everything else here: an unbounded hold was
// measured keeping a dead occupant's address for ever — a genuine newcomer
// never inventoried, and a third host attaching to the dead asset on the
// address alone. A stale park ages out like any other silence.
func (AssetAddresses) CloseStale(ctx context.Context, c *Conn, before, at time.Time) (int64, error) {
	const q = `
		UPDATE asset_addresses a
		   SET valid_to = $3
		 WHERE a.tenant_id = $1 AND a.valid_to IS NULL AND a.valid_from < $2
		   AND NOT EXISTS (
		       SELECT 1 FROM asset_resolution_queue q
		        WHERE q.tenant_id = a.tenant_id AND q.state = 'pending'
		          AND q.address = a.ip_address
		          AND a.asset_id = ANY (q.candidate_asset_ids)
		          AND q.enqueued_at >= $2)`
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
// A key recorded by a ROTATION or a LAPSE (ADR-096) is excluded whatever its
// sightings — a lapse is the same contest one window later, and recording it
// as trust was measured buying the root with one window of holding tcp/22
// against a live host. A rotation is excluded
// the classification sees banners only, and a takeover of the SSH port alone at
// the address across two scans is indistinguishable from a real rotation — the
// security review measured the attacker's key becoming this trust root three
// scans after taking port 22 while the host kept answering everything else. A
// contradiction is the signal the trust root exists to catch, so it is never
// re-rooted by the thing that observed the contradiction; the operator pins the
// new key (ADR-091 §4) or confirms the rotation (B39), and until then the
// credentialed job at that host refuses. Inventory moves; trust does not.
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
		 WHERE a.tenant_id = $1 AND a.ip_address = host($2::inet)::inet AND a.valid_to IS NULL
		   AND k.key_type = 'ssh_hostkey'::identity_key_type AND k.valid_to IS NULL
		   AND k.provenance NOT IN ('rotation', 'lapsed')
		   AND s.address = host($2::inet)::inet AND s.port = $3 AND s.scans_seen >= 2
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
		                 coalesce(nullif(merge_evidence_payload ->> 'protocol', ''), 'tcp')
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
	// KeyFromRotation: recorded by an attach that classified a same-service
	// SSH host-key contradiction as a key rotation (ADR-096, migration 0045).
	KeyFromRotation KeyProvenance = "rotation"
	// KeyFromLapsed: recorded by a new asset that displaced an address holder
	// whose key had been silent for a full window under a fresh contest
	// (ADR-096). Excluded from the trust root like a rotation.
	KeyFromLapsed KeyProvenance = "lapsed"
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
//
// Returns whether the KEY ROW was written: false when the value is already
// live — on this asset (a re-sighting, the usual case) or on ANOTHER asset,
// which the caller must tell apart with LiveByValue, because a silent no-op
// there leaves an asset keyless (measured: a returning host became a third,
// keyless asset that could never re-merge). The sighting is counted either way
// for this asset's own live row.
func (AssetIdentityKeys) Record(ctx context.Context, c *Conn, assetID uuid.UUID, k domain.IdentityKey, at time.Time, provenance KeyProvenance, scanID uuid.UUID, address string, port int) (bool, error) {
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
	tag, err := c.Exec(ctx, insert, c.Tenant().UUID(), assetID, string(k.Type), k.Value,
		k.Type.Strength(), obsID, payload, at, string(provenance))
	if err != nil {
		return false, mapError(err)
	}
	inserted := tag.RowsAffected() > 0
	if scanID == uuid.Nil || address == "" || port <= 0 || port > 65535 {
		return inserted, nil // no occasion to count
	}

	// The sighting, only for the live row THIS asset holds.
	const sight = `
		INSERT INTO asset_identity_key_sightings
		    (tenant_id, identity_key_id, address, port, scans_seen, last_seen_scan, last_seen_at)
		SELECT $1, k.identity_key_id, host($5::inet)::inet, $8, 1, $3, $4
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
	if _, err := c.Exec(ctx, sight, c.Tenant().UUID(), assetID, scanID, at, address, string(k.Type), k.Value, port,
		SightingWindow.String()); err != nil {
		return false, mapError(err)
	}
	return inserted, nil
}

// EstablishedAt reports whether the asset holds this key live and it has been
// seen at the address, on the port, by two distinct scans inside the window —
// the same bar the trust root sets. A key that agrees but is not established
// cannot corroborate a contradiction (ADR-094): an attach can write what the
// asset holds, so an attacker who planted a key one scan earlier would
// otherwise corroborate their own certificate with it the next.
//
// A key recorded by a ROTATION or a LAPSE never establishes, however many
// scans see it (ADR-096): the same bar the trust root sets, for the same
// reason — the review measured a rotation key, withheld from the trust root,
// reaching two sightings on a scan where the attacker withheld 443 and then
// corroborating its own certificate against the victim's, which handed the
// attacker two moderate keys of trusting provenance on the victim's asset and
// a merge at any address it controlled. Until an operator confirms, such a
// key corroborates nothing.
func (AssetIdentityKeys) EstablishedAt(ctx context.Context, c *Conn, assetID uuid.UUID, k domain.IdentityKey, address string, port int, within time.Duration) (bool, error) {
	const q = `
		SELECT EXISTS (
		    SELECT 1 FROM asset_identity_keys k
		      JOIN asset_identity_key_sightings s
		        ON s.tenant_id = k.tenant_id AND s.identity_key_id = k.identity_key_id
		     WHERE k.tenant_id = $1 AND k.asset_id = $2 AND k.key_type = $3::identity_key_type
		       AND k.key_value = $4 AND k.valid_to IS NULL
		       AND k.provenance NOT IN ('rotation', 'lapsed')
		       AND s.address = host($5::inet)::inet AND s.port = $6 AND s.scans_seen >= 2
		       AND s.last_seen_at >= $7)`
	var ok bool
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), assetID, string(k.Type), k.Value, address, port,
		time.Now().Add(-within)).Scan(&ok); err != nil {
		return false, mapError(err)
	}
	return ok, nil
}

// LastSeenAt is ADR-096's second continuity fact: when the live key of one
// type the asset holds from one service was last sighted at an address. found
// is false when the asset holds no such key or it was never sighted there.
func (AssetIdentityKeys) LastSeenAt(ctx context.Context, c *Conn, assetID uuid.UUID, t domain.IdentityKeyType, port int, address string) (at time.Time, found bool, err error) {
	const q = `
		SELECT max(s.last_seen_at)
		  FROM asset_identity_keys k
		  JOIN asset_identity_key_sightings s
		    ON s.tenant_id = k.tenant_id AND s.identity_key_id = k.identity_key_id
		 WHERE k.tenant_id = $1 AND k.asset_id = $2 AND k.key_type = $3::identity_key_type
		   AND k.valid_to IS NULL
		   AND k.merge_evidence_payload -> 'port' = to_jsonb($4::int)
		   AND s.address = $5::inet AND s.port = $4`
	var last *time.Time
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), assetID, string(t), port, address).Scan(&last); err != nil {
		return time.Time{}, false, mapError(err)
	}
	if last == nil {
		return time.Time{}, false, nil
	}
	return *last, true, nil
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
//
// Returns whether an item was written: a repeat of the same (observation, key)
// is a no-op, and the caller raises the operator-facing signal only for the
// first (ADR-096 — a park that nothing announces is a disappearance).
func (ResolutionQueue) Enqueue(ctx context.Context, c *Conn, v domain.Verdict, k domain.IdentityKey, address string, at time.Time) (bool, error) {
	// One pending item per (observation, key): migration 0013 built
	// asset_resolution_queue_by_key_idx for exactly this check and the check
	// was never written, so one flapping key became a queue entry per sweep.
	const q = `
		INSERT INTO asset_resolution_queue
		    (tenant_id, observation_id, observed_payload, key_type, key_value,
		     candidate_asset_ids, conflict_reason, enqueued_at, address)
		SELECT $1, $2, $3, $4::identity_key_type, $5, $6, $7, $8, host($9::inet)::inet
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
	// An item may name NO candidate (two hosts answering on one port at an
	// address nothing holds, ADR-096): the column is NOT NULL, the array is
	// empty, and the item reads "unplaceable" rather than "choose one".
	cands := v.Candidates
	if cands == nil {
		cands = []uuid.UUID{}
	}

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), obsID, payload,
		string(k.Type), k.Value, cands, v.Reason, at, address)
	if err != nil {
		return false, mapError(err)
	}
	return tag.RowsAffected() > 0, nil
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

// A queue item's address is the normalised `address inet` column (migration
// 0045), written once by Enqueue and backfilled for older rows from the copied
// payload or the ip_window key value. Every by-address read compares inet to
// inet: the first draft compared the payload's TEXT to host(inet), and the
// review measured a non-canonical spelling ageing the occupant out of its
// address and handing the trust root to the newcomer. A row whose address
// could not be parsed at backfill is NULL and counts for nothing.

// PendingAddresses counts the ADDRESSES with a pending item — the number an
// operator acts on (one contested host, however many observations it parked).
// The DISTINCT runs in a subquery over the extracted text, not as
// count(DISTINCT expr) over the row: the latter sorts every pending row with
// its jsonb payload (measured: 296 ms and 115 MB of disk sort at 100k items,
// on a route any scan.read caller can hit), the former 79 ms and 2 MB.
func (ResolutionQueue) PendingAddresses(ctx context.Context, c *Conn) (int64, error) {
	const q = `SELECT count(*) FROM (
	              SELECT DISTINCT address
	                FROM asset_resolution_queue
	               WHERE tenant_id = $1 AND state = 'pending') x
	            WHERE x.address IS NOT NULL`
	var n int64
	err := c.QueryRow(ctx, q, c.Tenant().UUID()).Scan(&n)
	return n, mapError(err)
}

// PendingAtAddress reports whether an item is pending at the address naming
// the asset among its candidates (ADR-096): a weak-only sighting there then
// waits with the contradiction instead of attaching.
func (ResolutionQueue) PendingAtAddress(ctx context.Context, c *Conn, address string, assetID uuid.UUID) (bool, error) {
	const q = `SELECT EXISTS (
	              SELECT 1 FROM asset_resolution_queue
	               WHERE tenant_id = $1 AND state = 'pending'
	                 AND address = host($2::inet)::inet
	                 AND $3 = ANY (candidate_asset_ids))`
	var ok bool
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), address, assetID).Scan(&ok)
	return ok, mapError(err)
}

// ContradictionLastSeen is when a CONTRADICTING key was last parked at the
// address naming the asset (ADR-096): a key of a type the asset holds live
// FROM THE SAME PORT with a different value — domain.Resolve's definition of
// a conflict at the held address, which carves CERTIFICATES out (a renewal is
// the same host, ADR-094) and this read carves them out too: a renewed
// certificate parked with a contested group would otherwise be "a different
// value on the same port" on every scan and keep the contest fresh for ever
// (measured, six weeks). Named by exclusion, not `= 'ssh_hostkey'`, so a
// strong key type this build cannot yet observe still counts. And a key the
// asset ITSELF holds live is never a contradiction, whatever else it holds:
// migration 0045's one-live-key-per-port index makes that state unreachable,
// and the predicate says so anyway (measured: an asset holding two keys on
// one port kept its own park fresh with its own key for ever). Zero, found=false, when no such item is pending. A key the
// asset merely has not recorded (TLS the occupant enabled after the park, a
// second sshd) contradicts nothing and must not keep the contest fresh; the
// review measured the first draft's "not held" predicate freezing an
// occupant on its own evidence for six weeks. The domain decides from this
// whether the contest is still fresh: a contradiction nobody has re-presented
// for a full window has gone stale, and a park with no expiry would freeze
// the host for ever on one drive-by packet.
func (ResolutionQueue) ContradictionLastSeen(ctx context.Context, c *Conn, address string, assetID uuid.UUID) (time.Time, bool, error) {
	const q = `
		SELECT max(q.enqueued_at) FROM asset_resolution_queue q
		 WHERE q.tenant_id = $1 AND q.state = 'pending'
		   AND q.address = host($2::inet)::inet
		   AND $3 = ANY (q.candidate_asset_ids)
		   AND q.key_type NOT IN ('ip_window', 'service_cert_fp')
		   AND EXISTS (SELECT 1 FROM asset_identity_keys k
		                WHERE k.tenant_id = q.tenant_id AND k.asset_id = $3 AND k.valid_to IS NULL
		                  AND k.key_type = q.key_type AND k.key_value <> q.key_value
		                  AND k.merge_evidence_payload -> 'port' = q.observed_payload -> 'port')
		   AND NOT EXISTS (SELECT 1 FROM asset_identity_keys k2
		                    WHERE k2.tenant_id = q.tenant_id AND k2.asset_id = $3 AND k2.valid_to IS NULL
		                      AND k2.key_type = q.key_type AND k2.key_value = q.key_value)`
	var last *time.Time
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), address, assetID).Scan(&last); err != nil {
		return time.Time{}, false, mapError(err)
	}
	if last == nil {
		return time.Time{}, false, nil
	}
	return *last, true, nil
}

// CloseExpired closes every pending item at the address naming the asset as
// `expired`: the domain judged the contest stale and the sighting attached
// (ADR-096). The parked observations do NOT re-enter the sweep — ListUnresolved
// excludes expired items — because released, the same contradicting
// observation re-parked itself with a fresh timestamp and renewed the freeze
// for ever (measured). What the freeze withheld is gone; what the host still
// answers is re-derived by the sighting that attached. Returns how many.
func (ResolutionQueue) CloseExpired(ctx context.Context, c *Conn, address string, assetID uuid.UUID, at time.Time) (int64, error) {
	const q = `
		UPDATE asset_resolution_queue
		   SET state = 'expired', resolved_at = $4
		 WHERE tenant_id = $1 AND state = 'pending'
		   AND address = host($2::inet)::inet
		   AND $3 = ANY (candidate_asset_ids)`
	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), address, assetID, at)
	if err != nil {
		return 0, mapError(err)
	}
	return tag.RowsAffected(), nil
}

// ExpireUnplaceable closes, as `expired`, pending items parked before
// `before` that no transition can reach any more (ADR-096): items naming NO
// candidate (two hosts answered on one port at an address nothing held —
// nobody was ever going to be chosen), and items none of whose candidates
// still holds the address live (the occupant aged out and another host took
// the address; CloseExpired and CloseRotated are keyed on the named asset
// attaching THERE, which it never will). Both were measured pending for
// sixty days with the Health chip amber and nothing an operator could do.
// Nothing is lost — the observations were never placeable. Returns how many.
// Returns the distinct addresses whose items closed, so the caller can
// announce them: a close-out nothing records is a refusal that vanished.
func (ResolutionQueue) ExpireUnplaceable(ctx context.Context, c *Conn, before, at time.Time) ([]string, error) {
	const q = `
		UPDATE asset_resolution_queue q
		   SET state = 'expired', resolved_at = $3
		 WHERE q.tenant_id = $1 AND q.state = 'pending'
		   AND q.enqueued_at < $2
		   AND (cardinality(q.candidate_asset_ids) = 0
		        OR NOT EXISTS (SELECT 1 FROM asset_addresses a
		                        WHERE a.tenant_id = q.tenant_id AND a.valid_to IS NULL
		                          AND a.ip_address = q.address
		                          AND a.asset_id = ANY (q.candidate_asset_ids)))
		 RETURNING host(q.address)`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), before, at)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var a *string
		if err := rows.Scan(&a); err != nil {
			return nil, mapError(err)
		}
		if a == nil || seen[*a] {
			continue
		}
		seen[*a] = true
		out = append(out, *a)
	}
	return out, mapError(rows.Err())
}

// KeyScansPending is ADR-096's key history from the queue: the DISTINCT scans
// on which a key was seen at an address and parked, and the earliest and
// latest of those sightings. It serves BOTH sides of the comparison — the
// newcomer's scans and the held key's last answer — because a scan that parks
// writes no sighting row, and a held key that answered during a parked scan
// is exactly what the comparison must see (the review measured it missed). The occasion is the observation's scan, read through the task —
// the same occasion a recorded key's sighting counts (ADR-094) — so the
// observations must still exist: bounded by `since`, the address window,
// inside which they do. An item whose observation has aged out counts for
// nothing, which is the conservative direction.
func (ResolutionQueue) KeyScansPending(ctx context.Context, c *Conn, t domain.IdentityKeyType, value, address string, since time.Time) (scans []uuid.UUID, first, last time.Time, err error) {
	const q = `
		SELECT DISTINCT j.scan_id, min(o.observed_at) OVER (), max(o.observed_at) OVER ()
		  FROM asset_resolution_queue q
		  JOIN observations o ON o.tenant_id = q.tenant_id AND o.observation_id = q.observation_id
		  JOIN scan_tasks t ON t.tenant_id = o.tenant_id AND t.task_id = o.task_id
		  JOIN scan_jobs j ON j.tenant_id = t.tenant_id AND j.job_id = t.job_id
		 WHERE q.tenant_id = $1 AND q.state = 'pending'
		   AND q.key_type = $2::identity_key_type AND q.key_value = $3
		   AND q.address = host($4::inet)::inet
		   AND q.enqueued_at >= $5 AND o.observed_at >= $5`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), string(t), value, address, since)
	if err != nil {
		return nil, time.Time{}, time.Time{}, mapError(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id, &first, &last); err != nil {
			return nil, time.Time{}, time.Time{}, mapError(err)
		}
		scans = append(scans, id)
	}
	return scans, first, last, mapError(rows.Err())
}

// CloseRotated closes, as `rotated`, the pending items at an address that
// name the asset AND that the rotation examined: items carrying a key the
// asset now holds live (the classified key, just recorded; a key that agreed
// all along — a park enqueues every key in the group), items carrying a
// certificate the verdict forgave as a renewal (left to the establishment
// gate, not recorded here), and the address-only items whose park (same
// address, same enqueue instant — one park is one transaction) carried no
// keyed item left unexamined: the siblings of the classified keys, and the
// keyless stragglers parked on the address alone because the contest was
// fresh. An item parked for a DIFFERENT contradiction stays pending, and so
// do the keyless siblings parked with it: the classification never examined
// it, and closing it would let the queue assert a decision nobody made (the
// review measured six closed for two classified). An item that nothing could
// ever close would keep the address contested forever (measured too).
// resolved_by stays NULL: no operator chose. The parked observations then
// re-enter the sweep and attach on the next pass. Returns how many closed.
func (ResolutionQueue) CloseRotated(ctx context.Context, c *Conn, address string, assetID uuid.UUID, examined []domain.IdentityKey, at time.Time) (int64, error) {
	keys := make([]string, 0, len(examined))
	for _, k := range examined {
		keys = append(keys, string(k.Type)+":"+k.Value)
	}
	const q = `
		UPDATE asset_resolution_queue q
		   SET state = 'rotated', resolved_asset_id = $3, resolved_at = $4
		 WHERE q.tenant_id = $1 AND q.state = 'pending'
		   AND q.address = host($2::inet)::inet
		   AND $3 = ANY (q.candidate_asset_ids)
		   AND (q.key_type::text || ':' || q.key_value = ANY ($5::text[])
		        OR EXISTS (SELECT 1 FROM asset_identity_keys k
		                    WHERE k.tenant_id = q.tenant_id AND k.asset_id = $3
		                      AND k.key_type = q.key_type AND k.key_value = q.key_value
		                      AND k.valid_to IS NULL)
		        OR (q.key_type = 'ip_window' AND NOT EXISTS (
		                SELECT 1 FROM asset_resolution_queue x
		                 WHERE x.tenant_id = q.tenant_id AND x.state = 'pending'
		                   AND x.address = q.address AND x.enqueued_at = q.enqueued_at
		                   AND x.key_type <> 'ip_window'
		                   AND NOT (x.key_type::text || ':' || x.key_value = ANY ($5::text[]))
		                   AND NOT EXISTS (SELECT 1 FROM asset_identity_keys k
		                                    WHERE k.tenant_id = x.tenant_id AND k.asset_id = $3
		                                      AND k.key_type = x.key_type AND k.key_value = x.key_value
		                                      AND k.valid_to IS NULL))))`
	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), address, assetID, at, keys)
	if err != nil {
		return 0, mapError(err)
	}
	return tag.RowsAffected(), nil
}
