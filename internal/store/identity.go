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
func (AssetIdentityKeys) SSHHostKeyFingerprintsAt(ctx context.Context, c *Conn, ip string) ([]string, error) {
	const q = `
		SELECT DISTINCT k.key_value
		  FROM asset_addresses a
		  JOIN asset_identity_keys k
		    ON k.tenant_id = a.tenant_id AND k.asset_id = a.asset_id
		 WHERE a.tenant_id = $1 AND a.ip_address = $2::inet AND a.valid_to IS NULL
		   AND k.key_type = 'ssh_hostkey'::identity_key_type AND k.valid_to IS NULL`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), ip)
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
func (AssetIdentityKeys) Record(ctx context.Context, c *Conn, assetID uuid.UUID, k domain.IdentityKey, at time.Time) error {
	const q = `
		INSERT INTO asset_identity_keys
		    (tenant_id, asset_id, key_type, key_value, strength,
		     merge_evidence_observation, merge_evidence_payload, valid_from)
		VALUES ($1, $2, $3::identity_key_type, $4, $5, $6, $7, $8)
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

	_, err := c.Exec(ctx, q, c.Tenant().UUID(), assetID, string(k.Type), k.Value,
		k.Type.Strength(), obsID, payload, at)
	return mapError(err)
}

// ResolutionQueue is ADR-007's unresolved queue (migration 0013).
type ResolutionQueue struct{}

// Enqueue records evidence a human has to adjudicate.
//
// Like the identity keys above, the observed payload is COPIED rather than
// referenced: a queue item must stay adjudicable after the observation that
// raised it has aged out, or the queue silently empties itself of anything older
// than 90 days.
func (ResolutionQueue) Enqueue(ctx context.Context, c *Conn, v domain.Verdict, k domain.IdentityKey, at time.Time) error {
	const q = `
		INSERT INTO asset_resolution_queue
		    (tenant_id, observation_id, observed_payload, key_type, key_value,
		     candidate_asset_ids, conflict_reason, enqueued_at)
		VALUES ($1, $2, $3, $4::identity_key_type, $5, $6, $7, $8)`

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
