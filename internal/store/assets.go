package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Criticality string

const (
	CriticalityUnknown  Criticality = "unknown"
	CriticalityLow      Criticality = "low"
	CriticalityMedium   Criticality = "medium"
	CriticalityHigh     Criticality = "high"
	CriticalityCritical Criticality = "critical"
)

// Asset is derived by Core from observations (ADR-006). Nothing in this package
// derives anything — these are persistence methods for the derivation stage in
// internal/control to call.
//
// There is no Zone field, and adding one is a blocker (ADR-008). Assets move;
// a stored zone is wrong shortly after it is written, and wrong in the specific
// way that corrupts exposure reporting. Zone belongs to the observation, and
// exposure is derived from which vantage points saw what.
//
// There is likewise no current-IP field. An IP is a time-bounded relationship,
// held in asset_addresses with valid_from / valid_to.
type Asset struct {
	ID          uuid.UUID
	Hostname    string
	OSFamily    string
	OSVersion   string
	DeviceType  string
	Vendor      string
	Criticality Criticality
	Environment string
	Owner       string

	// Fragile caps scan rate and suppresses aggressive checks regardless of
	// what the policy permits (ADR-024). It travels to the scan point per Task,
	// because it is a Core-held attribute the scan point cannot derive.
	Fragile bool

	FirstSeen time.Time
	LastSeen  time.Time
}

type Assets struct{}

func (Assets) Create(ctx context.Context, c *Conn, a Asset) (*Asset, error) {
	const q = `
		INSERT INTO assets (tenant_id, primary_hostname, os_family, os_version,
		                    device_type, vendor, criticality, environment, owner, fragile)
		VALUES ($1, nullif($2,''), nullif($3,''), nullif($4,''), nullif($5,''),
		        nullif($6,''), coalesce(nullif($7,'')::asset_criticality, 'unknown'),
		        nullif($8,''), nullif($9,''), $10)
		RETURNING asset_id, coalesce(primary_hostname,''), coalesce(os_family,''),
		          coalesce(os_version,''), coalesce(device_type,''), coalesce(vendor,''),
		          criticality, coalesce(environment,''), coalesce(owner,''), fragile,
		          first_seen, last_seen`

	var out Asset
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), a.Hostname, a.OSFamily, a.OSVersion,
		a.DeviceType, a.Vendor, string(a.Criticality), a.Environment, a.Owner, a.Fragile).
		Scan(&out.ID, &out.Hostname, &out.OSFamily, &out.OSVersion, &out.DeviceType,
			&out.Vendor, &out.Criticality, &out.Environment, &out.Owner, &out.Fragile,
			&out.FirstSeen, &out.LastSeen)
	if err != nil {
		return nil, mapError(err)
	}
	return &out, nil
}

func (Assets) GetByID(ctx context.Context, c *Conn, id uuid.UUID) (*Asset, error) {
	const q = `
		SELECT asset_id, coalesce(primary_hostname,''), coalesce(os_family,''),
		       coalesce(os_version,''), coalesce(device_type,''), coalesce(vendor,''),
		       criticality, coalesce(environment,''), coalesce(owner,''), fragile,
		       first_seen, last_seen
		  FROM assets
		 WHERE tenant_id = $1 AND asset_id = $2`

	var a Asset
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).
		Scan(&a.ID, &a.Hostname, &a.OSFamily, &a.OSVersion, &a.DeviceType, &a.Vendor,
			&a.Criticality, &a.Environment, &a.Owner, &a.Fragile, &a.FirstSeen, &a.LastSeen)
	if err != nil {
		return nil, mapError(err)
	}
	return &a, nil
}

// AssetPage is a keyset page. Offset paging was avoided deliberately: the asset
// list has a p95 budget of 300ms at 10k assets, and OFFSET degrades linearly
// with depth on exactly the query that budget applies to.
type AssetPage struct {
	Assets []Asset
	// NextBefore is the cursor for the following page: pass it as `before`.
	// Zero when the page is the last one.
	NextBefore time.Time
	NextID     uuid.UUID
}

// List returns assets newest-seen first, backed by the (tenant_id, last_seen DESC)
// index. Pass a zero `before` for the first page.
func (Assets) List(ctx context.Context, c *Conn, before time.Time, beforeID uuid.UUID, limit int) (*AssetPage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	const q = `
		SELECT asset_id, coalesce(primary_hostname,''), coalesce(os_family,''),
		       coalesce(os_version,''), coalesce(device_type,''), coalesce(vendor,''),
		       criticality, coalesce(environment,''), coalesce(owner,''), fragile,
		       first_seen, last_seen
		  FROM assets
		 WHERE tenant_id = $1
		   AND ($2::timestamptz IS NULL OR (last_seen, asset_id) < ($2, $3))
		 ORDER BY last_seen DESC, asset_id DESC
		 LIMIT $4`

	var beforeArg any
	var beforeIDArg any = beforeID
	if !before.IsZero() {
		beforeArg = before
	}

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), beforeArg, beforeIDArg, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	page := &AssetPage{}
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.Hostname, &a.OSFamily, &a.OSVersion, &a.DeviceType,
			&a.Vendor, &a.Criticality, &a.Environment, &a.Owner, &a.Fragile,
			&a.FirstSeen, &a.LastSeen); err != nil {
			return nil, mapError(err)
		}
		page.Assets = append(page.Assets, a)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	if len(page.Assets) == limit {
		last := page.Assets[len(page.Assets)-1]
		page.NextBefore, page.NextID = last.LastSeen, last.ID
	}
	return page, nil
}

// TouchLastSeen advances last_seen. Called by derivation when an observation
// confirms an asset is still there.
func (Assets) TouchLastSeen(ctx context.Context, c *Conn, id uuid.UUID, seenAt time.Time) error {
	const q = `
		UPDATE assets SET last_seen = greatest(last_seen, $3)
		 WHERE tenant_id = $1 AND asset_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, seenAt)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetFragile marks an asset as rate-capped regardless of policy (ADR-024).
func (Assets) SetFragile(ctx context.Context, c *Conn, id uuid.UUID, fragile bool) error {
	const q = `UPDATE assets SET fragile = $3 WHERE tenant_id = $1 AND asset_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, fragile)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
