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

// AssetFilter narrows the asset list. Empty fields do not filter.
type AssetFilter struct {
	// Query matches a substring of the primary hostname OR of any current
	// address (asset_addresses with valid_to IS NULL). Empty matches all.
	Query string
	// Environment is an exact match on the environment tag. Empty matches all.
	Environment string
	// Fragile filters on the fragile flag when non-nil.
	Fragile *bool
}

// List returns assets newest-seen first, backed by the (tenant_id, last_seen DESC)
// index, narrowed by f. Pass a zero `before` for the first page.
func (Assets) List(ctx context.Context, c *Conn, f AssetFilter, before time.Time, beforeID uuid.UUID, limit int) (*AssetPage, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}

	// Search over hostname OR a current address, as an operator would type it.
	// The pattern is a bound parameter, never interpolated, so a value with %
	// or _ in it searches literally-enough and cannot alter the statement. The
	// address arm is an EXISTS over the current-addresses partial index rather
	// than a join, so a host with several addresses is not returned several
	// times.
	var qArg, envArg, fragileArg any
	if f.Query != "" {
		qArg = "%" + f.Query + "%"
	}
	if f.Environment != "" {
		envArg = f.Environment
	}
	if f.Fragile != nil {
		fragileArg = *f.Fragile
	}

	const q = `
		SELECT asset_id, coalesce(primary_hostname,''), coalesce(os_family,''),
		       coalesce(os_version,''), coalesce(device_type,''), coalesce(vendor,''),
		       criticality, coalesce(environment,''), coalesce(owner,''), fragile,
		       first_seen, last_seen
		  FROM assets
		 WHERE tenant_id = $1
		   AND ($2::timestamptz IS NULL OR (last_seen, asset_id) < ($2, $3))
		   AND ($5::text IS NULL OR primary_hostname ILIKE $5 OR EXISTS (
		         SELECT 1 FROM asset_addresses aa
		          WHERE aa.tenant_id = assets.tenant_id AND aa.asset_id = assets.asset_id
		            AND aa.valid_to IS NULL AND host(aa.ip_address) ILIKE $5))
		   AND ($6::text IS NULL OR environment = $6)
		   AND ($7::boolean IS NULL OR fragile = $7)
		 ORDER BY last_seen DESC, asset_id DESC
		 LIMIT $4`

	var beforeArg any
	var beforeIDArg any = beforeID
	if !before.IsZero() {
		beforeArg = before
	}

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), beforeArg, beforeIDArg, limit, qArg, envArg, fragileArg)
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
// EnvironmentOf returns the asset's environment, or "" if unset.
//
// A thin read because the finding pipeline needs one field and building a whole
// Asset to get it would be wasteful on the hot path — every resolved host asks.
// Empty is NOT dev: the self-signed rule treats an un-tagged asset as
// production, because the safe default has to be the one that raises.
func (Assets) EnvironmentOf(ctx context.Context, c *Conn, id uuid.UUID) (string, error) {
	const q = `SELECT coalesce(environment,'') FROM assets WHERE tenant_id = $1 AND asset_id = $2`
	var env string
	if err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).Scan(&env); err != nil {
		return "", mapError(err)
	}
	return env, nil
}

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

// ============================================================================
// Asset detail (session 18): the base row plus its current addresses and
// services, for the operator UI's asset view.
// ============================================================================

// AssetAddress is one current address of an asset (valid_to IS NULL). Held as
// text — host(ip) and mac::text — because the API renders it and never does
// arithmetic on it.
type AssetAddress struct {
	IP        string
	MAC       string
	ValidFrom time.Time
}

// AssetService is one listening endpoint on an asset.
type AssetService struct {
	Port       int
	Protocol   string
	Service    string
	Product    string
	Version    string
	Confidence *float64 // nil when the version was not inferred with a confidence
	LastSeen   time.Time
}

// AssetDetail is one asset with everything the UI shows on its page.
type AssetDetail struct {
	Asset
	Addresses    []AssetAddress
	Services     []AssetService
	OpenFindings int
}

// GetDetail returns the full asset view, or ErrNotFound (also what a
// cross-tenant id gives — indistinguishable under RLS, deliberately).
func (Assets) GetDetail(ctx context.Context, c *Conn, id uuid.UUID) (*AssetDetail, error) {
	base, err := (Assets{}).GetByID(ctx, c, id)
	if err != nil {
		return nil, err
	}
	d := &AssetDetail{Asset: *base}

	const addrQ = `
		SELECT coalesce(host(ip_address), ''), coalesce(mac_address::text, ''), valid_from
		  FROM asset_addresses
		 WHERE tenant_id = $1 AND asset_id = $2 AND valid_to IS NULL
		 ORDER BY valid_from`
	rows, err := c.Query(ctx, addrQ, c.Tenant().UUID(), id)
	if err != nil {
		return nil, mapError(err)
	}
	for rows.Next() {
		var a AssetAddress
		if err := rows.Scan(&a.IP, &a.MAC, &a.ValidFrom); err != nil {
			rows.Close()
			return nil, mapError(err)
		}
		d.Addresses = append(d.Addresses, a)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, mapError(err)
	}
	rows.Close()

	const svcQ = `
		SELECT port, protocol, coalesce(service_name,''), coalesce(product,''),
		       coalesce(version,''), version_confidence, last_seen
		  FROM services
		 WHERE tenant_id = $1 AND asset_id = $2
		 ORDER BY port, protocol`
	srows, err := c.Query(ctx, svcQ, c.Tenant().UUID(), id)
	if err != nil {
		return nil, mapError(err)
	}
	for srows.Next() {
		var s AssetService
		if err := srows.Scan(&s.Port, &s.Protocol, &s.Service, &s.Product,
			&s.Version, &s.Confidence, &s.LastSeen); err != nil {
			srows.Close()
			return nil, mapError(err)
		}
		d.Services = append(d.Services, s)
	}
	if err := srows.Err(); err != nil {
		srows.Close()
		return nil, mapError(err)
	}
	srows.Close()

	const cntQ = `
		SELECT count(*) FROM findings
		 WHERE tenant_id = $1 AND asset_id = $2 AND status IN ('open','confirmed')`
	if err := c.QueryRow(ctx, cntQ, c.Tenant().UUID(), id).Scan(&d.OpenFindings); err != nil {
		return nil, mapError(err)
	}
	return d, nil
}

// AssetExportRowCap bounds a CSV export of assets, the asset analogue of
// findings' cap: an export over it is refused, never truncated, so an incomplete
// file cannot pass for complete.
const AssetExportRowCap = 50000

// ListForExport returns up to `max` assets matching the filter, newest-seen
// first, with no cursor — the whole set for a CSV. Callers pass the cap+1 and
// refuse when the result exceeds the cap. Ordered (last_seen, asset_id) so the
// bounded set is deterministic, not an arbitrary LIMIT slice.
func (Assets) ListForExport(ctx context.Context, c *Conn, f AssetFilter, max int) ([]Asset, error) {
	if max <= 0 || max > AssetExportRowCap+1 {
		max = AssetExportRowCap + 1
	}
	var qArg, envArg, fragileArg any
	if f.Query != "" {
		qArg = "%" + f.Query + "%"
	}
	if f.Environment != "" {
		envArg = f.Environment
	}
	if f.Fragile != nil {
		fragileArg = *f.Fragile
	}

	const q = `
		SELECT asset_id, coalesce(primary_hostname,''), coalesce(os_family,''),
		       coalesce(os_version,''), coalesce(device_type,''), coalesce(vendor,''),
		       criticality, coalesce(environment,''), coalesce(owner,''), fragile,
		       first_seen, last_seen
		  FROM assets
		 WHERE tenant_id = $1
		   AND ($2::text IS NULL OR primary_hostname ILIKE $2 OR EXISTS (
		         SELECT 1 FROM asset_addresses aa
		          WHERE aa.tenant_id = assets.tenant_id AND aa.asset_id = assets.asset_id
		            AND aa.valid_to IS NULL AND host(aa.ip_address) ILIKE $2))
		   AND ($3::text IS NULL OR environment = $3)
		   AND ($4::boolean IS NULL OR fragile = $4)
		 ORDER BY last_seen DESC, asset_id DESC
		 LIMIT $5`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), qArg, envArg, fragileArg, max)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Asset
	for rows.Next() {
		var a Asset
		if err := rows.Scan(&a.ID, &a.Hostname, &a.OSFamily, &a.OSVersion, &a.DeviceType,
			&a.Vendor, &a.Criticality, &a.Environment, &a.Owner, &a.Fragile,
			&a.FirstSeen, &a.LastSeen); err != nil {
			return nil, mapError(err)
		}
		out = append(out, a)
	}
	return out, mapError(rows.Err())
}
