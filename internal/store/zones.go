package store

import (
	"context"
	"net/netip"
	"time"

	"github.com/google/uuid"
)

// ZoneType is SCAN_ZONE.zone_type. A zone is a vantage point, and a vantage
// point is a property of an observation, never of an asset (ADR-008).
type ZoneType string

const (
	ZoneExternal ZoneType = "external"
	ZoneDMZ      ZoneType = "dmz"
	ZoneInternal ZoneType = "internal"
	ZoneBranch   ZoneType = "branch"
	ZoneCloud    ZoneType = "cloud"
	ZoneMgmt     ZoneType = "mgmt"
)

type Zone struct {
	ID          uuid.UUID
	Name        string
	Type        ZoneType
	TrustLevel  int
	Description string
	CreatedAt   time.Time
}

type NetworkRange struct {
	ID         uuid.UUID
	ZoneID     uuid.UUID
	CIDR       netip.Prefix
	Authorized bool
	CreatedAt  time.Time
}

type Zones struct{}
type NetworkRanges struct{}

func (Zones) Create(ctx context.Context, c *Conn, name string, zt ZoneType, trustLevel int, description string) (*Zone, error) {
	const q = `
		INSERT INTO scan_zones (tenant_id, name, zone_type, trust_level, description)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING zone_id, name, zone_type, trust_level, coalesce(description, ''), created_at`

	var z Zone
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), name, string(zt), trustLevel, description).
		Scan(&z.ID, &z.Name, &z.Type, &z.TrustLevel, &z.Description, &z.CreatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &z, nil
}

func (Zones) GetByID(ctx context.Context, c *Conn, id uuid.UUID) (*Zone, error) {
	const q = `
		SELECT zone_id, name, zone_type, trust_level, coalesce(description, ''), created_at
		  FROM scan_zones
		 WHERE tenant_id = $1 AND zone_id = $2`

	var z Zone
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).
		Scan(&z.ID, &z.Name, &z.Type, &z.TrustLevel, &z.Description, &z.CreatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &z, nil
}

func (Zones) List(ctx context.Context, c *Conn) ([]Zone, error) {
	const q = `
		SELECT zone_id, name, zone_type, trust_level, coalesce(description, ''), created_at
		  FROM scan_zones
		 WHERE tenant_id = $1
		 ORDER BY name`

	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Zone
	for rows.Next() {
		var z Zone
		if err := rows.Scan(&z.ID, &z.Name, &z.Type, &z.TrustLevel, &z.Description, &z.CreatedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, z)
	}
	return out, mapError(rows.Err())
}

// AddRange records a network range in a zone.
//
// authorized defaults to false in the schema and is passed explicitly here for
// the same reason: an unauthorised range is a legal problem rather than a bug
// (execution-plan §8, risk 6), so it should never be set by omission. Planning
// enforces the flag; this only stores it.
func (NetworkRanges) Add(ctx context.Context, c *Conn, zoneID uuid.UUID, prefix netip.Prefix, authorized bool) (*NetworkRange, error) {
	const q = `
		INSERT INTO network_ranges (tenant_id, zone_id, cidr, is_authorized)
		VALUES ($1, $2, $3, $4)
		RETURNING range_id, zone_id, cidr, is_authorized, created_at`

	var r NetworkRange
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), zoneID, prefix.String(), authorized).
		Scan(&r.ID, &r.ZoneID, &r.CIDR, &r.Authorized, &r.CreatedAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &r, nil
}

func (NetworkRanges) ListByZone(ctx context.Context, c *Conn, zoneID uuid.UUID) ([]NetworkRange, error) {
	const q = `
		SELECT range_id, zone_id, cidr, is_authorized, created_at
		  FROM network_ranges
		 WHERE tenant_id = $1 AND zone_id = $2
		 ORDER BY cidr`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), zoneID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []NetworkRange
	for rows.Next() {
		var r NetworkRange
		if err := rows.Scan(&r.ID, &r.ZoneID, &r.CIDR, &r.Authorized, &r.CreatedAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, r)
	}
	return out, mapError(rows.Err())
}
