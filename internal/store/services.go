package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Service is one listening endpoint, derived by Core from observations.
//
// Never written by a scan point (ADR-006). The identification evidence — how it
// was learned, whether we provoked it, the certificate, the host key — arrived
// with migration 0030.
type Service struct {
	AssetID  uuid.UUID
	Port     int
	Protocol string

	Name    string
	Product string
	Version string

	VersionConfidence        *float64
	IdentificationMethod     string
	IdentificationConfidence *float64
	Softmatch                bool
	Solicited                bool
	SafetyMode               string
	IdentificationProbe      string

	// TLS and SSH are the raw evidence objects, stored as jsonb on this row
	// rather than normalised. ADR-048 §5: a certificate is a property of a
	// service on a port, and splitting it makes every week 6 certificate rule a
	// join across the largest tables in the system.
	TLS []byte
	SSH []byte
}

type Services struct{}

// Upsert writes one endpoint, keyed on asset+port+protocol.
//
// One row per listening endpoint, because the network dedup key (ADR-010) is
// asset+port+protocol+rule and two service rows for one endpoint would split
// findings that should be one.
//
// `last_seen` moves on every observation; `first_seen` does not. A service that
// disappears is not deleted here — an endpoint that stopped answering is a fact
// with a date, and deleting the row would take the finding history with it.
func (Services) Upsert(ctx context.Context, c *Conn, s Service, seenAt time.Time) error {
	const q = `
		INSERT INTO services (
		    tenant_id, asset_id, port, protocol, service_name, product, version,
		    version_confidence, identification_method, identification_confidence,
		    softmatch, solicited, safety_mode, identification_probe, tls, ssh,
		    first_seen, last_seen)
		VALUES ($1, $2, $3, $4, nullif($5,''), nullif($6,''), nullif($7,''),
		        $8, nullif($9,''), $10, $11, $12, nullif($13,''), nullif($14,''),
		        $15, $16, $17, $17)
		ON CONFLICT (tenant_id, asset_id, port, protocol) DO UPDATE SET
		    -- Content moves only with a sighting at least as new as the row's:
		    -- a parked observation released after a later scan wrote current
		    -- evidence (ADR-096) must not put older banners under a newer
		    -- last_seen. That comparison is applied to every column below.
		    service_name              = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(nullif(excluded.service_name,''), services.service_name) ELSE services.service_name END,
		    product                   = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(nullif(excluded.product,''), services.product) ELSE services.product END,
		    version                   = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(nullif(excluded.version,''), services.version) ELSE services.version END,
		    version_confidence        = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(excluded.version_confidence, services.version_confidence) ELSE services.version_confidence END,
		    identification_method     = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(excluded.identification_method, services.identification_method) ELSE services.identification_method END,
		    identification_confidence = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(excluded.identification_confidence, services.identification_confidence) ELSE services.identification_confidence END,
		    softmatch                 = CASE WHEN excluded.last_seen >= services.last_seen THEN excluded.softmatch ELSE services.softmatch END,
		    solicited                 = CASE WHEN excluded.last_seen >= services.last_seen THEN excluded.solicited ELSE services.solicited END,
		    safety_mode               = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(excluded.safety_mode, services.safety_mode) ELSE services.safety_mode END,
		    identification_probe      = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(excluded.identification_probe, services.identification_probe) ELSE services.identification_probe END,
		    -- Evidence is REPLACED rather than merged when present, and kept when
		    -- absent. A certificate that has rotated is not a second certificate,
		    -- and a safe-mode rescan that learned nothing must not erase what an
		    -- intrusive scan found.
		    tls                       = CASE WHEN excluded.last_seen >= services.last_seen THEN coalesce(excluded.tls, services.tls) ELSE services.tls END,
		    ssh                       = CASE WHEN excluded.last_seen >= services.last_seen THEN coalesce(excluded.ssh, services.ssh) ELSE services.ssh END,
		    -- Monotonic: a parked observation released after a later scan
		    -- already wrote current evidence must not drag the row backwards
		    -- (ADR-096's continuity fact reads last_seen).
		    last_seen                 = greatest(services.last_seen, excluded.last_seen)`

	_, err := c.Exec(ctx, q, c.Tenant().UUID(), s.AssetID, s.Port, s.Protocol,
		s.Name, s.Product, s.Version, s.VersionConfidence,
		s.IdentificationMethod, s.IdentificationConfidence,
		s.Softmatch, s.Solicited, s.SafetyMode, s.IdentificationProbe,
		nullBytes(s.TLS), nullBytes(s.SSH), seenAt)
	return mapError(err)
}

// nullBytes turns an absent payload into SQL NULL rather than an empty jsonb.
//
// The difference is load-bearing in the upsert above: `coalesce(excluded.tls,
// services.tls)` keeps what a previous scan found when this one learned nothing,
// and an empty-but-not-null value would defeat that and erase the certificate on
// every safe-mode rescan.
func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

// HeldService is what continuity compares (ADR-096): the product the asset was
// last seen answering with on a port, and when. Nothing else on the row takes
// part in the classification — a version moves on every upgrade and would
// make every patched host "a different host".
type HeldService struct {
	Port     int
	Protocol string
	Product  string
	LastSeen time.Time
}

// ProductsSince lists the asset's service rows that carry a product and were
// seen at or after `since` — "every previously seen product" for ADR-096's
// continuity test, bounded by the same window that gives the address its
// meaning. A row with no product is not listed: an unidentified port has
// nothing to be continuous with.
func (Services) ProductsSince(ctx context.Context, c *Conn, assetID uuid.UUID, since time.Time) ([]HeldService, error) {
	const q = `
		SELECT port, protocol, product, last_seen
		  FROM services
		 WHERE tenant_id = $1 AND asset_id = $2
		   AND product IS NOT NULL AND product <> ''
		   AND last_seen >= $3
		 ORDER BY port, protocol`
	rows, err := c.Query(ctx, q, c.Tenant().UUID(), assetID, since)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []HeldService
	for rows.Next() {
		var s HeldService
		if err := rows.Scan(&s.Port, &s.Protocol, &s.Product, &s.LastSeen); err != nil {
			return nil, mapError(err)
		}
		out = append(out, s)
	}
	return out, mapError(rows.Err())
}
