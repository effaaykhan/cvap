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
		    service_name              = coalesce(nullif(excluded.service_name,''), services.service_name),
		    product                   = coalesce(nullif(excluded.product,''), services.product),
		    version                   = coalesce(nullif(excluded.version,''), services.version),
		    version_confidence        = coalesce(excluded.version_confidence, services.version_confidence),
		    identification_method     = coalesce(excluded.identification_method, services.identification_method),
		    identification_confidence = coalesce(excluded.identification_confidence, services.identification_confidence),
		    softmatch                 = excluded.softmatch,
		    solicited                 = excluded.solicited,
		    safety_mode               = coalesce(excluded.safety_mode, services.safety_mode),
		    identification_probe      = coalesce(excluded.identification_probe, services.identification_probe),
		    -- Evidence is REPLACED rather than merged when present, and kept when
		    -- absent. A certificate that has rotated is not a second certificate,
		    -- and a safe-mode rescan that learned nothing must not erase what an
		    -- intrusive scan found.
		    tls                       = coalesce(excluded.tls, services.tls),
		    ssh                       = coalesce(excluded.ssh, services.ssh),
		    last_seen                 = excluded.last_seen`

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
