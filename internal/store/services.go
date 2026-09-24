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

	// SeenOnly marks a port that ANSWERED but was never identified — the
	// discovery engine's `port` observation, promoted because an open port is
	// the asset's attack surface and observations are ephemeral (ADR-103,
	// ADR-016).
	//
	// It changes the merge, not just the row. An identified service carries
	// claims about softmatch and solicited; a bare port makes neither claim, so
	// a seen-only write must not assign them. Without that, a discovery pass
	// running AFTER a fingerprint pass resets both — the one clobber path the
	// coalesce in Upsert does not already close, named in ADR-103 so it got a
	// test rather than a later surprise.
	SeenOnly bool
}

// IdentificationDiscovery is the identification_method of a port that answered
// and was never identified (ADR-103).
//
// It is deliberately a value of the EXISTING column rather than a new one, so a
// later fingerprint pass upgrades this row in place instead of creating a second
// one for the same endpoint.
//
// It DID need a migration, and this comment used to say otherwise: `services`
// carries a CHECK whitelisting identification_method, which ADR-103 missed by
// reading only column nullability. Migration 0048 admits the value (ADR-104).
const IdentificationDiscovery = "discovery"

// Identified reports whether anything is actually known about this endpoint
// beyond the fact that it answered.
//
// It reads identification_method and NOT SeenOnly, which is deliberate and was
// wrong in the first cut: SeenOnly describes one WRITE, has no column, and is
// therefore always false on anything read back from the database. A predicate
// that consulted it would have answered "not identified" for every row in the
// table. The durable marker is the method (ADR-104's migration exists to make
// 'discovery' storable), so that is what a reader must ask.
func (s Service) Identified() bool {
	return s.IdentificationMethod != IdentificationDiscovery
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
		    -- $18 guards this for the same reason it guards softmatch and
		    -- solicited below, and missing it here was the more damaging of the
		    -- two: 'discovery' is NON-NULL, so it beat the coalesce and
		    -- RELABELLED an identified service as "nothing probed it" while the
		    -- row kept its product, its confidence and the probe that produced
		    -- them. Not a corner case — discovery scans run more often than
		    -- fingerprint scans, so their observed_at is usually the newer one
		    -- and this was the steady state. Found by a schema audit; ADR-103's
		    -- claim that softmatch/solicited were "the one clobber path" was
		    -- wrong by exactly this column.
		    identification_method     = CASE WHEN excluded.last_seen >= services.last_seen AND NOT $18
		                                     THEN coalesce(excluded.identification_method, services.identification_method) ELSE services.identification_method END,
		    identification_confidence = CASE WHEN excluded.last_seen >= services.last_seen
		                                     THEN coalesce(excluded.identification_confidence, services.identification_confidence) ELSE services.identification_confidence END,
		    -- $18 is "this write identified nothing". These two columns are
		    -- assignments rather than coalesces -- false is a real value, so
		    -- there is no empty to merge away -- which means a seen-only write
		    -- would otherwise RESET what a fingerprint pass established, purely
		    -- by being newer. A bare port makes no claim about either, so it
		    -- leaves both alone (ADR-103).
		    softmatch                 = CASE WHEN excluded.last_seen >= services.last_seen AND NOT $18
		                                     THEN excluded.softmatch ELSE services.softmatch END,
		    solicited                 = CASE WHEN excluded.last_seen >= services.last_seen AND NOT $18
		                                     THEN excluded.solicited ELSE services.solicited END,
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
		nullBytes(s.TLS), nullBytes(s.SSH), seenAt, s.SeenOnly)
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

// OpenPort is one listening endpoint with the address an operator reaches it
// at, for the overview's port table (ADR-103).
type OpenPort struct {
	AssetID  uuid.UUID
	Address  string
	Hostname string
	Port     int
	Protocol string
	Service  string
	Product  string

	// Identified is false for a port discovery merely SAW. The console must
	// render those differently: a row here is not a claim that anything was
	// recognised on the port (ADR-103 decision 1).
	Identified bool
	LastSeen   time.Time
}

// OpenPorts lists endpoints across the tenant, newest sighting first.
//
// Bounded by limit and ordered deterministically, because this feeds a screen
// rather than an export: an unbounded read of every service on a large estate
// is the shape ADR-052 refuses for the CSV paths, and the operator budget
// (ADR-101) is 30 seconds.
//
// The address is the asset's CURRENT one — `valid_to IS NULL` — which is the
// same subquery the asset list uses. A service row carries no address of its
// own: a dual-homed host's port 22 is one row whichever interface answered, so
// what is shown is the asset's address, not the vantage the port was seen from.
func (Services) OpenPorts(ctx context.Context, c *Conn, limit int) ([]OpenPort, error) {
	const q = `
		SELECT s.asset_id,
		       coalesce((SELECT host(ad.ip_address) FROM asset_addresses ad
		                  WHERE ad.tenant_id = s.tenant_id AND ad.asset_id = s.asset_id
		                    AND ad.valid_to IS NULL
		                  ORDER BY ad.valid_from LIMIT 1), ''),
		       coalesce(a.primary_hostname, ''),
		       s.port, s.protocol,
		       coalesce(s.service_name, ''), coalesce(s.product, ''),
		       coalesce(s.identification_method, '') <> $2 AS identified,
		       s.last_seen
		  FROM services s
		  JOIN assets a ON a.tenant_id = s.tenant_id AND a.asset_id = s.asset_id
		 WHERE s.tenant_id = $1
		 ORDER BY s.last_seen DESC, s.asset_id, s.port
		 LIMIT $3`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), IdentificationDiscovery, limit)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []OpenPort
	for rows.Next() {
		var p OpenPort
		if err := rows.Scan(&p.AssetID, &p.Address, &p.Hostname, &p.Port, &p.Protocol,
			&p.Service, &p.Product, &p.Identified, &p.LastSeen); err != nil {
			return nil, mapError(err)
		}
		out = append(out, p)
	}
	return out, mapError(rows.Err())
}
