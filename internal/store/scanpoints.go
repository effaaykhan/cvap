package store

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// ScanPointStatus mirrors the scan_point_status enum.
//
// The first three are the states from which a scan point may resolve its tenant
// at enrolment; disabled and revoked are not (ADR-031, migration 0015). Adding a
// value here means adding it to the migration's enum AND deciding explicitly
// whether tenant_for_scan_point should accept it — the default is "cannot
// enrol", which is safe but silent.
type ScanPointStatus string

const (
	ScanPointPending  ScanPointStatus = "pending"
	ScanPointOnline   ScanPointStatus = "online"
	ScanPointOffline  ScanPointStatus = "offline"
	ScanPointDisabled ScanPointStatus = "disabled"
	ScanPointRevoked  ScanPointStatus = "revoked"
)

// Engine mirrors the engine_kind enum. The first three exist as engine
// processes; the rest are out of MVP scope (execution-plan §2) and carry no code.
type Engine string

const (
	EngineDiscovery   Engine = "discovery"
	EngineFingerprint Engine = "fingerprint"
	EngineRules       Engine = "rules"

	// The rest of the engine_kind enum. Out of MVP scope (execution-plan §2)
	// and carrying no code, but present in the type because a scan point may
	// declare one and Core must be able to say "recorded, and never dispatched"
	// rather than failing the enrollment.
	EngineHost  Engine = "host"
	EngineDAST  Engine = "dast"
	EngineAPI   Engine = "api"
	EngineSAST  Engine = "sast"
	EngineCloud Engine = "cloud"
)

var validEngines = map[Engine]struct{}{
	EngineDiscovery: {}, EngineFingerprint: {}, EngineRules: {},
	EngineHost: {}, EngineDAST: {}, EngineAPI: {}, EngineSAST: {}, EngineCloud: {},
}

// ValidEngine reports whether a self-asserted engine name is one the
// engine_kind enum knows.
//
// Used at enrollment to SKIP an unknown engine rather than refuse the
// enrollment: a newer scan point declaring an engine this Core has never heard
// of should still enroll, because Core will not dispatch that engine to it
// regardless. Refusing would make every new engine a fleet-wide enrollment
// outage, which is what ADR-022's additive-only posture exists to avoid.
func ValidEngine(s string) bool {
	_, ok := validEngines[Engine(s)]
	return ok
}

type ScanPoint struct {
	ID              uuid.UUID
	ZoneID          uuid.UUID
	Hostname        string
	AgentVersion    string
	ProtocolVersion string
	Status          ScanPointStatus
	CertFingerprint string
	LastHeartbeat   *time.Time
	EnrolledAt      time.Time
}

type Capability struct {
	ID            uuid.UUID
	ScanPointID   uuid.UUID
	Engine        Engine
	EngineVersion string
	Enabled       bool
	DeclaredAt    time.Time
}

type ScanPoints struct{}

func (ScanPoints) Create(ctx context.Context, c *Conn, zoneID uuid.UUID, hostname, agentVersion, protocolVersion, certFingerprint string) (*ScanPoint, error) {
	const q = `
		INSERT INTO scan_points
		    (tenant_id, zone_id, hostname, agent_version, protocol_version, cert_fingerprint)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING scan_point_id, zone_id, hostname, agent_version, protocol_version,
		          status, cert_fingerprint, last_heartbeat, enrolled_at`

	var sp ScanPoint
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), zoneID, hostname, agentVersion, protocolVersion, certFingerprint).
		Scan(&sp.ID, &sp.ZoneID, &sp.Hostname, &sp.AgentVersion, &sp.ProtocolVersion,
			&sp.Status, &sp.CertFingerprint, &sp.LastHeartbeat, &sp.EnrolledAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &sp, nil
}

func (ScanPoints) GetByID(ctx context.Context, c *Conn, id uuid.UUID) (*ScanPoint, error) {
	const q = `
		SELECT scan_point_id, zone_id, hostname, agent_version, protocol_version,
		       status, cert_fingerprint, last_heartbeat, enrolled_at
		  FROM scan_points
		 WHERE tenant_id = $1 AND scan_point_id = $2`

	var sp ScanPoint
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), id).
		Scan(&sp.ID, &sp.ZoneID, &sp.Hostname, &sp.AgentVersion, &sp.ProtocolVersion,
			&sp.Status, &sp.CertFingerprint, &sp.LastHeartbeat, &sp.EnrolledAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &sp, nil
}

// GetByFingerprint reads a scan point by certificate fingerprint, WITHIN the
// connection's tenant.
//
// This is the read enrolment performs after DB.resolveTenant has established
// which tenant to open the connection as. It is not itself the enrolment
// lookup: it is tenant-scoped like everything else, which is exactly why
// resolveTenant has to exist separately (ADR-031).
func (ScanPoints) GetByFingerprint(ctx context.Context, c *Conn, certFingerprint string) (*ScanPoint, error) {
	const q = `
		SELECT scan_point_id, zone_id, hostname, agent_version, protocol_version,
		       status, cert_fingerprint, last_heartbeat, enrolled_at
		  FROM scan_points
		 WHERE tenant_id = $1 AND cert_fingerprint = $2`

	var sp ScanPoint
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), certFingerprint).
		Scan(&sp.ID, &sp.ZoneID, &sp.Hostname, &sp.AgentVersion, &sp.ProtocolVersion,
			&sp.Status, &sp.CertFingerprint, &sp.LastHeartbeat, &sp.EnrolledAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &sp, nil
}

func (ScanPoints) ListByZone(ctx context.Context, c *Conn, zoneID uuid.UUID) ([]ScanPoint, error) {
	const q = `
		SELECT scan_point_id, zone_id, hostname, agent_version, protocol_version,
		       status, cert_fingerprint, last_heartbeat, enrolled_at
		  FROM scan_points
		 WHERE tenant_id = $1 AND zone_id = $2
		 ORDER BY hostname`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), zoneID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []ScanPoint
	for rows.Next() {
		var sp ScanPoint
		if err := rows.Scan(&sp.ID, &sp.ZoneID, &sp.Hostname, &sp.AgentVersion, &sp.ProtocolVersion,
			&sp.Status, &sp.CertFingerprint, &sp.LastHeartbeat, &sp.EnrolledAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, sp)
	}
	return out, mapError(rows.Err())
}

// Heartbeat records liveness. Separate from SetStatus because it runs every 30s
// per scan point and should touch one column.
func (ScanPoints) Heartbeat(ctx context.Context, c *Conn, id uuid.UUID, at time.Time) error {
	const q = `
		UPDATE scan_points
		   SET last_heartbeat = $3, status = 'online'
		 WHERE tenant_id = $1 AND scan_point_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, at)
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (ScanPoints) SetStatus(ctx context.Context, c *Conn, id uuid.UUID, status ScanPointStatus) error {
	const q = `UPDATE scan_points SET status = $3 WHERE tenant_id = $1 AND scan_point_id = $2`

	tag, err := c.Exec(ctx, q, c.Tenant().UUID(), id, string(status))
	if err != nil {
		return mapError(err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeclareCapability records what a scan point can run. Core never dispatches a
// job type a scan point has not declared, so dispatch reads these before it
// assigns.
func (ScanPoints) DeclareCapability(ctx context.Context, c *Conn, scanPointID uuid.UUID, engine Engine, engineVersion string, enabled bool) (*Capability, error) {
	const q = `
		INSERT INTO scan_point_capabilities
		    (tenant_id, scan_point_id, engine, engine_version, enabled)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id, scan_point_id, engine)
		DO UPDATE SET engine_version = EXCLUDED.engine_version,
		              enabled        = EXCLUDED.enabled,
		              declared_at    = now()
		RETURNING capability_id, scan_point_id, engine, engine_version, enabled, declared_at`

	var cap Capability
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), scanPointID, string(engine), engineVersion, enabled).
		Scan(&cap.ID, &cap.ScanPointID, &cap.Engine, &cap.EngineVersion, &cap.Enabled, &cap.DeclaredAt)
	if err != nil {
		return nil, mapError(err)
	}
	return &cap, nil
}

// EnabledEngines returns the enabled engine names for every scan point in the
// tenant, one query for the whole fleet — the health list reads it, and a scan
// point with none can be dispatched nothing (it is reachable but useless).
func (ScanPoints) EnabledEngines(ctx context.Context, c *Conn) (map[uuid.UUID][]string, error) {
	const q = `
		SELECT scan_point_id, engine FROM scan_point_capabilities
		 WHERE tenant_id = $1 AND enabled
		 ORDER BY scan_point_id, engine`
	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	out := map[uuid.UUID][]string{}
	for rows.Next() {
		var id uuid.UUID
		var engine string
		if err := rows.Scan(&id, &engine); err != nil {
			return nil, mapError(err)
		}
		out[id] = append(out[id], engine)
	}
	return out, mapError(rows.Err())
}

// CountDispatchable counts the scan points that could actually run a job for the
// given engine under the given policy: online (a heartbeat within the timeout,
// recomputed here rather than trusting the stored status, which lags a sweep),
// not disabled or revoked, holding an ENABLED capability for the engine, and in a
// zone the policy permits.
//
// The zone clause MIRRORS Jobs.Claim's exactly — empty/absent allowed_zones is
// unrestricted (ADR-037), otherwise the scan point's zone_id must appear in the
// jsonb array, matched as lowercase text (no ::uuid cast, so one malformed entry
// cannot fail the whole query). It must mirror it, because this is the check that
// promises a scan can be dispatched and Claim is what actually dispatches it: if
// the two disagreed, a scan accepted here would still hang unclaimed, which is
// the exact silent non-result this exists to refuse.
//
// Zero means "creating this scan would queue jobs no scan point can claim" — the
// caller refuses the scan rather than letting it sit `running` against nothing.
func (ScanPoints) CountDispatchable(ctx context.Context, c *Conn, engine Engine, policyID uuid.UUID) (int, error) {
	const q = `
		SELECT count(DISTINCT sp.scan_point_id)
		  FROM scan_points sp
		  JOIN scan_point_capabilities cap
		    ON cap.tenant_id = sp.tenant_id AND cap.scan_point_id = sp.scan_point_id
		 WHERE sp.tenant_id = $1
		   AND cap.engine = $2::text::engine_kind
		   AND cap.enabled
		   AND sp.status NOT IN ('disabled', 'revoked')
		   AND sp.last_heartbeat IS NOT NULL
		   AND sp.last_heartbeat > now() - make_interval(secs => $4)
		   AND NOT EXISTS (
		       SELECT 1 FROM scan_policies p
		        WHERE p.tenant_id = sp.tenant_id AND p.policy_id = $3
		          AND jsonb_array_length(p.allowed_zones) > 0
		          AND NOT EXISTS (
		              SELECT 1 FROM jsonb_array_elements_text(p.allowed_zones) z
		               WHERE lower(z) = sp.zone_id::text
		          )
		   )`
	var n int
	err := c.QueryRow(ctx, q, c.Tenant().UUID(), string(engine), policyID, HeartbeatTimeout.Seconds()).Scan(&n)
	if err != nil {
		return 0, mapError(err)
	}
	return n, nil
}

// HeldLeaseCounts returns how many granted leases each scan point holds, for the
// whole fleet, one query. Informational context on the health list — a scan
// point with live leases is actively working — not a health determinant (a
// partitioned one shows offline via its heartbeat, which is the signal).
func (ScanPoints) HeldLeaseCounts(ctx context.Context, c *Conn) (map[uuid.UUID]int, error) {
	const q = `
		SELECT holder_scan_point, count(*) FROM job_leases
		 WHERE tenant_id = $1 AND state = 'granted'
		 GROUP BY holder_scan_point`
	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	out := map[uuid.UUID]int{}
	for rows.Next() {
		var id uuid.UUID
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, mapError(err)
		}
		out[id] = n
	}
	return out, mapError(rows.Err())
}

func (ScanPoints) Capabilities(ctx context.Context, c *Conn, scanPointID uuid.UUID) ([]Capability, error) {
	const q = `
		SELECT capability_id, scan_point_id, engine, engine_version, enabled, declared_at
		  FROM scan_point_capabilities
		 WHERE tenant_id = $1 AND scan_point_id = $2
		 ORDER BY engine`

	rows, err := c.Query(ctx, q, c.Tenant().UUID(), scanPointID)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []Capability
	for rows.Next() {
		var cap Capability
		if err := rows.Scan(&cap.ID, &cap.ScanPointID, &cap.Engine, &cap.EngineVersion,
			&cap.Enabled, &cap.DeclaredAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, cap)
	}
	return out, mapError(rows.Err())
}

// ListAll returns every scan point in the tenant, WORST-first by liveness: the
// ones an operator worries about — never heard from (NULL heartbeat), then
// longest-silent — surface at the top, healthiest last. This is a fleet HEALTH
// list, so it sorts the way the finding views do (worst first), not
// newest-first, which would bury exactly the points that need attention. The
// per-zone ListByZone remains for the zone view; this is what the UI reads
// without iterating zones. cert_fingerprint is selected for the struct but the
// API never renders it (handlers_ops).
func (ScanPoints) ListAll(ctx context.Context, c *Conn) ([]ScanPoint, error) {
	const q = `
		SELECT scan_point_id, zone_id, hostname, agent_version, protocol_version,
		       status, cert_fingerprint, last_heartbeat, enrolled_at
		  FROM scan_points
		 WHERE tenant_id = $1
		 ORDER BY last_heartbeat ASC NULLS FIRST, hostname`

	rows, err := c.Query(ctx, q, c.Tenant().UUID())
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()

	var out []ScanPoint
	for rows.Next() {
		var sp ScanPoint
		if err := rows.Scan(&sp.ID, &sp.ZoneID, &sp.Hostname, &sp.AgentVersion, &sp.ProtocolVersion,
			&sp.Status, &sp.CertFingerprint, &sp.LastHeartbeat, &sp.EnrolledAt); err != nil {
			return nil, mapError(err)
		}
		out = append(out, sp)
	}
	return out, mapError(rows.Err())
}
