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
