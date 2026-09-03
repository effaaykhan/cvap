package api

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/store"
)

// Kill switch, zones, scan points, enrollment tokens, policies.

// IssueKillRequest is the body of POST /v1/kill.
type IssueKillRequest struct {
	Scope  string  `json:"scope" doc:"tenant | zone | scan. A tenant-scoped kill halts everything this tenant is running."`
	ZoneID *string `json:"zone_id,omitempty" doc:"Required when scope is zone."`
	ScanID *string `json:"scan_id,omitempty" doc:"Required when scope is scan."`
	Reason string  `json:"reason" doc:"Required. A fleet stop with no stated reason is unreviewable afterwards."`
}

type KillResponse struct {
	ID         string     `json:"id"`
	Scope      string     `json:"scope"`
	ZoneID     *string    `json:"zone_id,omitempty"`
	ScanID     *string    `json:"scan_id,omitempty"`
	Reason     string     `json:"reason"`
	IssuedAt   time.Time  `json:"issued_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

func killResponse(k *store.KillSwitch) KillResponse {
	out := KillResponse{
		ID: k.ID.String(), Scope: string(k.Scope), Reason: k.Reason,
		IssuedAt: k.IssuedAt, ResolvedAt: k.ResolvedAt,
	}
	if k.ZoneID != nil {
		v := k.ZoneID.String()
		out.ZoneID = &v
	}
	if k.ScanID != nil {
		v := k.ScanID.String()
		out.ScanID = &v
	}
	return out
}

// issueKill is the third dead path this session activates.
//
// ADR-024 control 4 requires a fleet-wide stop reachable in seconds. Everything
// beneath it existed — kill_switches, kill_acks, LiveFor, the propagation in
// dispatch, the 10-second bound at the receiver — with nothing able to issue
// one. A control that cannot be triggered is not a control.
func (s *Server) issueKill(w http.ResponseWriter, r *http.Request) {
	var req IssueKillRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	if req.Reason == "" {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "reason is required.", nil)
		return
	}

	scope := store.KillScope(req.Scope)
	var zoneID, scanID *uuid.UUID
	switch scope {
	case store.KillTenant:
		if req.ZoneID != nil || req.ScanID != nil {
			// Refused rather than ignored. A caller who sent a scan id with a
			// tenant scope believes they issued a narrow kill; accepting it
			// would halt the whole fleet while telling them otherwise.
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"A tenant-scoped kill takes no zone_id or scan_id.", nil)
			return
		}
	case store.KillZone:
		id, err := parseUUIDPtr(req.ZoneID)
		if err != nil || id == nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"A zone-scoped kill requires zone_id.", err)
			return
		}
		zoneID = id
	case store.KillScan:
		id, err := parseUUIDPtr(req.ScanID)
		if err != nil || id == nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"A scan-scoped kill requires scan_id.", err)
			return
		}
		scanID = id
	default:
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"scope must be tenant, zone or scan.", nil)
		return
	}

	tenant, _ := tenantFrom(r.Context())
	var k *store.KillSwitch
	err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		k, err = (store.KillSwitches{}).Issue(ctx, c, scope, zoneID, scanID, actor(r), req.Reason)
		if err != nil {
			return err
		}
		id := k.ID
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: actor(r), ActorType: store.ActorUser,
			Action: "kill.issued", ResourceType: "kill_switch", ResourceID: &id,
			Detail: map[string]any{"scope": string(scope), "reason": req.Reason},
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	s.log.Warn("kill switch issued",
		"request_id", requestIDFrom(r.Context()), "kill_id", k.ID.String(),
		"scope", string(scope), "tenant_id", tenant.String())
	writeJSON(w, r, s.log, http.StatusCreated, killResponse(k))
}

// resolveKill clears a kill switch.
//
// Separate permission from issuing it. Stopping the fleet is an emergency action
// that should be easy to reach; letting it start again is a decision that the
// emergency is over, which is not the same judgement and often not the same
// person.
func (s *Server) resolveKill(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "kill_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "kill_id is not a uuid.", err)
		return
	}
	tenant, _ := tenantFrom(r.Context())

	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.KillSwitches{}).Resolve(ctx, c, id); err != nil {
			return err
		}
		k := id
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: actor(r), ActorType: store.ActorUser,
			Action: "kill.resolved", ResourceType: "kill_switch", ResourceID: &k,
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	s.log.Warn("kill switch resolved",
		"request_id", requestIDFrom(r.Context()), "kill_id", id.String(),
		"tenant_id", tenant.String())
	writeJSON(w, r, s.log, http.StatusNoContent, nil)
}

// ZoneRequest creates a zone.
type ZoneRequest struct {
	Name        string `json:"name"`
	Type        string `json:"type" doc:"external | dmz | internal | branch | cloud | mgmt."`
	TrustLevel  int    `json:"trust_level"`
	Description string `json:"description,omitempty"`
}

type ZoneResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	TrustLevel  int    `json:"trust_level"`
	Description string `json:"description,omitempty"`
}

type ZoneListResponse struct {
	Zones []ZoneResponse `json:"zones"`
}

var validZoneTypes = map[string]bool{
	"external": true, "dmz": true, "internal": true,
	"branch": true, "cloud": true, "mgmt": true,
}

func (s *Server) createZone(w http.ResponseWriter, r *http.Request) {
	var req ZoneRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	if req.Name == "" || !validZoneTypes[req.Type] {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"A zone needs a name and a type of external, dmz, internal, branch, cloud or mgmt.", nil)
		return
	}

	tenant, _ := tenantFrom(r.Context())
	var z *store.Zone
	err := s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		z, err = (store.Zones{}).Create(ctx, c, req.Name, store.ZoneType(req.Type), req.TrustLevel, req.Description)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusCreated, ZoneResponse{
		ID: z.ID.String(), Name: z.Name, Type: string(z.Type),
		TrustLevel: z.TrustLevel, Description: z.Description,
	})
}

func (s *Server) listZones(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())
	var zones []store.Zone
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		zones, err = (store.Zones{}).List(ctx, c)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := ZoneListResponse{Zones: make([]ZoneResponse, 0, len(zones))}
	for _, z := range zones {
		out.Zones = append(out.Zones, ZoneResponse{
			ID: z.ID.String(), Name: z.Name, Type: string(z.Type),
			TrustLevel: z.TrustLevel, Description: z.Description,
		})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// NetworkRangeRequest adds a range to a zone.
type NetworkRangeRequest struct {
	Prefix string `json:"prefix" doc:"CIDR. Parsed and re-rendered in masked form before storage."`

	// Same attestation as a scan target, for the same reason: a range recorded
	// against a zone is a statement about a network somebody is claiming to be
	// entitled to scan.
	AuthorizationVerified bool `json:"authorization_verified"`
}

type NetworkRangeResponse struct {
	ID         string `json:"id"`
	Prefix     string `json:"prefix"`
	Authorized bool   `json:"authorization_verified"`
}

func (s *Server) addNetworkRange(w http.ResponseWriter, r *http.Request) {
	zoneID, err := pathUUID(r, "zone_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "zone_id is not a uuid.", err)
		return
	}
	var req NetworkRangeRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	prefix, err := netip.ParsePrefix(req.Prefix)
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"prefix must be a CIDR.", err)
		return
	}
	// Masked before storage, so 10.0.0.5/24 and 10.0.0.0/24 are one row rather
	// than two rows naming the same range.
	prefix = prefix.Masked()

	tenant, _ := tenantFrom(r.Context())
	var nr *store.NetworkRange
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		nr, err = (store.NetworkRanges{}).Add(ctx, c, zoneID, prefix, req.AuthorizationVerified)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusCreated, NetworkRangeResponse{
		ID: nr.ID.String(), Prefix: nr.CIDR.String(), Authorized: nr.Authorized,
	})
}

// ScanPointResponse describes an enrolled scan point.
//
// No certificate fingerprint. It is the scan point's authentication identity and
// the input to tenant_for_scan_point; publishing it through a read endpoint puts
// an authentication input in every operator's browser history for no operational
// benefit.
type ScanPointResponse struct {
	ID              string     `json:"id"`
	ZoneID          string     `json:"zone_id"`
	Hostname        string     `json:"hostname"`
	Status          string     `json:"status"`
	AgentVersion    string     `json:"agent_version"`
	ProtocolVersion string     `json:"protocol_version"`
	LastHeartbeat   *time.Time `json:"last_heartbeat,omitempty"`
}

type ScanPointListResponse struct {
	ScanPoints []ScanPointResponse `json:"scan_points"`
}

func (s *Server) listScanPoints(w http.ResponseWriter, r *http.Request) {
	zoneID, err := pathUUID(r, "zone_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "zone_id is not a uuid.", err)
		return
	}
	tenant, _ := tenantFrom(r.Context())

	var points []store.ScanPoint
	err = s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		points, err = (store.ScanPoints{}).ListByZone(ctx, c, zoneID)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := ScanPointListResponse{ScanPoints: make([]ScanPointResponse, 0, len(points))}
	for _, p := range points {
		out.ScanPoints = append(out.ScanPoints, ScanPointResponse{
			ID: p.ID.String(), ZoneID: p.ZoneID.String(), Hostname: p.Hostname,
			Status: string(p.Status), AgentVersion: p.AgentVersion,
			ProtocolVersion: p.ProtocolVersion, LastHeartbeat: p.LastHeartbeat,
		})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// EnrollmentTokenRequest issues a token for a zone.
type EnrollmentTokenRequest struct {
	ZoneID      string `json:"zone_id" doc:"The zone the scan point is enrolled INTO. A scan point never asserts its own zone (ADR-018)."`
	TTLSeconds  int    `json:"ttl_seconds,omitempty" doc:"Defaults to 24h. Capped at 7 days by the database."`
	Description string `json:"description,omitempty"`
}

// EnrollmentTokenResponse carries the token, once.
type EnrollmentTokenResponse struct {
	TokenID string `json:"token_id"`

	// ============================================================================
	// The only time this value is ever readable.
	// ============================================================================
	//
	// Only its SHA-256 is stored, so it cannot be shown again, recovered, or
	// mailed to somebody who lost it. A lost token is reissued.
	Token     string    `json:"token" doc:"Shown once. Only a SHA-256 of it is stored; it cannot be retrieved again."`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Server) issueEnrollmentToken(w http.ResponseWriter, r *http.Request) {
	var req EnrollmentTokenRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	zoneID, err := uuid.Parse(req.ZoneID)
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "zone_id is not a uuid.", err)
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second

	tenant, _ := tenantFrom(r.Context())
	issued, err := enrollment.NewIssuer(s.db).Issue(r.Context(), tenant, zoneID, actor(r), ttl, req.Description)
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	// The token itself is never logged, here or anywhere. The id and the zone
	// are what an audit needs.
	s.log.Info("enrollment token issued",
		"request_id", requestIDFrom(r.Context()), "token_id", issued.TokenID.String(),
		"zone_id", zoneID.String())

	// Reveal() is called exactly here, at the boundary where the value has to
	// leave the process, and the result goes straight into the response body.
	// It is not held in a variable, not logged, and not put in a struct that
	// something else might render — PlaintextToken redacts every formatting
	// path precisely so that this is the only line where the plaintext exists.
	writeJSON(w, r, s.log, http.StatusCreated, EnrollmentTokenResponse{
		TokenID: issued.TokenID.String(), Token: issued.Token.Reveal(), ExpiresAt: issued.ExpiresAt,
	})
}

func parseUUIDPtr(s *string) (*uuid.UUID, error) {
	if s == nil || *s == "" {
		return nil, nil
	}
	id, err := uuid.Parse(*s)
	if err != nil {
		return nil, err
	}
	return &id, nil
}
