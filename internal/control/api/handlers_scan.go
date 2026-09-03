package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/target"
)

// ScanTargetInput is one target of a scan being created.
type ScanTargetInput struct {
	Type  string `json:"type" doc:"cidr | host | url | repo | cloud_account."`
	Value string `json:"value" doc:"The target as written. Stored verbatim; the canonical form written to each task is derived at planning (ADR-044)."`

	// ============================================================================
	// The authorisation attestation. Not a formality.
	// ============================================================================
	//
	// Execution-plan §8 risk 6: scanning a network without authorisation is legal
	// exposure and potentially criminal. The column defaults false, planning
	// refuses to decompose a target that still is, and this field is the only way
	// it becomes true. It is per target rather than per scan because
	// authorisation is a statement about a network, and a scan may name several.
	AuthorizationVerified bool `json:"authorization_verified" doc:"Attestation that this target is authorised for scanning. A scan whose targets are not all attested is refused at planning."`
}

// CreateScanRequest is the body of POST /v1/scans.
//
// There is no safety_mode field, deliberately. ADR-021 makes intrusive an
// explicit opt-in with its own audit event and its own permission; a mode
// accepted at creation would make the opt-in a property of the plan, and the
// creator of a scan would be granting themselves an authority the permission
// model hands out separately.
type CreateScanRequest struct {
	PolicyID string            `json:"policy_id" doc:"The policy this scan runs under. Its ceilings bound everything the scan may do."`
	ScanType string            `json:"scan_type" doc:"Which kind of scan. Validated against the scan types Core can plan."`
	Targets  []ScanTargetInput `json:"targets" doc:"At least one. All must be attested as authorised."`
}

// ScanResponse is a scan as the API renders it.
type ScanResponse struct {
	ID          string     `json:"id"`
	PolicyID    string     `json:"policy_id"`
	ScanType    string     `json:"scan_type"`
	Status      string     `json:"status"`
	SafetyMode  string     `json:"safety_mode" doc:"safe unless explicitly opted in beneath the policy ceiling (ADR-021)."`
	RequestedBy *string    `json:"requested_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

type ScanListResponse struct {
	Scans []ScanResponse `json:"scans"`

	// NextBefore is the keyset cursor. Absent when there is no further page.
	NextBefore *string `json:"next_before,omitempty" doc:"Pass as ?before= to fetch the next page."`
	NextID     *string `json:"next_id,omitempty" doc:"Pass as ?before_id= with ?before=."`
}

func scanResponse(s *store.Scan) ScanResponse {
	out := ScanResponse{
		ID: s.ID.String(), PolicyID: s.PolicyID.String(), ScanType: s.ScanType,
		Status: string(s.Status), SafetyMode: string(s.SafetyMode),
		CreatedAt: s.CreatedAt, StartedAt: s.StartedAt, CompletedAt: s.CompletedAt,
	}
	if s.RequestedBy != nil {
		v := s.RequestedBy.String()
		out.RequestedBy = &v
	}
	return out
}

// validScanTargetTypes is the closed set the enum accepts.
//
// Checked here as well as by the database because a bad value would otherwise
// surface as a 500 from a cast failure, which tells the caller nothing and
// reports a client error as ours.
var validScanTargetTypes = map[string]bool{
	"cidr": true, "host": true, "url": true, "repo": true, "cloud_account": true,
}

// validScanStatuses is the scan_status enum, for the list filter.
var validScanStatuses = map[store.ScanStatus]bool{
	store.ScanPending: true, store.ScanPlanning: true, store.ScanRunning: true,
	store.ScanCompleted: true, store.ScanFailed: true,
	store.ScanCancelled: true, store.ScanKilled: true,
}

func (s *Server) createScan(w http.ResponseWriter, r *http.Request) {
	var req CreateScanRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}

	policyID, err := uuid.Parse(req.PolicyID)
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "policy_id is not a uuid.", err)
		return
	}
	if req.ScanType == "" {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "scan_type is required.", nil)
		return
	}
	if len(req.Targets) == 0 {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"A scan needs at least one target.", nil)
		return
	}

	targets := make([]store.ScanTarget, 0, len(req.Targets))
	for _, t := range req.Targets {
		if !validScanTargetTypes[t.Type] {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"A target type must be one of cidr, host, url, repo, cloud_account.", nil)
			return
		}
		if t.Value == "" {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"A target needs a value.", nil)
			return
		}
		// Canonicalised HERE as well as at planning, and the point is WHO is
		// told.
		//
		// Planning is a periodic sweeper pass, so a target with no canonical
		// form would otherwise surface minutes later as a failed scan with a
		// reason in the audit log — while the operator who typed 192.000.2.5 is
		// standing in front of a 201. Canonicalise is a pure function with no
		// I/O, so refusing at the request costs nothing and puts the error where
		// somebody can act on it.
		//
		// The value STORED is still what they wrote (ADR-044): scan_targets
		// records what was authorised, and the canonical form belongs on the
		// task.
		if _, err := target.Canonicalise(t.Value); err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"That target does not name a host this system can reach. A string that names an "+
					"address must parse as one.", err)
			return
		}
		targets = append(targets, store.ScanTarget{
			Type: t.Type, Value: t.Value, Authorized: t.AuthorizationVerified,
		})
	}

	tenant, _ := tenantFrom(r.Context())
	var scan *store.Scan
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		scan, err = (store.Scans{}).Create(ctx, c, policyID, req.ScanType, actor(r), targets)
		if err != nil {
			return err
		}
		// The audit event is in the SAME transaction as the scan, for the
		// reason SetSafetyMode gives about its own: a scan that exists with no
		// record of who asked for it is the record an investigation needs
		// missing precisely where it matters.
		id := scan.ID
		return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
			ActorID: actor(r), ActorType: store.ActorUser,
			Action: "scan.created", ResourceType: "scan", ResourceID: &id,
			Detail: map[string]any{
				"policy_id": policyID.String(),
				"scan_type": req.ScanType,
				"targets":   len(targets),
			},
		})
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}

	writeJSON(w, r, s.log, http.StatusCreated, scanResponse(scan))
}

func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "scan_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "scan_id is not a uuid.", err)
		return
	}
	tenant, _ := tenantFrom(r.Context())

	var scan *store.Scan
	err = s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		scan, err = (store.Scans{}).Get(ctx, c, id)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, scanResponse(scan))
}

func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Validated against the closed set rather than left to the enum cast, which
	// would surface a typo as a 422 with a generic sentence — reporting a client
	// mistake in the same shape as a constraint violation.
	status := store.ScanStatus(q.Get("status"))
	if status != "" && !validScanStatuses[status] {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"status must be one of pending, planning, running, completed, failed, cancelled, killed.", nil)
		return
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := atoiBounded(v, 1, 200)
		if err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"limit must be an integer between 1 and 200.", err)
			return
		}
		limit = n
	}

	var beforeTime *time.Time
	var beforeID *uuid.UUID
	if v := q.Get("before"); v != "" {
		t, err := time.Parse(time.RFC3339Nano, v)
		if err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"before must be an RFC 3339 timestamp.", err)
			return
		}
		id, err := uuid.Parse(q.Get("before_id"))
		if err != nil {
			// Both halves of a keyset cursor or neither. One alone would silently
			// page from a different point than the caller believes.
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
				"before requires before_id, and it must be a uuid.", err)
			return
		}
		beforeTime, beforeID = &t, &id
	}

	tenant, _ := tenantFrom(r.Context())
	var scans []store.Scan
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		scans, err = (store.Scans{}).List(ctx, c, status, limit, beforeTime, beforeID)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}

	out := ScanListResponse{Scans: make([]ScanResponse, 0, len(scans))}
	for i := range scans {
		out.Scans = append(out.Scans, scanResponse(&scans[i]))
	}
	if len(scans) == limit {
		last := scans[len(scans)-1]
		t := last.CreatedAt.Format(time.RFC3339Nano)
		id := last.ID.String()
		out.NextBefore, out.NextID = &t, &id
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// CancelScanRequest carries why.
type CancelScanRequest struct {
	Reason string `json:"reason" doc:"Recorded in the audit event. Required: a stopped scan with no stated reason is an unexplained gap in coverage."`
}

// cancelScan is the operator lever ADR-024 control 4 was missing.
//
// Everything downstream of scans.status = 'cancelled' was built in session 8e
// and unreachable — Jobs.Claim excludes stopped scans, CancellableFor finds the
// in-flight jobs, dispatch sends CancelJob naming the lease epoch. This is the
// endpoint that says so.
func (s *Server) cancelScan(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "scan_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "scan_id is not a uuid.", err)
		return
	}
	var req CancelScanRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	if req.Reason == "" {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "reason is required.", nil)
		return
	}

	tenant, _ := tenantFrom(r.Context())
	var scan *store.Scan
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Scans{}).Cancel(ctx, c, id, actor(r), req.Reason); err != nil {
			return err
		}
		var err error
		scan, err = (store.Scans{}).Get(ctx, c, id)
		return err
	})
	if err != nil {
		if errors.Is(err, store.ErrScanNotCancellable) {
			writeError(w, r, s.log, http.StatusConflict, CodeConflict,
				"That scan has already finished.", err)
			return
		}
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, scanResponse(scan))
}

// SafetyModeRequest is the ADR-021 per-scan opt-in.
type SafetyModeRequest struct {
	SafetyMode string `json:"safety_mode" doc:"safe | intrusive. Must be at or beneath the policy's ceiling."`
}

// setSafetyMode is the second dead path this session activates.
//
// It carries its own permission, separate from scan.create, because choosing to
// send intrusive traffic is a different authority from choosing to run a scan —
// and ADR-021's whole point is that the escalation is a decision somebody makes
// each time rather than a property of a policy left switched on.
func (s *Server) setSafetyMode(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "scan_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "scan_id is not a uuid.", err)
		return
	}
	var req SafetyModeRequest
	if err := decode(w, r, &req); err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"The request body could not be read as this endpoint's schema.", err)
		return
	}
	mode := store.SafetyMode(req.SafetyMode)
	if mode != store.SafetySafe && mode != store.SafetyIntrusive {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"safety_mode must be safe or intrusive.", nil)
		return
	}

	tenant, _ := tenantFrom(r.Context())
	var scan *store.Scan
	err = s.db.Write(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Scans{}).SetSafetyMode(ctx, c, id, mode, actor(r)); err != nil {
			return err
		}
		var err error
		scan, err = (store.Scans{}).Get(ctx, c, id)
		return err
	})
	if err != nil {
		switch {
		case errors.Is(err, store.ErrSafetyModeAbovePolicy):
			writeError(w, r, s.log, http.StatusConflict, CodeConflict,
				"That scan's policy does not permit intrusive scanning. The policy is the ceiling; a scan opts in beneath it.", err)
		case errors.Is(err, store.ErrScanAlreadyStarted):
			writeError(w, r, s.log, http.StatusConflict, CodeConflict,
				"That scan has already started. Safety mode is chosen before a scan runs; cancellation is the lever for one already running.", err)
		default:
			storeError(w, r, s.log, err)
		}
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, scanResponse(scan))
}

func atoiBounded(s string, lo, hi int) (int, error) {
	n := 0
	if s == "" {
		return 0, errors.New("empty")
	}
	for _, ch := range s {
		if ch < '0' || ch > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(ch-'0')
		if n > hi {
			return 0, errors.New("out of range")
		}
	}
	if n < lo {
		return 0, errors.New("out of range")
	}
	return n, nil
}
