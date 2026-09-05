package api

import (
	"context"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// The finding read surface (session 18), and the finding DETAIL is the point of
// it: an analyst reads a finding, sees the evidence that produced it, and checks
// the claim by hand without re-scanning. Findings are derived (ADR-006); nothing
// here writes one.

var validFindingStatuses = map[string]bool{
	"open": true, "confirmed": true, "false_positive": true,
	"accepted_risk": true, "remediated": true, "closed": true,
}

var validSeverities = map[string]bool{
	"info": true, "low": true, "medium": true, "high": true, "critical": true,
}

// FindingSummaryResponse is one row of the finding list.
type FindingSummaryResponse struct {
	ID            string    `json:"id"`
	Rule          string    `json:"rule" doc:"The rule that raised the finding (ADR-009: every finding has one)."`
	Category      string    `json:"category"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	AssetID       string    `json:"asset_id"`
	AssetHostname string    `json:"asset_hostname,omitempty"`
	Locator       string    `json:"instance_locator,omitempty" doc:"Where on the asset, e.g. 443/tcp."`
	Confidence    float64   `json:"confidence"`
	ExposureZones int       `json:"exposure_zones" doc:"Distinct zones this finding is visible from (ADR-008). One finding, N zones — never counted as N findings."`
	FirstSeen     time.Time `json:"first_seen"`
	LastSeen      time.Time `json:"last_seen"`
}

// FindingListResponse is a keyset page of findings, newest-seen first.
type FindingListResponse struct {
	Findings   []FindingSummaryResponse `json:"findings"`
	NextBefore *string                  `json:"next_before,omitempty"`
	NextID     *string                  `json:"next_id,omitempty"`
}

// EvidenceResponse is one piece of the proof, copied from the observation at
// finding creation (ADR-016).
type EvidenceResponse struct {
	Type string         `json:"type" doc:"banner | response | package_version | config_value | code_span."`
	Data map[string]any `json:"data" doc:"The captured summary, redacted to the same standard as the observation it came from."`

	// ObservationID is absent, and ObservationAgedOut true, once the source
	// observation's partition has been dropped (ADR-016). The evidence above is
	// still complete — it was copied, not referenced — so this is provenance
	// degrading rather than data loss, and the UI must say so rather than show a
	// dead link. Every evidence row is born with an observation, so a nil id
	// means aged-out, never "never linked".
	ObservationID      *string `json:"observation_id,omitempty"`
	ObservationAgedOut bool    `json:"observation_aged_out"`

	HasFullArtefact bool      `json:"has_full_artefact" doc:"The summary is not the whole of it; a larger artefact is in the object store (ADR-015)."`
	CapturedAt      time.Time `json:"captured_at"`
}

// ExposureResponse is one vantage point a finding is visible from.
type ExposureResponse struct {
	ZoneID            string    `json:"zone_id"`
	ZoneName          string    `json:"zone_name,omitempty"`
	ZoneType          string    `json:"zone_type"`
	InternetReachable bool      `json:"internet_reachable"`
	AuthRequired      bool      `json:"auth_required"`
	LastConfirmed     time.Time `json:"last_confirmed" doc:"Exposure is derived and goes stale after a network change; this is how fresh it is, shown so staleness is visible rather than silent."`
}

// FindingResponse is the full finding, with the evidence a human verifies it by.
type FindingResponse struct {
	FindingSummaryResponse
	Source      string             `json:"source" doc:"network | credentialed | dast | api | sast | config | cloud (ADR-010)."`
	DedupKey    string             `json:"dedup_key" doc:"The identity this finding persists under across scans (ADR-010). Shown so it is auditable why two observations are, or are not, the same finding."`
	CWE         string             `json:"cwe,omitempty"`
	Remediation string             `json:"remediation,omitempty"`
	HasVulnDef  bool               `json:"has_vuln_def" doc:"A CVE/vuln definition is linked. Nothing branches on this (ADR-009): most findings have none."`
	ResolvedAt  *time.Time         `json:"resolved_at,omitempty"`
	Evidence    []EvidenceResponse `json:"evidence"`
	Exposures   []ExposureResponse `json:"exposures"`
}

// ZoneExposureResponse is one zone's open-finding exposure.
type ZoneExposureResponse struct {
	ZoneID   string `json:"zone_id"`
	ZoneName string `json:"zone_name,omitempty"`
	ZoneType string `json:"zone_type"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
	Total    int    `json:"total" doc:"Distinct open findings visible from THIS zone. NOT summable across zones: a finding visible from three zones counts once in each, so summing would triple-count it (ADR-010)."`
}

// ExposureByZoneResponse is the exposure-by-zone view.
type ExposureByZoneResponse struct {
	Zones []ZoneExposureResponse `json:"zones"`
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	var f store.FindingListFilter
	f.Status = q.Get("status")
	if f.Status != "" && !validFindingStatuses[f.Status] {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"status must be one of open, confirmed, false_positive, accepted_risk, remediated, closed.", nil)
		return
	}
	f.Severity = q.Get("severity")
	if f.Severity != "" && !validSeverities[f.Severity] {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest,
			"severity must be one of info, low, medium, high, critical.", nil)
		return
	}
	if v := q.Get("asset_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "asset_id must be a uuid.", err)
			return
		}
		f.AssetID = id
	}
	if v := q.Get("rule_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "rule_id must be a uuid.", err)
			return
		}
		f.RuleID = id
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

	before, beforeID, ok := s.keysetCursor(w, r)
	if !ok {
		return
	}

	tenant, _ := tenantFrom(r.Context())
	var page *store.FindingPage
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		page, err = (store.Findings{}).List(ctx, c, f, before, beforeID, limit)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}

	out := FindingListResponse{Findings: make([]FindingSummaryResponse, 0, len(page.Findings))}
	for i := range page.Findings {
		out.Findings = append(out.Findings, findingSummaryResponse(page.Findings[i]))
	}
	setKeysetNext(&out.NextBefore, &out.NextID, page.NextBefore, page.NextID)
	writeJSON(w, r, s.log, http.StatusOK, out)
}

func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "finding_id")
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, "finding_id is not a uuid.", err)
		return
	}
	tenant, _ := tenantFrom(r.Context())

	var d *store.FindingDetail
	err = s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		d, err = (store.Findings{}).GetFinding(ctx, c, id)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, findingResponse(d))
}

func (s *Server) exposureByZone(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())
	var zones []store.ZoneExposure
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		zones, err = (store.Findings{}).ExposureByZone(ctx, c)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := ExposureByZoneResponse{Zones: make([]ZoneExposureResponse, 0, len(zones))}
	for _, z := range zones {
		out.Zones = append(out.Zones, ZoneExposureResponse{
			ZoneID: z.ZoneID.String(), ZoneName: z.ZoneName, ZoneType: z.ZoneType,
			Critical: z.Critical, High: z.High, Medium: z.Medium, Low: z.Low, Info: z.Info,
			Total: z.Total,
		})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

func findingSummaryResponse(f store.FindingSummary) FindingSummaryResponse {
	return FindingSummaryResponse{
		ID: f.ID.String(), Rule: f.RuleName, Category: f.Category,
		Severity: f.Severity, Status: f.Status, AssetID: f.AssetID.String(),
		AssetHostname: f.AssetHostname, Locator: f.Locator, Confidence: f.Confidence,
		ExposureZones: f.ExposureZones, FirstSeen: f.FirstSeen, LastSeen: f.LastSeen,
	}
}

func findingResponse(d *store.FindingDetail) FindingResponse {
	out := FindingResponse{
		FindingSummaryResponse: FindingSummaryResponse{
			ID: d.ID.String(), Rule: d.RuleName, Category: d.Category,
			Severity: d.Severity, Status: d.Status, AssetID: d.AssetID.String(),
			AssetHostname: d.AssetHost, Locator: d.Locator, Confidence: d.Confidence,
			ExposureZones: len(d.Exposures), FirstSeen: d.FirstSeen, LastSeen: d.LastSeen,
		},
		Source: d.Source, DedupKey: d.DedupKey, CWE: d.CWE, Remediation: d.Remediation,
		HasVulnDef: d.HasVulnDef, ResolvedAt: d.ResolvedAt,
		Evidence:  make([]EvidenceResponse, 0, len(d.Evidence)),
		Exposures: make([]ExposureResponse, 0, len(d.Exposures)),
	}
	for _, e := range d.Evidence {
		er := EvidenceResponse{
			Type: e.Type, Data: e.Data, CapturedAt: e.CapturedAt,
			HasFullArtefact: e.HasObjectStore,
		}
		if e.ObservationID != nil {
			id := e.ObservationID.String()
			er.ObservationID = &id
		} else {
			er.ObservationAgedOut = true
		}
		out.Evidence = append(out.Evidence, er)
	}
	for _, e := range d.Exposures {
		out.Exposures = append(out.Exposures, ExposureResponse{
			ZoneID: e.ZoneID.String(), ZoneName: e.ZoneName, ZoneType: e.ZoneType,
			InternetReachable: e.InternetReachable, AuthRequired: e.AuthRequired,
			LastConfirmed: e.LastConfirmed,
		})
	}
	return out
}
