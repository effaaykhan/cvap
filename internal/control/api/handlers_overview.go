package api

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// The console's landing and health reads (design spec, backlog #12). Both
// follow the rule the knowledge-freshness surface set: every verdict is
// computed server-side from the data and the UI renders the word, never
// recomputes it. Every count is a count of rows the list endpoints page over,
// so an operator can open what any number here counts.

// ChangedFindingResponse is one finding named on the change list.
type ChangedFindingResponse struct {
	ID            string    `json:"id"`
	Rule          string    `json:"rule"`
	AssetHostname string    `json:"asset_hostname,omitempty"`
	Severity      string    `json:"severity"`
	KEV           bool      `json:"kev"`
	At            time.Time `json:"at" doc:"When it appeared (first_seen) or, for a KEV listing, the date CISA added the CVE."`
}

// AssetRiskResponse is one system on the worst-systems list.
type AssetRiskResponse struct {
	ID            string `json:"id"`
	Hostname      string `json:"hostname,omitempty"`
	Address       string `json:"address,omitempty"`
	Open          int    `json:"open"`
	Critical      int    `json:"critical"`
	High          int    `json:"high"`
	Medium        int    `json:"medium"`
	Low           int    `json:"low"`
	KEV           int    `json:"kev"`
	WorstSeverity string `json:"worst_severity"`
}

// TrendPointResponse is one day of the open-finding series.
type TrendPointResponse struct {
	Day  string `json:"day" doc:"UTC calendar day, YYYY-MM-DD."`
	Open int    `json:"open" doc:"Findings first seen on or before this day and not resolved by its end."`
	KEV  int    `json:"kev" doc:"The subset of open whose CVE is in CISA KEV today."`
}

// FindingSummaryStatsResponse is what the operator landing draws from.
type FindingSummaryStatsResponse struct {
	Open       int            `json:"open" doc:"Findings in open or confirmed status. Exact."`
	KEVOpen    int            `json:"kev_open" doc:"Open findings whose CVE is in CISA KEV. Exact."`
	BySeverity map[string]int `json:"by_severity"`

	Since          time.Time `json:"since" doc:"Start of the change window; the window is a fixed number of days, not a per-user last visit."`
	WindowDays     int       `json:"window_days"`
	NewSince       int       `json:"new_since" doc:"Open findings first seen inside the window."`
	ResolvedSince  int       `json:"resolved_since" doc:"Findings resolved inside the window (remediated or superseded)."`
	ReopenedSince  int       `json:"reopened_since" doc:"Recorded transitions back to open inside the window (finding_history)."`
	KEVListedSince int       `json:"kev_listed_since" doc:"Open findings whose CVE CISA added to KEV inside the window — the ones that re-ranked."`

	NewItems       []ChangedFindingResponse `json:"new_items"`
	KEVListedItems []ChangedFindingResponse `json:"kev_listed_items"`

	WorstAssets []AssetRiskResponse `json:"worst_assets" doc:"The systems carrying the most open findings, worst first: KEV first, then the highest severity present, then count. Which system is vulnerable, by asset rather than by rule."`

	TrendDays int                  `json:"trend_days"`
	Trend     []TrendPointResponse `json:"trend" doc:"Oldest first; the last point is today so far. Derived from first_seen and resolved_at, so it is reproducible from the finding rows and has no rollup of its own."`
}

// BlockedScanResponse is a scan that will not progress because nothing can
// claim its queued jobs — the silent-success class, named.
type BlockedScanResponse struct {
	ID       string `json:"id"`
	ScanType string `json:"scan_type"`
	Status   string `json:"status"`
	PolicyID string `json:"policy_id"`
	Engine   string `json:"engine"`
	Reason   string `json:"reason" doc:"Why no scan point can claim its jobs, in the words Jobs.Claim's predicate would use."`
}

// ActiveKillResponse is one unresolved kill switch and how far it has propagated.
type ActiveKillResponse struct {
	ID             string    `json:"id"`
	Scope          string    `json:"scope"`
	ZoneID         *string   `json:"zone_id,omitempty"`
	ScanID         *string   `json:"scan_id,omitempty"`
	IssuedAt       time.Time `json:"issued_at"`
	Reason         string    `json:"reason"`
	Unacknowledged int       `json:"unacknowledged" doc:"Scan points the kill covers that have not acknowledged it — the propagation bound ADR-024 requires to be measurable."`
}

// HealthResponse is the pipeline-and-safety surface: what is not working, from
// server-owned state, never inferred by the client.
type HealthResponse struct {
	BlockedScans []BlockedScanResponse `json:"blocked_scans" doc:"Scans still meant to run with queued jobs no online, capable scan point in a permitted zone can claim."`

	IngestBacklog          int64 `json:"ingest_backlog" doc:"Observations still pending — never attested complete by a terminal ack — older than one hour, within the last 7 days (ADR-026 keeps them; this makes the count visible)."`
	UnresolvedObservations int64 `json:"unresolved_observations" doc:"Accepted observations in the last 7 days that correlation has not attached to an asset yet."`
	ResolutionQueuePending int64 `json:"resolution_queue_pending" doc:"Items in the identity resolution queue awaiting an operator (ADR-007/094): one per (observation, key) parked because the evidence at an address contradicts what the asset holds — several per host per scan. No operator verb exists yet (B39); an item leaves only when a later scan classifies the contradiction as a key rotation (ADR-096). See contested_addresses for the host count."`
	ContestedAddresses     int64 `json:"contested_addresses" doc:"Distinct addresses with a pending resolution item — the number of hosts an operator would act on; each is a host whose inventory has stopped moving."`

	KillSwitchState string               `json:"kill_switch_state" doc:"active when any kill is unresolved; inactive otherwise. The control is always armed; this is whether it is pressed."`
	ActiveKills     []ActiveKillResponse `json:"active_kills"`

	CredentialGrantsUnconfirmed int `json:"credential_grants_unconfirmed" doc:"Credential releases past their expiry with no zeroisation attestation from the scan point that received them (migration 0006)."`

	ScopeEnforcementSites int `json:"scope_enforcement_sites" doc:"Always 2 (Core at planning, the scan point on the send path — ADR-024). A property of the design asserted by the safety gate, reported so the surface says what is measured and what is not."`

	ComputedAt time.Time `json:"computed_at"`
}

const (
	defaultWindowDays = 7
	defaultTrendDays  = 30
	healthLookback    = 7 * 24 * time.Hour
	ingestBacklogAge  = time.Hour
)

func intQuery(r *http.Request, key string, def, min, max int) (int, error) {
	v := r.URL.Query().Get(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, min, max)
	}
	return n, nil
}

func (s *Server) findingSummaryStats(w http.ResponseWriter, r *http.Request) {
	windowDays, err := intQuery(r, "days", defaultWindowDays, 1, 90)
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, err.Error()+".", nil)
		return
	}
	trendDays, err := intQuery(r, "trend_days", defaultTrendDays, 7, 90)
	if err != nil {
		writeError(w, r, s.log, http.StatusBadRequest, CodeBadRequest, err.Error()+".", nil)
		return
	}
	now := time.Now().UTC()
	since := now.Add(-time.Duration(windowDays) * 24 * time.Hour)

	tenant, _ := tenantFrom(r.Context())
	var stats *store.FindingStats
	if err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		stats, err = (store.Findings{}).Stats(ctx, c, since, now, trendDays)
		return err
	}); err != nil {
		storeError(w, r, s.log, err)
		return
	}

	items := func(in []store.ChangedFinding) []ChangedFindingResponse {
		out := make([]ChangedFindingResponse, 0, len(in))
		for _, i := range in {
			out = append(out, ChangedFindingResponse{
				ID: i.ID.String(), Rule: i.RuleName, AssetHostname: i.AssetHostname,
				Severity: i.Severity, KEV: i.KEV, At: i.At,
			})
		}
		return out
	}
	out := FindingSummaryStatsResponse{
		Open: stats.Open, KEVOpen: stats.KEVOpen, BySeverity: stats.BySeverity,
		Since: since, WindowDays: windowDays,
		NewSince: stats.NewSince, ResolvedSince: stats.ResolvedSince,
		ReopenedSince: stats.ReopenedSince, KEVListedSince: stats.KEVListedSince,
		NewItems: items(stats.NewItems), KEVListedItems: items(stats.KEVListedItems),
		TrendDays: trendDays, Trend: make([]TrendPointResponse, 0, len(stats.Trend)),
		WorstAssets: make([]AssetRiskResponse, 0, len(stats.WorstAssets)),
	}
	for _, a := range stats.WorstAssets {
		out.WorstAssets = append(out.WorstAssets, AssetRiskResponse{
			ID: a.ID.String(), Hostname: a.Hostname, Address: a.Address, Open: a.Open,
			Critical: a.Critical, High: a.High, Medium: a.Medium, Low: a.Low, KEV: a.KEV, WorstSeverity: a.WorstSeverity,
		})
	}
	for _, p := range stats.Trend {
		out.Trend = append(out.Trend, TrendPointResponse{Day: p.Day.UTC().Format("2006-01-02"), Open: p.Open, KEV: p.KEV})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	tenant, _ := tenantFrom(r.Context())
	out := HealthResponse{
		BlockedScans: []BlockedScanResponse{}, ActiveKills: []ActiveKillResponse{},
		KillSwitchState: "inactive", ScopeEnforcementSites: 2, ComputedAt: now,
	}
	if err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		// Blocked for capacity: the same predicate scan creation refuses on,
		// asked again for scans that were accepted and whose fleet has since
		// changed under them (a scan point went offline, a capability was
		// disabled). CountDispatchable mirrors Jobs.Claim, so "blocked" here is
		// "Claim would hand this to nobody".
		scans, err := (store.Scans{}).ActiveWithQueuedJobs(ctx, c)
		if err != nil {
			return err
		}
		for _, sc := range scans {
			engine, ok := store.EngineForScanType(sc.ScanType)
			if !ok {
				out.BlockedScans = append(out.BlockedScans, BlockedScanResponse{
					ID: sc.ID.String(), ScanType: sc.ScanType, Status: string(sc.Status), PolicyID: sc.PolicyID.String(),
					Reason: "Core has no engine that runs this scan type",
				})
				continue
			}
			n, err := (store.ScanPoints{}).CountDispatchable(ctx, c, engine, sc.PolicyID)
			if err != nil {
				return err
			}
			if n == 0 {
				out.BlockedScans = append(out.BlockedScans, BlockedScanResponse{
					ID: sc.ID.String(), ScanType: sc.ScanType, Status: string(sc.Status), PolicyID: sc.PolicyID.String(),
					Engine: string(engine),
					Reason: fmt.Sprintf("no online scan point with the %s engine enabled in a zone this policy allows", engine),
				})
			}
		}

		if out.IngestBacklog, err = (store.Observations{}).PendingOlderThan(ctx, c, now.Add(-healthLookback), now.Add(-ingestBacklogAge)); err != nil {
			return err
		}
		if out.UnresolvedObservations, err = (store.Observations{}).CountUnresolved(ctx, c, now.Add(-healthLookback), now); err != nil {
			return err
		}
		if out.ResolutionQueuePending, err = (store.ResolutionQueue{}).PendingCount(ctx, c); err != nil {
			return err
		}
		if out.ContestedAddresses, err = (store.ResolutionQueue{}).PendingAddresses(ctx, c); err != nil {
			return err
		}

		kills, err := (store.KillSwitches{}).Active(ctx, c)
		if err != nil {
			return err
		}
		for _, k := range kills {
			unacked, err := (store.KillSwitches{}).Unacknowledged(ctx, c, k.ID)
			if err != nil {
				return err
			}
			out.ActiveKills = append(out.ActiveKills, ActiveKillResponse{
				ID: k.ID.String(), Scope: string(k.Scope), ZoneID: uuidString(k.ZoneID), ScanID: uuidString(k.ScanID),
				IssuedAt: k.IssuedAt, Reason: k.Reason, Unacknowledged: len(unacked),
			})
		}
		if len(kills) > 0 {
			out.KillSwitchState = "active"
		}

		unconfirmed, err := (store.CredentialGrants{}).Unconfirmed(ctx, c, now, 1000)
		if err != nil {
			return err
		}
		out.CredentialGrantsUnconfirmed = len(unconfirmed)
		return nil
	}); err != nil {
		storeError(w, r, s.log, err)
		return
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

func uuidString(id *uuid.UUID) *string {
	if id == nil {
		return nil
	}
	s := id.String()
	return &s
}
