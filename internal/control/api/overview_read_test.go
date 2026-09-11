package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/store"
)

// The operator landing's summary (console rung 2 and 5): every number must be
// reproducible from the finding rows. These seed through the store and read
// through the API, then move a finding through its states and require the
// counts and the series to follow — a summary that stayed put would be a
// rollup with a life of its own.
func TestFindingSummaryCountsFollowTheRows(t *testing.T) {
	f := newFixture(t, `{"finding.read": true}`)
	cookies, csrf := f.login(t)

	read := func() api.FindingSummaryStatsResponse {
		w := f.do(t, http.MethodGet, "/v1/findings/summary?days=7&trend_days=14", nil, cookies, csrf)
		if w.Code != http.StatusOK {
			t.Fatalf("summary: %d %s", w.Code, w.Body.String())
		}
		var out api.FindingSummaryStatsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	before := read()
	if before.Open != 0 || before.NewSince != 0 || len(before.Trend) != 14 {
		t.Fatalf("empty tenant: open=%d new=%d trend=%d, want 0/0/14", before.Open, before.NewSince, len(before.Trend))
	}

	sf := f.seedFinding(t, false)
	after := read()
	if after.Open != 1 || after.NewSince != 1 {
		t.Errorf("one open finding seeded: open=%d new_since=%d, want 1/1", after.Open, after.NewSince)
	}
	if after.BySeverity["high"]+after.BySeverity["critical"]+after.BySeverity["medium"]+after.BySeverity["low"]+after.BySeverity["info"] != 1 {
		t.Errorf("by_severity does not sum to the open count: %v", after.BySeverity)
	}
	if len(after.NewItems) != 1 || after.NewItems[0].ID != sf.findingID.String() {
		t.Errorf("new_items = %+v, want the seeded finding", after.NewItems)
	}
	if len(after.WorstAssets) != 1 || after.WorstAssets[0].ID != sf.assetID.String() || after.WorstAssets[0].Open != 1 {
		t.Errorf("worst_assets = %+v, want the seeded asset with one open finding", after.WorstAssets)
	}

	// The inventory row carries the same facts, and the risk order puts the
	// burdened system first even when it was seen earlier than a clean one.
	{
		w := f.do(t, http.MethodGet, "/v1/assets?sort=risk&at_risk=true", nil, cookies, csrf)
		if w.Code != http.StatusForbidden {
			t.Fatalf("assets without asset.read gave %d, want 403", w.Code)
		}
	}
	fa := newFixture(t, `{"finding.read": true, "asset.read": true}`)
	sfa := fa.seedFinding(t, false)
	ca, xa := fa.login(t)
	if err := fa.db.Write(context.Background(), fa.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "clean-and-newer.corp", Environment: "production"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var list api.AssetListResponse
	wr := fa.do(t, http.MethodGet, "/v1/assets?sort=risk", nil, ca, xa)
	if err := json.Unmarshal(wr.Body.Bytes(), &list); err != nil || wr.Code != http.StatusOK {
		t.Fatalf("assets sort=risk: %d %s", wr.Code, wr.Body.String())
	}
	if len(list.Assets) < 2 || list.Assets[0].ID != sfa.assetID.String() {
		t.Fatalf("risk order did not put the burdened asset first: %+v", list.Assets)
	}
	if row := list.Assets[0]; row.OpenFindings != 1 || row.WorstSeverity == "" || row.AdvisoryStatus == "" {
		t.Errorf("inventory row lacks its risk facts: %+v", row)
	}
	wr = fa.do(t, http.MethodGet, "/v1/assets?at_risk=true", nil, ca, xa)
	if err := json.Unmarshal(wr.Body.Bytes(), &list); err != nil || len(list.Assets) != 1 {
		t.Errorf("at_risk=true returned %d assets, want 1: %s", len(list.Assets), wr.Body.String())
	}
	last := after.Trend[len(after.Trend)-1]
	if last.Open != 1 {
		t.Errorf("today's trend point open=%d, want 1 (it must equal the open count)", last.Open)
	}
	if after.Trend[0].Open != 0 {
		t.Errorf("a finding first seen today is counted %d on the earliest day, want 0", after.Trend[0].Open)
	}

	// Backdate it ten days and resolve it three days ago: the series must show
	// it open for the days in between and gone after, and the window counts
	// must move from "new" to "resolved".
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`UPDATE findings SET first_seen = now() - interval '10 days', status = 'remediated',
			        resolved_at = now() - interval '3 days'
			  WHERE tenant_id = $1 AND finding_id = $2`, c.Tenant().UUID(), sf.findingID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	moved := read()
	if moved.Open != 0 || moved.NewSince != 0 || moved.ResolvedSince != 1 {
		t.Errorf("after resolving: open=%d new=%d resolved=%d, want 0/0/1", moved.Open, moved.NewSince, moved.ResolvedSince)
	}
	// 14 points: days -13..0. First seen at -10, resolved at -3: open on -10..-4.
	openDays := 0
	for _, p := range moved.Trend {
		openDays += p.Open
	}
	if openDays != 7 {
		t.Errorf("the series counts the finding open on %d days, want 7 (first seen -10d, resolved -3d): %+v", openDays, moved.Trend)
	}
	if moved.Trend[len(moved.Trend)-1].Open != 0 {
		t.Error("today's point still counts a resolved finding")
	}

	// A recorded reopen transition is what reopened_since counts.
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Findings{}).RecordTransition(ctx, c, sf.findingID, "remediated", "open", "seen again", time.Now())
	}); err != nil {
		t.Fatal(err)
	}
	if got := read().ReopenedSince; got != 1 {
		t.Errorf("reopened_since = %d, want 1 after a recorded remediated->open transition", got)
	}

	w := f.do(t, http.MethodGet, "/v1/findings/summary?days=0", nil, cookies, csrf)
	if w.Code != http.StatusBadRequest {
		t.Errorf("days=0 gave %d, want 400", w.Code)
	}
}

// The health surface (console rung 4): blocked-for-capacity is the same
// predicate scan creation refuses on, asked again after the fleet changed.
func TestHealthNamesBlockedScansAndKillState(t *testing.T) {
	f := newFixture(t, `{"scan.read": true}`)
	f.seedScanPoint(t) // capable and online, so the scan below is dispatchable
	cookies, csrf := f.login(t)

	read := func() api.HealthResponse {
		w := f.do(t, http.MethodGet, "/v1/health", nil, cookies, csrf)
		if w.Code != http.StatusOK {
			t.Fatalf("health: %d %s", w.Code, w.Body.String())
		}
		var out api.HealthResponse
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// A running scan with a queued discovery job; the fixture's scan point is
	// online and capable, so nothing is blocked.
	var scanID uuid.UUID
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type, status) VALUES ($1,$2,'discovery','running') RETURNING scan_id`,
			tid, f.policyID).Scan(&scanID); err != nil {
			return err
		}
		_, err := c.Exec(ctx, `INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe) VALUES ($1,$2,'discovery',true)`, tid, scanID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h := read()
	if len(h.BlockedScans) != 0 {
		t.Fatalf("a scan with a capable online scan point reads as blocked: %+v", h.BlockedScans)
	}
	if h.KillSwitchState != "inactive" || h.ScopeEnforcementSites != 2 {
		t.Errorf("kill=%q sites=%d, want inactive/2", h.KillSwitchState, h.ScopeEnforcementSites)
	}

	// The scan point goes quiet past the heartbeat timeout: the scan is now
	// blocked, and the reason names the engine.
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE scan_points SET last_heartbeat = now() - interval '1 day' WHERE tenant_id = $1`, c.Tenant().UUID())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h = read()
	if len(h.BlockedScans) != 1 || h.BlockedScans[0].ID != scanID.String() || h.BlockedScans[0].Engine != "discovery" {
		t.Fatalf("blocked_scans = %+v, want the running scan whose only scan point went offline", h.BlockedScans)
	}

	// A tenant-wide kill: active, and every covered scan point that has not
	// acknowledged is counted. The scan point comes back online first — an
	// offline one is outside the acknowledgement set by design (a dead scan
	// point cannot ack, and counting it forever would make the bound unmeasurable).
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := c.Exec(ctx, `UPDATE scan_points SET last_heartbeat = now() WHERE tenant_id = $1`, c.Tenant().UUID()); err != nil {
			return err
		}
		_, err := (store.KillSwitches{}).Issue(ctx, c, store.KillTenant, nil, nil, nil, "health test")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	h = read()
	if h.KillSwitchState != "active" || len(h.ActiveKills) != 1 || h.ActiveKills[0].Unacknowledged < 1 {
		t.Errorf("after a tenant kill: state=%q kills=%+v, want active with unacknowledged >= 1", h.KillSwitchState, h.ActiveKills)
	}
}

func TestSummaryAndHealthRequireTheirPermissions(t *testing.T) {
	scanOnly := newFixture(t, `{"scan.read": true}`)
	c1, x1 := scanOnly.login(t)
	if w := scanOnly.do(t, http.MethodGet, "/v1/findings/summary", nil, c1, x1); w.Code != http.StatusForbidden {
		t.Errorf("summary without finding.read gave %d, want 403", w.Code)
	}
	findingOnly := newFixture(t, `{"finding.read": true}`)
	c2, x2 := findingOnly.login(t)
	if w := findingOnly.do(t, http.MethodGet, "/v1/health", nil, c2, x2); w.Code != http.StatusForbidden {
		t.Errorf("health without scan.read gave %d, want 403", w.Code)
	}
}
