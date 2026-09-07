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

// mutate:subject internal/control/api/handlers_scan.go
// mutate:test    ./internal/control/api/ -run TestAScanWithNoCapableScanPointIsRefused
//
// mutate:case    the no-capable-scan-point gate never refuses
// mutate:old     if n == 0 {
// mutate:new     if n < 0 {
//
// mutate:subject internal/store/scanpoints.go
//
// mutate:case    the dispatchable count ignores whether the scan point is online
// mutate:old     AND sp.last_heartbeat > now() - make_interval(secs => $4)
// mutate:new     AND sp.last_heartbeat < now() - make_interval(secs => $4)
//
// The first mutation makes createScan accept a scan no scan point can run — the
// silent non-result this gate exists to refuse; the disabled and stale cases
// below kill it. The second flips the online check so a fresh heartbeat no longer
// counts (and a stale one would): the happy case, whose scan point just
// heartbeated, then gets refused, killing it.

// TestAScanWithNoCapableScanPointIsRefused is the fix for the worst failure this
// product can have: a scan that runs against nothing while reporting activity, so
// the operator reads "clean" instead of "broken". A scan is refused at creation
// unless some scan point is online and capable of its engine in a zone the policy
// permits.
func TestAScanWithNoCapableScanPointIsRefused(t *testing.T) {
	f := newFixture(t, `{"scan.read": true, "scan.create": true}`)
	f.seedScanPoint(t)
	cookies, csrf := f.login(t)

	body := map[string]any{
		"policy_id": f.policyID.String(), "scan_type": "discovery",
		"targets": []map[string]any{{"type": "cidr", "value": "192.0.2.0/30", "authorization_verified": true}},
	}

	// The seeded scan point is capable (discovery) and online, so the scan is
	// accepted — the gate must not refuse a scan Core CAN dispatch.
	if w := f.do(t, http.MethodPost, "/v1/scans", body, cookies, csrf); w.Code != http.StatusCreated {
		t.Fatalf("with a capable online scan point, create gave %d, want 201: %s", w.Code, w.Body.String())
	}
	before := scanCount(t, f, cookies)

	// Make the scan point stale: online status, but a heartbeat older than the
	// timeout. Core cannot dispatch to it, so the scan is refused.
	setHeartbeat(t, f, f.scanPointID, time.Now().Add(-1*time.Hour))
	if w := f.do(t, http.MethodPost, "/v1/scans", body, cookies, csrf); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("with a stale scan point, create gave %d, want 422: %s", w.Code, w.Body.String())
	}

	// Disable the scan point entirely. Still refused.
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.ScanPoints{}).SetStatus(ctx, c, f.scanPointID, store.ScanPointDisabled)
	}); err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodPost, "/v1/scans", body, cookies, csrf)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("with a disabled scan point, create gave %d, want 422: %s", w.Code, w.Body.String())
	}

	// A refusal must not create a scan row. A silent create behind a 422 is the
	// same lie as a silent success — the scan would sit there scanning nothing.
	if after := scanCount(t, f, cookies); after != before {
		t.Errorf("refused scans still created rows: %d -> %d", before, after)
	}
}

// TestAnUnplannableScanTypeIsRefusedAtCreation: Core has three engines; a
// scan_type it has none for is refused where the operator can act on it, not
// left to fail at planning minutes later.
func TestAnUnplannableScanTypeIsRefusedAtCreation(t *testing.T) {
	f := newFixture(t, `{"scan.read": true, "scan.create": true}`)
	cookies, csrf := f.login(t)
	body := map[string]any{
		"policy_id": f.policyID.String(), "scan_type": "dast",
		"targets": []map[string]any{{"type": "cidr", "value": "192.0.2.0/30", "authorization_verified": true}},
	}
	if w := f.do(t, http.MethodPost, "/v1/scans", body, cookies, csrf); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("an unplannable scan_type gave %d, want 422: %s", w.Code, w.Body.String())
	}
}

func scanCount(t *testing.T, f *fixture, cookies []*http.Cookie) int {
	t.Helper()
	w := f.do(t, http.MethodGet, "/v1/scans", nil, cookies, "")
	if w.Code != http.StatusOK {
		t.Fatalf("listing scans gave %d", w.Code)
	}
	var resp api.ScanListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return len(resp.Scans)
}

func setHeartbeat(t *testing.T, f *fixture, id uuid.UUID, at time.Time) {
	t.Helper()
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.ScanPoints{}).Heartbeat(ctx, c, id, at)
	}); err != nil {
		t.Fatal(err)
	}
}
