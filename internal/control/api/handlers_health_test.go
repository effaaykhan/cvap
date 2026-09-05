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

// TestScanPointHealthIsSynthesized drives GET /v1/scan-points and asserts the
// health each state resolves to — in particular that an online scan point on an
// unsupported protocol version is `degraded`, not `healthy` (session 22's
// decision: dispatch will not hand it work, so calling it healthy overstates the
// fleet). The fixture's supported window is "v1".
func TestScanPointHealthIsSynthesized(t *testing.T) {
	f := newFixture(t, `{"scanpoint.read": true}`)
	cookies, _ := f.login(t)

	type spec struct {
		hostname     string
		protocol     string
		heartbeatAgo time.Duration // <0 means never
		capable      bool
		status       store.ScanPointStatus
		wantHealth   string
	}
	specs := []spec{
		{"healthy-1", "v1", 10 * time.Second, true, store.ScanPointOnline, "healthy"},
		{"unsupported-proto", "v0", 10 * time.Second, true, store.ScanPointOnline, "degraded"},
		{"no-capability", "v1", 10 * time.Second, false, store.ScanPointOnline, "degraded"},
		{"stale", "v1", 5 * time.Minute, true, store.ScanPointOnline, "offline"},
		{"disabled-1", "v1", 10 * time.Second, true, store.ScanPointDisabled, "disabled"},
		{"never", "v1", -1, true, store.ScanPointPending, "pending"},
	}

	ids := map[string]string{}
	for _, sp := range specs {
		var id uuid.UUID
		if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
			p, err := (store.ScanPoints{}).Create(ctx, c, f.zoneID, sp.hostname, "1.0", sp.protocol, "fp-"+uuid.NewString())
			if err != nil {
				return err
			}
			id = p.ID
			if sp.heartbeatAgo >= 0 {
				if err := (store.ScanPoints{}).Heartbeat(ctx, c, p.ID, time.Now().Add(-sp.heartbeatAgo)); err != nil {
					return err
				}
			}
			if sp.capable {
				if _, err := (store.ScanPoints{}).DeclareCapability(ctx, c, p.ID, store.EngineDiscovery, "1.0", true); err != nil {
					return err
				}
			}
			// Heartbeat forces status online; set the intended status last.
			return (store.ScanPoints{}).SetStatus(ctx, c, p.ID, sp.status)
		}); err != nil {
			t.Fatalf("seed %s: %v", sp.hostname, err)
		}
		ids[id.String()] = sp.wantHealth
	}

	w := f.do(t, http.MethodGet, "/v1/scan-points", nil, cookies, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var resp api.ScanPointListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, p := range resp.ScanPoints {
		got[p.ID] = p.Health
		// A non-healthy state always says why; a healthy one has no reason.
		if p.Health == "healthy" && p.HealthReason != "" {
			t.Errorf("%s healthy but carries a reason %q", p.Hostname, p.HealthReason)
		}
		if p.Health != "healthy" && p.HealthReason == "" {
			t.Errorf("%s is %q with no health_reason", p.Hostname, p.Health)
		}
	}
	for id, want := range ids {
		if got[id] != want {
			t.Errorf("scan point %s: health %q, want %q", id, got[id], want)
		}
	}
}
