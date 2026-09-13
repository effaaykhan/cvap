package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/store"
)

// Health surfaces the identity resolution queue (ADR-096 step 1): the pending
// ITEM count and the distinct contested ADDRESSES — items are several per
// host per scan, addresses are what an operator acts on. An `ip_window` item
// parked before ADR-094 carries `{}` as its payload; migration 0045 backfilled
// its address from the key value, and it must count as an address, not vanish
// from the host number while still counting as an item (the review measured
// 40% of a dev queue in that shape rendering a green "0 hosts").
func TestHealthCountsPendingItemsAndContestedAddresses(t *testing.T) {
	f := newFixture(t, `{"scan.read": true}`)
	cookies, csrf := f.login(t)

	read := func() api.HealthResponse {
		t.Helper()
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
	if h := read(); h.ResolutionQueuePending != 0 || h.ContestedAddresses != 0 {
		t.Fatalf("empty queue reads pending=%d contested=%d", h.ResolutionQueuePending, h.ContestedAddresses)
	}

	var asset, legacy uuid.UUID
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{})
		if err != nil {
			return err
		}
		asset = a.ID
		const ins = `INSERT INTO asset_resolution_queue
		    (tenant_id, observed_payload, key_type, key_value, candidate_asset_ids, conflict_reason, address, source)
		    VALUES ($1, $2, $3::identity_key_type, $4, ARRAY[$5::uuid], 'test', $6::inet,
		            CASE WHEN $3 = 'ip_window' THEN NULL ELSE '22/tcp' END) RETURNING resolution_id`
		var id uuid.UUID
		// Two items at one address: one host. The address column is what is
		// counted (migration 0045 normalises it at write), so a payload that
		// spells the address differently is still the same host.
		if err := c.QueryRow(ctx, ins, tid, `{"address":"10.9.0.1","port":22}`, "ssh_hostkey", "SHA256:aaaa", asset, "10.9.0.1").Scan(&id); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, ins, tid, `{"address":"010.9.0.1","port":8080}`, "ip_window", "10.9.0.1", asset, "10.9.0.1").Scan(&id); err != nil {
			return err
		}
		// A pre-ADR-094 item: empty payload; the migration backfilled its
		// address from the key value.
		return c.QueryRow(ctx, ins, tid, `{}`, "ip_window", "10.9.0.2", asset, "10.9.0.2").Scan(&legacy)
	}); err != nil {
		t.Fatal(err)
	}
	if h := read(); h.ResolutionQueuePending != 3 || h.ContestedAddresses != 2 {
		t.Fatalf("pending=%d contested=%d; want 3 items across 2 addresses — counted by the normalised address column",
			h.ResolutionQueuePending, h.ContestedAddresses)
	}

	// A rotation closes the legacy address's item (ADR-096): it leaves both
	// counts. A rotated item names the asset it attached to (migration 0045's
	// CHECK), as a merged item names the one the operator chose.
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE asset_resolution_queue SET state = 'rotated', resolved_asset_id = $3, resolved_at = now()
		    WHERE tenant_id = $1 AND resolution_id = $2`, c.Tenant().UUID(), legacy, asset)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if h := read(); h.ResolutionQueuePending != 2 || h.ContestedAddresses != 1 {
		t.Fatalf("after one address resolved: pending=%d contested=%d; want 2 items, 1 address", h.ResolutionQueuePending, h.ContestedAddresses)
	}
}
