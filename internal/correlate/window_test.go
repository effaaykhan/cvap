package correlate_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// The ADR-091 trust root rests on the address relationship: a sighting counts
// for as long as the address it was seen at is evidence of the same host
// (ADR-094). The two windows used to be constants in two packages, asserted
// equal; since ADR-100 they are one per-tenant setting read inside each
// transaction that uses it. This proves the store's sighting decay reads that
// setting rather than a constant: a 48-hour window, two sightings three days
// apart, and the count starts over — under the 7-day default it would be 2.
func TestASightingLivesExactlyAsLongAsTheTenantsWindow(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "window")
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-10 * 24 * time.Hour)
	var asset uuid.UUID
	key := domain.IdentityKey{Type: domain.KeySSHHostKey, Value: "SHA256:window-key", Source: "22/tcp"}
	if err := db.Write(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.IdentitySettings{}).SetWindow(ctx, c, 48*time.Hour, nil, t0); err != nil {
			return err
		}
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{})
		if err != nil {
			return err
		}
		asset = a.ID
		for i, at := range []time.Time{t0, t0.Add(3 * 24 * time.Hour)} {
			if _, err := (store.AssetIdentityKeys{}).Record(ctx, c, asset, key, at, store.KeyFromAttach, uuid.New(), "10.0.0.50", 22); err != nil {
				return fmt.Errorf("sighting %d: %w", i, err)
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var seen int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT scans_seen FROM asset_identity_key_sightings WHERE tenant_id = $1 AND address = '10.0.0.50'`, s.tenant.UUID()).Scan(&seen)
	}); err != nil {
		t.Fatal(err)
	}
	if seen != 1 {
		t.Fatalf("scans_seen after two sightings three days apart under a 48h window = %d, want 1 (the decay reads the tenant's window)", seen)
	}
}
