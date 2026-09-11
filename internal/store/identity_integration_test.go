package store_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// The address-interval invariant, asserted against the DATABASE.
//
// ============================================================================
// The constraint is tested here as well as the outcome, because the failure it
// prevents is AMBIGUITY and ambiguity does not announce itself.
// ============================================================================
//
// If a DHCP move opens a new interval without closing the old one, two assets
// both claim the address. Nothing errors. Every later correlation then finds two
// candidates and returns ambiguous rather than merging, and merge quality
// degrades quietly until somebody notices the inventory has doubled.
//
// A test that only asserted "the DHCP scenario resolves to one asset" would pass
// on a system where the close step had been removed, right up until the second
// host appeared. So these assert the constraint itself.

func newAsset(t *testing.T, db *store.DB, tenant store.TenantID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{})
		if err != nil {
			return err
		}
		id = a.ID
		return nil
	}); err != nil {
		t.Fatalf("create asset: %v", err)
	}
	return id
}

// TestTwoAssetsCannotHoldOneLiveAddress.
//
// Migration 0031. The insert must be REFUSED by the database, not merely avoided
// by the caller: correlation orders its statements correctly today, and the
// index is what makes that still true after somebody edits it.
func TestTwoAssetsCannotHoldOneLiveAddress(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "addr-"+uuid.NewString()[:8])
	a, b := newAsset(t, db, tenant), newAsset(t, db, tenant)
	now := time.Now().UTC()

	// A holds it.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AssetAddresses{}).Open(ctx, c, a, "10.10.0.11", now)
	}); err != nil {
		t.Fatalf("open for A: %v", err)
	}

	// ================================================================
	// The sabotage: open for B WITHOUT closing A's interval.
	// ================================================================
	//
	// This is the raw INSERT that AssetAddresses.Open deliberately does not do —
	// it closes other holders first. Reaching past that method is the point: the
	// question is whether the database refuses, not whether our code remembers.
	err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, e := c.Exec(ctx, `
			INSERT INTO asset_addresses (tenant_id, asset_id, ip_address, valid_from)
			VALUES ($1, $2, $3::inet, $4)`, tenant.UUID(), b, "10.10.0.11", now)
		return e
	})
	if err == nil {
		t.Fatal("two assets hold one live address and the database allowed it. Every later " +
			"correlation against that address is now ambiguous rather than wrong, which " +
			"degrades merge quality silently.")
	}
	if !strings.Contains(err.Error(), "asset_addresses_one_live_holder_idx") &&
		!strings.Contains(strings.ToLower(err.Error()), "conflict") &&
		!strings.Contains(strings.ToLower(err.Error()), "duplicate") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// TestTheAddressMovesWhenTheHostDoes.
//
// The legitimate sequence: close, then open. Open does both, in that order, in
// one statement pair — which is what keeps the constraint above satisfiable.
func TestTheAddressMovesWhenTheHostDoes(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "move-"+uuid.NewString()[:8])
	a, b := newAsset(t, db, tenant), newAsset(t, db, tenant)
	now := time.Now().UTC()

	ctx := context.Background()
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AssetAddresses{}).Open(ctx, c, a, "10.10.0.12", now)
	}); err != nil {
		t.Fatal(err)
	}
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AssetAddresses{}).Open(ctx, c, b, "10.10.0.12", now.Add(time.Hour))
	}); err != nil {
		t.Fatalf("the move was refused: %v", err)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		id, _, err := (store.AssetAddresses{}).LiveHolder(ctx, c, "10.10.0.12")
		if err != nil {
			return err
		}
		if id != b {
			t.Errorf("live holder is %v, want B — the move did not transfer it", id)
		}
		// A's interval is CLOSED, not deleted: the history is what makes an old
		// finding's locator meaningful.
		var n int
		if err := c.QueryRow(ctx, `
			SELECT count(*) FROM asset_addresses
			 WHERE tenant_id = $1 AND asset_id = $2 AND ip_address = $3::inet
			   AND valid_to IS NOT NULL`, tenant.UUID(), a, "10.10.0.12").Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("A has %d closed intervals for the address, want 1; the history was "+
				"deleted rather than closed", n)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestRescanningDoesNotOpenASecondInterval.
//
// One continuous tenancy is one row. Reopening on every scan would turn the
// address history — the thing the interval exists for — into a scan log.
func TestRescanningDoesNotOpenASecondInterval(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "rescan-"+uuid.NewString()[:8])
	a := newAsset(t, db, tenant)
	now := time.Now().UTC()

	ctx := context.Background()
	for i := range 3 {
		at := now.Add(time.Duration(i) * time.Hour)
		if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			if err := (store.AssetAddresses{}).Open(ctx, c, a, "10.10.0.13", at); err != nil {
				return err
			}
			return (store.AssetAddresses{}).TouchLive(ctx, c, a, "10.10.0.13", at)
		}); err != nil {
			t.Fatal(err)
		}
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var n int
		if err := c.QueryRow(ctx, `
			SELECT count(*) FROM asset_addresses
			 WHERE tenant_id = $1 AND asset_id = $2`, tenant.UUID(), a).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("%d address rows after three scans, want 1", n)
		}
		_, lastSeen, err := (store.AssetAddresses{}).LiveHolder(ctx, c, "10.10.0.13")
		if err != nil {
			return err
		}
		if !lastSeen.After(now) {
			t.Errorf("valid_from is %v and was not refreshed; the window would expire on a "+
				"host that is being scanned continuously", lastSeen)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOneLiveKeyValuePerTenantAndType.
//
// Migration 0007's partial unique index. Two assets holding the same live strong
// key at once IS the wrong-merge state the ranked-key scheme exists to prevent,
// so the database refuses it rather than trusting the resolver never to ask.
func TestOneLiveKeyValuePerTenantAndType(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "keys-"+uuid.NewString()[:8])
	a, b := newAsset(t, db, tenant), newAsset(t, db, tenant)
	now := time.Now().UTC()

	k := domain.IdentityKey{
		Type: domain.KeySSHHostKey, Value: "SHA256:shared", Source: "22/tcp",
	}
	ctx := context.Background()
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AssetIdentityKeys{}).Record(ctx, c, a, k, now, store.KeyFromNewAsset, uuid.Nil, "", 0)
	}); err != nil {
		t.Fatal(err)
	}

	// Record's ON CONFLICT updates only the SAME asset's row (a sighting), so
	// the second write is a no-op rather than an error — and the assertion is
	// that B did NOT acquire the key.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AssetIdentityKeys{}).Record(ctx, c, b, k, now, store.KeyFromNewAsset, uuid.Nil, "", 0)
	}); err != nil {
		t.Fatalf("the second Record errored rather than doing nothing: %v", err)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		id, err := (store.AssetIdentityKeys{}).LiveByValue(ctx, c, k.Type, k.Value)
		if err != nil {
			return err
		}
		if id != a {
			t.Errorf("the key moved to %v; a live key value must stay with the asset that "+
				"first held it until it is closed", id)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestMergeEvidenceIsCopiedNotJustReferenced.
//
// ADR-007 requires both, and migration 0007 has a CHECK asserting they arrive
// together: half the evidence is worse than none, because it looks complete.
// The copy is what lets a merge stay auditable after the observation partition
// drops (ADR-016).
func TestMergeEvidenceIsCopiedNotJustReferenced(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "evidence-"+uuid.NewString()[:8])
	a := newAsset(t, db, tenant)
	now := time.Now().UTC()

	obsID := uuid.New()
	k := domain.IdentityKey{
		Type: domain.KeyServiceCert, Value: "SHA256:cert", Source: "443/tcp",
		ObservationID: obsID, Payload: []byte(`{"address":"10.10.0.15","port":443}`),
	}
	ctx := context.Background()
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.AssetIdentityKeys{}).Record(ctx, c, a, k, now, store.KeyFromNewAsset, uuid.Nil, "", 0)
	}); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var (
			gotObs     uuid.UUID
			gotPayload []byte
		)
		if err := c.QueryRow(ctx, `
			SELECT merge_evidence_observation, merge_evidence_payload
			  FROM asset_identity_keys
			 WHERE tenant_id = $1 AND asset_id = $2 AND valid_to IS NULL`,
			tenant.UUID(), a).Scan(&gotObs, &gotPayload); err != nil {
			return err
		}
		if gotObs != obsID {
			t.Errorf("observation reference = %v, want %v", gotObs, obsID)
		}
		if !strings.Contains(string(gotPayload), "10.10.0.15") {
			t.Errorf("the payload was not copied: %s. It must outlive the observation "+
				"partition, which drops on the 90-day clock.", gotPayload)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestAnAddressAgesOutWhenItStopsBeingObserved.
//
// ============================================================================
// This is what makes `valid_to IS NULL` mean "is here now" rather than "was
// here once".
// ============================================================================
//
// Open closes another ASSET's hold, because two assets on one live address is
// the ambiguous state migration 0031 refuses. It deliberately does not close the
// same asset's other addresses — a multi-homed host holds two, and a scan that
// saw one is not evidence the other is gone.
//
// So an address that simply stops being seen would stay open forever. Ageing is
// the mechanism that closes it, on the same window that gives `ip_window` its
// meaning, and the row is closed rather than deleted because an old finding's
// locator needs the history.
func TestAnAddressAgesOutWhenItStopsBeingObserved(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "age-"+uuid.NewString()[:8])
	a := newAsset(t, db, tenant)
	now := time.Now().UTC()

	ctx := context.Background()
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		// One recent, one stale.
		if err := (store.AssetAddresses{}).Open(ctx, c, a, "10.10.0.31", now); err != nil {
			return err
		}
		return (store.AssetAddresses{}).Open(ctx, c, a, "10.10.0.32", now.Add(-30*24*time.Hour))
	}); err != nil {
		t.Fatal(err)
	}

	var closed int64
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		closed, err = (store.AssetAddresses{}).CloseStale(ctx, c, now.Add(-7*24*time.Hour), now)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if closed != 1 {
		t.Errorf("closed %d intervals, want 1 — the stale one and not the recent one", closed)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var live, total int
		if err := c.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE valid_to IS NULL), count(*)
			  FROM asset_addresses WHERE tenant_id = $1`, tenant.UUID()).
			Scan(&live, &total); err != nil {
			return err
		}
		if live != 1 {
			t.Errorf("%d live intervals, want 1", live)
		}
		if total != 2 {
			t.Errorf("%d rows, want 2 — closing is an UPDATE and the history stays", total)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
