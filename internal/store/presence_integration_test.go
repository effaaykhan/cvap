package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// Address presence (ADR-108, ADR-109), end to end through the store.
//
// The estate is seeded to the shape that motivated the ADR rather than an
// abstract one: a population large enough for the range-wide signal to be
// trusted, one anonymous port answering across nearly all of it, and a handful
// of hosts that identify themselves. A test on three addresses would prove the
// plumbing and nothing about the rule.
type seededEstate struct {
	tenant store.TenantID
	scanID uuid.UUID
}

// seedEstate builds `total` addresses in 10.60.0.0/24. Every address answers on
// the anonymous port 5060; `real` of them additionally run an identified SSH.
func seedEstate(t *testing.T, db *store.DB, name string, total, real int) seededEstate {
	t.Helper()
	tenant := newTenant(t, db, name)
	ctx := context.Background()
	var scanID uuid.UUID

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		// A scanned CIDR, so the impossible-address arithmetic has a prefix to
		// work from. Without one that half of the rule silently does nothing —
		// which is worth asserting rather than assuming, see the .0/.255 case.
		var policyID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name) VALUES ($1,$2) RETURNING policy_id`,
			tenant.UUID(), "presence-"+uuid.NewString()[:8]).Scan(&policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `
			INSERT INTO scans (tenant_id, policy_id, scan_type, status)
			VALUES ($1, $2, 'discovery', 'completed') RETURNING scan_id`,
			tenant.UUID(), policyID).Scan(&scanID); err != nil {
			return err
		}
		if _, err := c.Exec(ctx, `
			INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value)
			VALUES ($1, $2, 'cidr', '10.60.0.0/24')`, tenant.UUID(), scanID); err != nil {
			return err
		}
		for i := 0; i < total; i++ {
			a, err := (store.Assets{}).Create(ctx, c, store.Asset{})
			if err != nil {
				return err
			}
			ip := "10.60.0." + itoa(i)
			if err := (store.AssetAddresses{}).Open(ctx, c, a.ID, ip, time.Now().UTC()); err != nil {
				return err
			}
			// The anonymous range-wide port: answers everywhere, never identifies.
			if err := (store.Services{}).Upsert(ctx, c, store.Service{
				AssetID: a.ID, Port: 5060, Protocol: "tcp",
				IdentificationMethod: store.IdentificationDiscovery, SeenOnly: true,
			}, time.Now().UTC()); err != nil {
				return err
			}
			if i < real {
				// A real host: SSH that identified itself with a product.
				if err := (store.Services{}).Upsert(ctx, c, store.Service{
					AssetID: a.ID, Port: 22, Protocol: "tcp",
					Product: "OpenSSH", Version: "9." + itoa(i) + "p1",
					IdentificationMethod: "banner",
				}, time.Now().UTC()); err != nil {
					return err
				}
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("seed estate: %v", err)
	}
	return seededEstate{tenant: tenant, scanID: scanID}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func decide(t *testing.T, db *store.DB, tenant store.TenantID) store.PresenceSummary {
	t.Helper()
	var sum store.PresenceSummary
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		pop, ev, err := (store.Presence{}).GatherEvidence(ctx, c)
		if err != nil {
			return err
		}
		sum, err = (store.Presence{}).RecordVerdicts(ctx, c, pop, ev, domain.DefaultResponderPolicy(), time.Now())
		return err
	}); err != nil {
		t.Fatalf("decide presence: %v", err)
	}
	return sum
}

// The whole point: an estate where one anonymous port answers everywhere and a
// few hosts identify themselves resolves to the few, not the many.
func TestPresenceSuppressesTheRangeResponderAndKeepsTheRealHosts(t *testing.T) {
	db := testDB(t)
	e := seedEstate(t, db, "presence-estate", 64, 5)

	sum := decide(t, db, e.tenant)
	if sum.Present != 5 {
		t.Errorf("present = %d, want 5 (only the hosts that identified themselves)", sum.Present)
	}
	if sum.Responder < 50 {
		t.Errorf("responder = %d, want the bulk of 64: a port answering on every address and never identifying itself is one device, not an estate", sum.Responder)
	}
	if sum.Total() != 64 {
		t.Errorf("total = %d, want 64 — nothing may be lost from the count", sum.Total())
	}

	// Decision 5: nothing is deleted. The suppressed addresses and their services
	// are still there.
	var addrs, svcs int
	if err := db.Read(context.Background(), e.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := c.QueryRow(ctx, `SELECT count(*) FROM asset_addresses WHERE tenant_id=$1 AND valid_to IS NULL`,
			e.tenant.UUID()).Scan(&addrs); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM services WHERE tenant_id=$1`, e.tenant.UUID()).Scan(&svcs)
	}); err != nil {
		t.Fatal(err)
	}
	if addrs != 64 {
		t.Errorf("%d live addresses after suppression, want 64: a suppressed address is labelled, never removed (ADR-108 decision 5)", addrs)
	}
	if svcs < 64 {
		t.Errorf("%d service rows survive, want at least 64: suppression must not destroy the evidence it was based on", svcs)
	}
}

// ADR-109's invariant, at the store layer: no address carrying an identified
// service is ever suppressed, including the ones the prefix arithmetic calls
// impossible. .0 is the network address of the seeded /24 AND runs identified SSH.
func TestAnIdentifiedHostIsNeverSuppressedEvenAtAnImpossibleAddress(t *testing.T) {
	db := testDB(t)
	// real=1 puts the identified host on 10.60.0.0 — the network address.
	e := seedEstate(t, db, "presence-impossible", 32, 1)
	decide(t, db, e.tenant)

	var presence, reason string
	if err := db.Read(context.Background(), e.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `
			SELECT presence, coalesce(presence_reason,'') FROM asset_addresses
			 WHERE tenant_id=$1 AND valid_to IS NULL AND host(ip_address)='10.60.0.0'`,
			e.tenant.UUID()).Scan(&presence, &reason)
	}); err != nil {
		t.Fatal(err)
	}
	if presence == "responder" {
		t.Errorf("10.60.0.0 runs an identified OpenSSH and was SUPPRESSED as a network address (%q). ADR-109: a scan target is an instruction, not a declaration of the subnet mask, and a service that identified itself outranks the arithmetic", reason)
	}
	if presence != "present" {
		t.Errorf("presence = %q, want present", presence)
	}
}

// The arithmetic still decides when nothing identified itself — otherwise the
// four genuine phantoms of the measured estate go back into the inventory.
func TestAnUnidentifiedImpossibleAddressIsStillSuppressed(t *testing.T) {
	db := testDB(t)
	e := seedEstate(t, db, "presence-broadcast", 32, 0) // nothing identifies anywhere
	decide(t, db, e.tenant)

	var presence, reason string
	if err := db.Read(context.Background(), e.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `
			SELECT presence, coalesce(presence_reason,'') FROM asset_addresses
			 WHERE tenant_id=$1 AND valid_to IS NULL AND host(ip_address)='10.60.0.0'`,
			e.tenant.UUID()).Scan(&presence, &reason)
	}); err != nil {
		t.Fatal(err)
	}
	if presence != "responder" {
		t.Errorf("the network address of a scanned /24 with nothing identified reads %q, want responder: with no positive evidence the arithmetic is all there is", presence)
	}
	if reason == "" {
		t.Error("a suppressed address carries no reason; ADR-108 decision 6 requires it be arguable")
	}
}

// Every recorded verdict carries its reason and timestamp — the CHECK in 0052
// enforces the pairing, and this asserts the writer actually supplies it rather
// than relying on the constraint to catch a bug in production.
func TestEveryRecordedVerdictIsExplained(t *testing.T) {
	db := testDB(t)
	e := seedEstate(t, db, "presence-explained", 32, 2)
	decide(t, db, e.tenant)

	var unexplained int
	if err := db.Read(context.Background(), e.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `
			SELECT count(*) FROM asset_addresses
			 WHERE tenant_id=$1 AND valid_to IS NULL
			   AND (presence_reason IS NULL OR btrim(presence_reason)='' OR presence_decided_at IS NULL)`,
			e.tenant.UUID()).Scan(&unexplained)
	}); err != nil {
		t.Fatal(err)
	}
	if unexplained != 0 {
		t.Errorf("%d addresses carry a verdict with no reason or no timestamp; a suppression an operator cannot interrogate is just a smaller wrong number", unexplained)
	}
}

// One tenant's estate must not judge another's. The population is the
// denominator of the ubiquity fraction, so a leak here would not merely expose
// data — it would change the verdict.
func TestPresenceDoesNotCrossTenants(t *testing.T) {
	db := testDB(t)
	a := seedEstate(t, db, "presence-a", 32, 1)
	b := seedEstate(t, db, "presence-b", 32, 32) // every host identified

	decide(t, db, a.tenant)
	sumB := func() store.PresenceSummary {
		var s store.PresenceSummary
		if err := db.Read(context.Background(), b.tenant, func(ctx context.Context, c *store.Conn) error {
			var e error
			s, e = (store.Presence{}).Summary(ctx, c)
			return e
		}); err != nil {
			t.Fatal(err)
		}
		return s
	}()
	if sumB.Present != 0 || sumB.Responder != 0 {
		t.Errorf("tenant B shows verdicts (%+v) after only tenant A was judged", sumB)
	}
	if sumB.Unknown != 32 {
		t.Errorf("tenant B unknown = %d, want 32 — every address unjudged", sumB.Unknown)
	}
	// And B's own run sees only B.
	if got := decide(t, db, b.tenant); got.Present != 32 {
		t.Errorf("tenant B present = %d, want 32; its own population is all identified", got.Present)
	}
}
