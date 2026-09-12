package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// A key is ADR-091 trust material at an address only once two distinct scans
// have seen it there, on the dialled port, inside the address window (ADR-094,
// migration 0044). SSHHostKeyFingerprintsAt is that trust root; this proves
// what it returns and when:
//
//   - one sighting is nothing, whatever verdict recorded the key — a new-asset
//     key at its own address included, because first sight is not an
//     enrolment (an address interval that ages out makes the next newcomer a
//     "new asset");
//   - a second Record from the SAME scan does not count, however much later
//     its timestamp — the batch cut splits one scan across sweeps, and one
//     scan is one occasion;
//   - a different, later scan at the same address counts: two, and trusted;
//   - a merge counts as a sighting like any verdict — at its own address;
//   - a dual-homed host counts at each address independently, and a sighting
//     elsewhere does not disturb the count here;
//   - a Record with no occasion (no scan, no address, no port) counts nothing;
//   - a key seen twice on another PORT is trust material for that port only;
//   - a sighting older than the address window no longer counts: the two-scan
//     cost is not a one-time payment.
//
// Two sightings narrow the window; they do not verify the key. That is stated
// in the ADR and in the query's comment, and this test does not claim more.
func TestAnObservedKeyIsTrustMaterialOnlyAfterTwoScansAtTheAddress(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "prov-"+uuid.NewString()[:8])
	a := newAsset(t, db, tenant)
	const addr, other = "10.30.0.7", "10.30.0.9"
	first := time.Now().UTC().Add(-time.Hour)

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.AssetAddresses{}).Open(ctx, c, a, addr, first); err != nil {
			return err
		}
		return (store.AssetAddresses{}).Open(ctx, c, a, other, first)
	}); err != nil {
		t.Fatal(err)
	}
	scan1, scan2, scan3 := uuid.New(), uuid.New(), uuid.New()
	record := func(k domain.IdentityKey, at time.Time, from store.KeyProvenance, scan uuid.UUID, where string, port int) {
		t.Helper()
		if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			return recordKey(ctx, c, a, k, at, from, scan, where, port)
		}); err != nil {
			t.Fatal(err)
		}
	}
	trustedAt := func(ip string, port int) []string {
		t.Helper()
		var out []string
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			var err error
			out, err = (store.AssetIdentityKeys{}).SSHHostKeyFingerprintsAt(ctx, c, ip, port, store.SightingWindow)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	seenAt := func(value, ip string, port int) int {
		t.Helper()
		var n int
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			return c.QueryRow(ctx, `SELECT coalesce(max(s.scans_seen), 0) FROM asset_identity_key_sightings s
			   JOIN asset_identity_keys k ON k.tenant_id = s.tenant_id AND k.identity_key_id = s.identity_key_id
			  WHERE s.tenant_id = $1 AND k.key_value = $2 AND s.address = $3::inet AND s.port = $4`,
				c.Tenant().UUID(), value, ip, port).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}
	sshKey := func(value string) domain.IdentityKey {
		return domain.IdentityKey{Type: domain.KeySSHHostKey, Value: value, Source: "22/tcp",
			ObservationID: uuid.New(), Payload: []byte(`{"port":22,"protocol":"tcp"}`)}
	}

	key := sshKey("SHA256:seen")
	record(key, first, store.KeyFromNewAsset, scan1, addr, 22)
	if got := trustedAt(addr, 22); len(got) != 0 {
		t.Fatalf("trust root after one new-asset sighting = %v, want none: first sight is not an enrolment", got)
	}
	// The same scan again, later in time — the other side of a batch cut, or
	// a second address group in the same sweep: one occasion, one sighting.
	record(key, first.Add(5*time.Minute), store.KeyFromAttach, scan1, addr, 22)
	if n := seenAt(key.Value, addr, 22); n != 1 {
		t.Fatalf("sightings after a second Record from the same scan = %d, want 1", n)
	}
	// A different, later scan — here the merge branch, which counts like any
	// verdict — makes two, and the key is trust material at that address.
	record(key, first.Add(10*time.Minute), store.KeyFromMerge, scan2, addr, 22)
	if n := seenAt(key.Value, addr, 22); n != 2 {
		t.Fatalf("sightings after a second scan = %d, want 2", n)
	}
	if got := trustedAt(addr, 22); len(got) != 1 || got[0] != key.Value {
		t.Fatalf("trust root after two scans at the address = %v, want [%s]", got, key.Value)
	}
	// Seen at ANOTHER address the asset holds: that address counts from one,
	// and the first address keeps its two — a dual-homed host is trusted where
	// it has been seen twice, and nowhere else.
	record(key, first.Add(20*time.Minute), store.KeyFromAttach, scan3, other, 22)
	if n := seenAt(key.Value, other, 22); n != 1 {
		t.Fatalf("sightings at the second address after one scan = %d, want 1", n)
	}
	if got := trustedAt(other, 22); len(got) != 0 {
		t.Fatalf("trust root at the second address after one sighting = %v, want none", got)
	}
	if got := trustedAt(addr, 22); len(got) != 1 || got[0] != key.Value {
		t.Fatalf("trust root at the first address after a sighting elsewhere = %v, want [%s] still", got, key.Value)
	}
	// A Record with no occasion — no scan, no address, or no port — counts nothing.
	record(key, first.Add(25*time.Minute), store.KeyFromAttach, uuid.Nil, other, 22)
	record(key, first.Add(26*time.Minute), store.KeyFromAttach, uuid.New(), "", 22)
	record(key, first.Add(27*time.Minute), store.KeyFromAttach, uuid.New(), other, 0)
	if n := seenAt(key.Value, other, 22); n != 1 {
		t.Fatalf("sightings after occasion-less Records = %d, want 1", n)
	}

	// A key seen twice on ANOTHER port — a second sshd on 2222 — is trust
	// material for 2222 and never for 22: the engine dials one service, and
	// a key planted on a second port is not a contradiction the handover rule
	// could see (ADR-094). The sighting, not the key's copied payload, says
	// which port it was seen on.
	otherPort := domain.IdentityKey{Type: domain.KeySSHHostKey, Value: "SHA256:other-port", Source: "2222/tcp",
		ObservationID: uuid.New(), Payload: []byte(`{"port":2222,"protocol":"tcp"}`)}
	record(otherPort, first, store.KeyFromNewAsset, scan1, addr, 2222)
	record(otherPort, first.Add(time.Minute), store.KeyFromAttach, scan2, addr, 2222)
	if got := trustedAt(addr, 2222); len(got) != 1 || got[0] != otherPort.Value {
		t.Fatalf("trust root for port 2222 = %v, want [%s]", got, otherPort.Value)
	}
	if got := trustedAt(addr, 22); len(got) != 1 || got[0] != key.Value {
		t.Fatalf("trust root for port 22 after a port-2222 key = %v, want [%s] only", got, key.Value)
	}

	// Sightings age. Push the port-22 sighting past the address window: the
	// count is still 2 but no longer counts — an attacker who paid the
	// two-scan cost, left, and returned is not trusted on one scan.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE asset_identity_key_sightings s SET last_seen_at = now() - $2::interval
		   FROM asset_identity_keys k
		  WHERE k.tenant_id = s.tenant_id AND k.identity_key_id = s.identity_key_id
		    AND s.tenant_id = $1 AND k.key_value = $3 AND s.address = $4::inet AND s.port = 22`,
			c.Tenant().UUID(), (store.SightingWindow + time.Hour).String(), key.Value, addr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if got := trustedAt(addr, 22); len(got) != 0 {
		t.Fatalf("trust root from a sighting older than the address window = %v, want none", got)
	}
	// ...and the RETURN: one scan after the gap restarts the count at 1
	// rather than making a stale 2 recent again. "At least two ever, and one
	// recently" is what a count without decay implements, and one returning
	// scan satisfies both halves at once.
	record(key, time.Now().UTC(), store.KeyFromAttach, uuid.New(), addr, 22)
	if n := seenAt(key.Value, addr, 22); n != 1 {
		t.Fatalf("sightings after a return past the window = %d, want 1 (restarted)", n)
	}
	if got := trustedAt(addr, 22); len(got) != 0 {
		t.Fatalf("trust root after one returning scan = %v, want none: the two-scan cost is not a one-time payment", got)
	}
	record(key, time.Now().UTC().Add(time.Second), store.KeyFromAttach, uuid.New(), addr, 22)
	if got := trustedAt(addr, 22); len(got) != 1 {
		t.Fatalf("trust root after two returning scans = %v, want the key: the cost is paid again, in full", got)
	}
}
