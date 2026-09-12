package correlate_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// ADR-096 end to end: a host rotates its SSH key (a reimage renews the
// certificate too), keeps its services and its OS, and is scanned twice
// after the rotation. The first post-rotation scan parks (ADR-094); the second
// classifies a rotation and attaches — old key retired, new key recorded at
// ONE sighting, the parked items closed, the parked observations back in the
// sweep. Then the trust root: the rotated key is not trust material until the
// scan after that sees it again.

const (
	rotOld   = "SHA256:oldoldoldoldoldoldoldoldoldoldoldoldoldoldo"
	rotNew   = "SHA256:newnewnewnewnewnewnewnewnewnewnewnewnewnewn"
	rotCertA = "SHA256:certAcertAcertAcertAcertAcertAcertAcertAcer"
	rotCertB = "SHA256:certBcertBcertBcertBcertBcertBcertBcertBcer"
	rotAddr  = "10.10.9.40"
)

func withOS(p map[string]any, hint string) map[string]any {
	p["os"] = map[string]any{"hint": hint, "source": "banner"}
	return p
}

type rotationState struct {
	assets, liveKeys, retired int
	provenance                map[string]string // key value -> provenance, live rows
	pending, rotated          int64
	contested, rotatedEvents  int64
	unresolved                int
	service443                string
	service8080               bool
	lastReason                string
}

func readRotation(t *testing.T, db *store.DB, tenant store.TenantID) rotationState {
	t.Helper()
	var st rotationState
	st.provenance = map[string]string{}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tid).Scan(&st.assets); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FILTER (WHERE valid_to IS NULL), count(*) FILTER (WHERE valid_to IS NOT NULL)
		    FROM asset_identity_keys WHERE tenant_id = $1 AND strength >= 2`, tid).Scan(&st.liveKeys, &st.retired); err != nil {
			return err
		}
		rows, err := c.Query(ctx, `SELECT key_value, provenance::text FROM asset_identity_keys WHERE tenant_id = $1 AND valid_to IS NULL`, tid)
		if err != nil {
			return err
		}
		for rows.Next() {
			var v, p string
			if err := rows.Scan(&v, &p); err != nil {
				rows.Close()
				return err
			}
			st.provenance[v] = p
		}
		rows.Close()
		if err := c.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'pending'), count(*) FILTER (WHERE state = 'rotated')
		    FROM asset_resolution_queue WHERE tenant_id = $1`, tid).Scan(&st.pending, &st.rotated); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FILTER (WHERE action = 'identity.contested'), count(*) FILTER (WHERE action = 'identity.rotated')
		    FROM audit_events WHERE tenant_id = $1`, tid).Scan(&st.contested, &st.rotatedEvents); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FROM observations WHERE tenant_id = $1 AND asset_id IS NULL AND ingest_state = 'accepted'`,
			tid).Scan(&st.unresolved); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT coalesce(max(product),'') FROM services WHERE tenant_id = $1 AND port = 443`, tid).Scan(&st.service443); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM services WHERE tenant_id = $1 AND port = 8080)`, tid).Scan(&st.service8080); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT coalesce((SELECT conflict_reason FROM asset_resolution_queue WHERE tenant_id = $1
		    ORDER BY enqueued_at DESC, resolution_id LIMIT 1), '')`, tid).Scan(&st.lastReason)
	}); err != nil {
		t.Fatal(err)
	}
	return st
}

// rotatedHost seeds the pre-rotation host and one parked post-rotation scan:
// the state every scenario below starts from. Returns the seed and the time
// of the parked scan.
func rotatedHost(t *testing.T, db *store.DB, label string) (*seeded, *correlate.Correlator, time.Time) {
	t.Helper()
	s := seed(t, db, label)
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-8 * time.Hour) // every scan below must be in the past: the sweep reads observed_at < now

	s.observe(t, db, t0, withOS(sshService(rotAddr, 22, rotOld), "Ubuntu"))
	s.observe(t, db, t0, tlsService(rotAddr, 443, rotCertA))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := readRotation(t, db, s.tenant)
	if st.assets != 1 || st.liveKeys != 2 {
		t.Fatalf("before the rotation: %d assets, %d live keys; want 1 and 2", st.assets, st.liveKeys)
	}

	// The reimage: new host key, new certificate, same products, same OS.
	s.nextScan(t, db)
	t1 := t0.Add(time.Hour)
	s.observe(t, db, t1, withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t1, tlsService(rotAddr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st = readRotation(t, db, s.tenant)
	if st.assets != 1 || st.liveKeys != 2 || st.pending == 0 || st.unresolved != 2 || st.contested != 1 || st.rotatedEvents != 0 {
		t.Fatalf("first post-rotation scan: %+v; want parked (ADR-094): one asset, the old keys live, items pending, "+
			"both observations unresolved, one contested event, no rotation", st)
	}
	if _, ok := st.provenance[rotNew]; ok {
		t.Fatal("the rotated key was recorded on the first sighting; a handover records nothing")
	}
	return &s, c, t1
}

func TestAKeyRotationWithContinuityAttachesOnTheSecondScan(t *testing.T) {
	db := testDB(t)
	s, c, t1 := rotatedHost(t, db, "rotation")
	ctx := context.Background()

	// A straggler of the parked scan — a keyless port that did not make the
	// sweep's batch — arrives alone. It must wait with the contradiction, not
	// walk in on the address and write the newcomer's service on the asset.
	s.observe(t, db, t1.Add(time.Minute), map[string]any{
		"address": rotAddr, "port": 8080, "protocol": "tcp", "service": "http", "product": "nginx",
		"method": "banner", "solicited": false, "safety_mode": "safe",
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := readRotation(t, db, s.tenant)
	if st.service8080 || st.unresolved != 3 {
		t.Fatalf("a weak-only straggler at the contested address: service on 8080 written=%t, unresolved=%d; "+
			"want it parked with the contradiction (ADR-096 step 1)", st.service8080, st.unresolved)
	}

	// The second post-rotation scan: same key, same products, same OS.
	s.nextScan(t, db)
	t2 := t1.Add(time.Hour)
	s.observe(t, db, t2, withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t2, tlsService(rotAddr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st = readRotation(t, db, s.tenant)
	if st.assets != 1 || st.rotatedEvents != 1 || st.pending != 0 || st.rotated < 2 {
		t.Fatalf("second post-rotation scan: %+v; want a rotation: one asset, one identity.rotated event, "+
			"no pending item, the parked items closed as rotated", st)
	}
	if st.provenance[rotNew] != "rotation" {
		t.Fatalf("live key provenance %v; want the rotated SSH key recorded as `rotation`", st.provenance)
	}
	if _, old := st.provenance[rotOld]; old || st.retired != 1 {
		t.Fatalf("old key still live=%t, retired=%d; want the old SSH key retired", old, st.retired)
	}
	// The renewed certificate is NOT replaced by the rotation: it stays under
	// the establishment gate, and nothing established corroborates it yet.
	if _, ok := st.provenance[rotCertB]; ok || st.provenance[rotCertA] == "" {
		t.Fatalf("certificates after the rotation: %v; want the held one kept and the renewed one unrecorded", st.provenance)
	}
	// The parked observations are back in the sweep: the next pass attaches
	// them — the straggler's service included. Nothing parked was lost.
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st = readRotation(t, db, s.tenant)
	if st.unresolved != 0 || !st.service8080 || st.assets != 1 {
		t.Fatalf("after the release sweep: unresolved=%d service8080=%t assets=%d; want everything parked attached to the one asset",
			st.unresolved, st.service8080, st.assets)
	}

	// The trust root (ADR-094/096): a rotation-recorded key is NEVER the
	// credentialed trust root on its own, however many scans see it — a
	// takeover of the SSH port alone is indistinguishable from a rotation on
	// banner data. The inventory moved; the trust waits for an operator.
	trust := func() []string {
		t.Helper()
		var fps []string
		if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
			var err error
			fps, err = (store.AssetIdentityKeys{}).SSHHostKeyFingerprintsAt(ctx, c, rotAddr, 22, store.SightingWindow)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return fps
	}
	if fps := trust(); len(fps) != 0 {
		t.Fatalf("trust root after the rotation attached = %v; want empty — a rotation records ONE sighting", fps)
	}
	s.nextScan(t, db)
	s.observe(t, db, t2.Add(time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var scansSeen int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT coalesce(max(sg.scans_seen),0) FROM asset_identity_key_sightings sg
		    JOIN asset_identity_keys k ON k.tenant_id = sg.tenant_id AND k.identity_key_id = sg.identity_key_id
		   WHERE sg.tenant_id = $1 AND k.key_value = $2 AND k.valid_to IS NULL`, c.Tenant().UUID(), rotNew).Scan(&scansSeen)
	}); err != nil {
		t.Fatal(err)
	}
	if fps := trust(); len(fps) != 0 || scansSeen != 2 {
		t.Fatalf("trust root after the next sighting = %v (rotated key seen on %d scans); want EMPTY — a rotation "+
			"never re-roots credentialed trust by itself (ADR-096)", fps, scansSeen)
	}
	// One more scan with the renewed certificate: the rotated key has two
	// sightings here, and it still corroborates NOTHING — a rotation key
	// never establishes, however many scans see it, exactly as it never
	// becomes the trust root. The review measured the alternative: withhold
	// 443 for one scan, establish the rotation key, then swap the victim's
	// certificate for the attacker's through the renewal gate — two moderate
	// keys of trusting provenance on the victim's asset. The held
	// certificate key stays; the service row carries the new certificate
	// regardless; an operator's confirmation (B39) is what unlocks it.
	s.nextScan(t, db)
	s.observe(t, db, t2.Add(2*time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t2.Add(2*time.Hour), tlsService(rotAddr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st = readRotation(t, db, s.tenant)
	if _, b := st.provenance[rotCertB]; b || st.provenance[rotCertA] == "" || st.pending != 0 {
		t.Fatalf("certificates with the rotated key at two sightings: %v (pending=%d); want the held certificate kept, "+
			"the renewal unrecorded — a rotation key corroborates nothing — and nothing pending", st.provenance, st.pending)
	}
	if fps := trust(); len(fps) != 0 {
		t.Fatalf("trust root = %v; want still EMPTY", fps)
	}
}

func TestTheHeldKeyAnsweringDuringAParkedScanIsNotARotation(t *testing.T) {
	db := testDB(t)
	s, c, t1 := rotatedHost(t, db, "rotation-parked-answer")
	ctx := context.Background()

	// The occupant and the newcomer BOTH answer on 22 in one scan (two keys
	// on one port): the group parks, and the occupant's key is parked with
	// it — no sighting row is written by a park. The next newcomer-only scan
	// must still see that the held key answered since its first sighting.
	s.nextScan(t, db)
	s.observe(t, db, t1.Add(30*time.Minute), withOS(sshService(rotAddr, 22, rotOld), "Ubuntu"))
	s.observe(t, db, t1.Add(30*time.Minute), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t1.Add(30*time.Minute), tlsService(rotAddr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := readRotation(t, db, s.tenant)
	if st.rotatedEvents != 0 || st.unresolved != 5 || !strings.Contains(st.lastReason, "two different keys answered on 22/tcp") {
		t.Fatalf("two keys on one port: %+v; want parked, naming two keys on one port", st)
	}
	s.nextScan(t, db)
	s.observe(t, db, t1.Add(time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t1.Add(time.Hour), tlsService(rotAddr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st = readRotation(t, db, s.tenant)
	if st.rotatedEvents != 0 || st.unresolved != 7 || st.provenance[rotOld] == "" {
		t.Fatalf("newcomer after the occupant answered during a parked scan: %+v; want still parked, the occupant's key live", st)
	}
	if !strings.Contains(st.lastReason, "answered since") {
		t.Fatalf("queue reason %q; want the held key's parked sighting counted", st.lastReason)
	}
}

func TestANewKeyLiveOnAnotherAssetIsNotARotation(t *testing.T) {
	db := testDB(t)
	s, c, t1 := rotatedHost(t, db, "rotation-elsewhere")
	ctx := context.Background()

	// The newcomer's key is already live on ANOTHER asset (enrolled at its
	// own address first — ADR-094's shape). A rotation would retire the
	// occupant's key and record nothing; it must queue instead.
	// (SSH only at the other address: with a certificate of its own there too,
	// that asset is contested on its cert before the holder's handover is
	// even classified — queued either way, but the reason is the guard's.)
	s.nextScan(t, db)
	s.observe(t, db, t1.Add(20*time.Minute), sshService("10.10.9.41", 22, rotNew))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s.nextScan(t, db)
	s.observe(t, db, t1.Add(time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t1.Add(time.Hour), tlsService(rotAddr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := readRotation(t, db, s.tenant)
	if st.rotatedEvents != 0 || st.provenance[rotOld] == "" || !strings.Contains(st.lastReason, "live on another asset") {
		t.Fatalf("new key live elsewhere: %+v; want still parked with the reason naming it", st)
	}
}

func TestAProductChangeAtTheAddressIsNotARotation(t *testing.T) {
	db := testDB(t)
	s, c, t1 := rotatedHost(t, db, "rotation-product")
	ctx := context.Background()

	// Same new key, same OS — but 443 now answers as Apache, not nginx.
	s.nextScan(t, db)
	p := tlsService(rotAddr, 443, rotCertB)
	p["product"] = "Apache httpd"
	s.observe(t, db, t1.Add(time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t1.Add(time.Hour), p)
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := readRotation(t, db, s.tenant)
	if st.rotatedEvents != 0 || st.assets != 1 || st.service443 != "nginx" || st.unresolved != 4 {
		t.Fatalf("product changed: %+v; want still parked — no rotation, the occupant's service untouched, four unresolved", st)
	}
	if _, ok := st.provenance[rotNew]; ok {
		t.Fatal("the new key was recorded despite a product contradiction")
	}
	if st.contested != 2 {
		t.Fatalf("contested events = %d; want 2 — one per scan that parked something new", st.contested)
	}
	if !strings.Contains(st.lastReason, "services not continuous") {
		t.Fatalf("queue reason %q; want the failed fact named for the operator", st.lastReason)
	}
}

func TestTheHeldKeyAnsweringSinceTheNewcomerIsNotARotation(t *testing.T) {
	db := testDB(t)
	s, c, t1 := rotatedHost(t, db, "rotation-alternating")
	ctx := context.Background()

	// The OLD key answers again after the newcomer's first sighting: two keys
	// alternating at one address is not a rotation, whatever else agrees.
	s.nextScan(t, db)
	s.observe(t, db, t1.Add(30*time.Minute), withOS(sshService(rotAddr, 22, rotOld), "Ubuntu"))
	s.observe(t, db, t1.Add(30*time.Minute), tlsService(rotAddr, 443, rotCertA))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s.nextScan(t, db)
	s.observe(t, db, t1.Add(time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t1.Add(time.Hour), tlsService(rotAddr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := readRotation(t, db, s.tenant)
	if st.rotatedEvents != 0 || st.assets != 1 || st.unresolved != 4 {
		t.Fatalf("alternating keys: %+v; want still parked — the held key answered since the newcomer appeared", st)
	}
	if st.provenance[rotOld] == "" {
		t.Fatal("the occupant's key is no longer live; a parked newcomer must not retire it")
	}
	if !strings.Contains(st.lastReason, "answered since the new key first appeared") {
		t.Fatalf("queue reason %q; want the failed fact named for the operator", st.lastReason)
	}
}

// A FRESH contest extends the occupant's hold on the address past the window;
// a stale one does not (ADR-096 step 1 §2–3). Measured both ways: unbounded,
// a newcomer became a new asset at the victim's address with a trusted key
// after seven days of waiting; bounded by nothing, a dead occupant's address
// was held for ever and a third host attached to the dead asset on the address
// alone. Time shifts are applied in the database because the sweep reads the
// clock.
func TestAStaleContestAgesOutAndAFreshOneHolds(t *testing.T) {
	db := testDB(t)
	s, c, _ := rotatedHost(t, db, "rotation-ageout")
	c.AgeEvery(0) // the clock is shifted in the database; every sweep must age
	ctx := context.Background()

	shift := func(days int, queueToo bool) {
		t.Helper()
		if err := db.Write(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
			tid := c.Tenant().UUID()
			qs := []string{
				`UPDATE asset_addresses SET valid_from = valid_from - make_interval(days => $2) WHERE tenant_id = $1`,
				`UPDATE asset_identity_key_sightings SET last_seen_at = last_seen_at - make_interval(days => $2) WHERE tenant_id = $1`,
				`UPDATE services SET last_seen = last_seen - make_interval(days => $2) WHERE tenant_id = $1`,
			}
			if queueToo {
				qs = append(qs, `UPDATE asset_resolution_queue SET enqueued_at = enqueued_at - make_interval(days => $2) WHERE tenant_id = $1`)
			}
			for _, q := range qs {
				if _, err := c.Exec(ctx, q, tid, days); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	liveAddrs := func() int {
		t.Helper()
		var n int
		if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
			return c.QueryRow(ctx, `SELECT count(*) FROM asset_addresses WHERE tenant_id = $1 AND valid_to IS NULL`, c.Tenant().UUID()).Scan(&n)
		}); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Eight days with nothing seen at the address, the newcomer's park
	// included: the contest is STALE, and the address ages out like any
	// other silence (ADR-094). The newcomer's return is then a new host at a
	// lapsed address, at ADR-094's price — not this ADR's.
	shift(8, true)
	if err := c.SweepOnce(ctx); err != nil { // CloseStale runs here
		t.Fatal(err)
	}
	if n := liveAddrs(); n != 0 {
		t.Fatalf("live address intervals after 8 days of silence under a stale contest = %d; want 0 — a stale park ages out", n)
	}
	s.nextScan(t, db)
	now := time.Now().UTC()
	s.observe(t, db, now.Add(-3*time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if st := readRotation(t, db, s.tenant); st.assets != 2 || st.rotatedEvents != 0 {
		t.Fatalf("newcomer at a lapsed address: %+v; want a NEW asset (ADR-094's aged-out address), no rotation", st)
	}
	// The stale items still name the occupant, which no longer holds the
	// address and never will again: no transition keyed on it attaching
	// there can reach them, so the ageing pass expires them (measured
	// pending for sixty days with the Health chip amber otherwise).
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var expiredEvents int64
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'identity.items_expired'`,
			c.Tenant().UUID()).Scan(&expiredEvents)
	}); err != nil {
		t.Fatal(err)
	}
	if st := readRotation(t, db, s.tenant); st.pending != 0 || expiredEvents != 1 {
		t.Fatalf("items naming an occupant that lost the address: pending=%d announced=%d; want 0 pending, expired by the ageing pass and announced once",
			st.pending, expiredEvents)
	}
}

func TestALapsedOccupantYieldsTheAddressToTheNewcomer(t *testing.T) {
	db := testDB(t)
	s, c, t1 := rotatedHost(t, db, "rotation-lapsed")
	c.AgeEvery(0)
	ctx := context.Background()

	// The newcomer keeps answering (the contest stays FRESH) while the
	// occupant's key has been silent here for a full window: shift the
	// occupant's interval and sightings back, not the queue.
	if err := db.Write(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		for _, q := range []string{
			`UPDATE asset_addresses SET valid_from = valid_from - interval '8 days' WHERE tenant_id = $1`,
			`UPDATE asset_identity_key_sightings SET last_seen_at = last_seen_at - interval '8 days' WHERE tenant_id = $1`,
			`UPDATE services SET last_seen = last_seen - interval '8 days' WHERE tenant_id = $1`,
		} {
			if _, err := c.Exec(ctx, q, tid); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.SweepOnce(ctx); err != nil { // CloseStale: the FRESH contest keeps the interval
		t.Fatal(err)
	}
	var liveAddrs int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM asset_addresses WHERE tenant_id = $1 AND valid_to IS NULL`, c.Tenant().UUID()).Scan(&liveAddrs)
	}); err != nil {
		t.Fatal(err)
	}
	if liveAddrs != 1 {
		t.Fatalf("live address intervals under a FRESH contest = %d; want 1 — a fresh contest holds the address", liveAddrs)
	}
	// The newcomer's second scan: the occupant has LAPSED — a new asset for
	// the newcomer, the occupant's items expired, its interval closed by the
	// newcomer's Open, its key untouched on its own asset.
	s.nextScan(t, db)
	s.observe(t, db, t1.Add(time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	s.observe(t, db, t1.Add(time.Hour), tlsService(rotAddr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := readRotation(t, db, s.tenant)
	var expiredEvents int64
	var newcomerHolds bool
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'identity.contest_expired'`, tid).Scan(&expiredEvents); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM asset_addresses a JOIN asset_identity_keys k ON k.tenant_id = a.tenant_id AND k.asset_id = a.asset_id
		    WHERE a.tenant_id = $1 AND a.valid_to IS NULL AND k.valid_to IS NULL AND k.key_value = $2)`, tid, rotNew).Scan(&newcomerHolds)
	}); err != nil {
		t.Fatal(err)
	}
	if st.assets != 2 || st.pending != 0 || st.rotatedEvents != 0 || expiredEvents != 1 || !newcomerHolds || st.provenance[rotOld] == "" {
		t.Fatalf("lapsed occupant: %+v expired events=%d newcomer holds the address=%t; want a second asset holding the address, "+
			"the occupant's items expired once, no rotation, the occupant's key still live on its own asset", st, expiredEvents, newcomerHolds)
	}
	// A lapse moves the INVENTORY, never the trust: the newcomer's key is
	// recorded as `lapsed` and the trust root at the address stays empty
	// however many scans see it — the review measured `new_asset` here
	// buying the root with one window of holding tcp/22 against a live host.
	if st.provenance[rotNew] != "lapsed" {
		t.Fatalf("newcomer key provenance = %q; want lapsed", st.provenance[rotNew])
	}
	s.nextScan(t, db)
	s.observe(t, db, t1.Add(2*time.Hour), withOS(sshService(rotAddr, 22, rotNew), "Ubuntu"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var fps []string
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		fps, err = (store.AssetIdentityKeys{}).SSHHostKeyFingerprintsAt(ctx, c, rotAddr, 22, store.SightingWindow)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(fps) != 0 {
		t.Fatalf("trust root at the address after a lapse and a further sighting = %v; want EMPTY", fps)
	}
}

// A key the asset has simply never recorded is not a contradiction, and a
// RENEWED CERTIFICATE is not one either (domain.Resolve carves it out at the
// held address); neither may keep a contest fresh. The review measured an
// SSH-only occupant that enabled TLS after a drive-by park refreshing its own
// freeze for six weeks with its own certificate — and then, with that fixed,
// an occupant whose certificate renewed inside the window doing the same.
func TestAnUnrecordedKeyDoesNotKeepAContestFresh(t *testing.T) {
	contestStaysAnchoredToTheDriveBy(t, false)
}

func TestARenewedCertificateDoesNotKeepAContestFresh(t *testing.T) {
	contestStaysAnchoredToTheDriveBy(t, true)
}

func contestStaysAnchoredToTheDriveBy(t *testing.T, heldCert bool) {
	t.Helper()
	db := testDB(t)
	s := seed(t, db, "contest-fresh")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-8 * time.Hour)
	const addr = "10.10.9.50"

	// The occupant (ssh-only, or ssh with a certificate that will renew),
	// then one drive-by contradiction on 22.
	s.observe(t, db, t0, sshService(addr, 22, rotOld))
	if heldCert {
		s.observe(t, db, t0, tlsService(addr, 443, rotCertA))
	}
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s.nextScan(t, db)
	s.observe(t, db, t0.Add(time.Hour), sshService(addr, 22, rotNew))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// The occupant returns with its own key AND a certificate the asset does
	// not hold — never recorded, or a renewal of the one it holds: parked
	// (the contest is fresh), the cert item parked with it.
	s.nextScan(t, db)
	s.observe(t, db, t0.Add(2*time.Hour), sshService(addr, 22, rotOld))
	s.observe(t, db, t0.Add(2*time.Hour), tlsService(addr, 443, rotCertB))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var last time.Time
	var found bool
	var assetID uuid.UUID
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := c.QueryRow(ctx, `SELECT asset_id FROM assets WHERE tenant_id = $1`, c.Tenant().UUID()).Scan(&assetID); err != nil {
			return err
		}
		var err error
		last, found, err = (store.ResolutionQueue{}).ContradictionLastSeen(ctx, c, addr, assetID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The contradiction's last sighting is the DRIVE-BY's park, not the
	// occupant's later park carrying an unrecorded certificate.
	var driveBy time.Time
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT enqueued_at FROM asset_resolution_queue WHERE tenant_id = $1 AND key_value = $2`,
			c.Tenant().UUID(), rotNew).Scan(&driveBy)
	}); err != nil {
		t.Fatal(err)
	}
	if !found || !last.Equal(driveBy) {
		t.Fatalf("contradiction last seen = %v (found=%t), drive-by parked at %v; the occupant's certificate (held=%t) must not count as a contradiction",
			last, found, driveBy, heldCert)
	}
}

// Two different SSH keys answering on one port in one scan is two hosts, and
// two hosts are never one asset (ADR-007, ADR-096): at an address nothing
// holds the group is queued with NO candidate — unplaceable — and no asset is
// created; at an address an asset holds without an SSH key of its own, the
// group is queued and NOTHING is recorded on it. The review measured the
// alternative: one asset holding both keys, after which its own key was a
// contradiction of its other key on every scan and the park never expired.
func TestTwoKeysOnOnePortAreNeverOneAsset(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "two-keys")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-8 * time.Hour)
	const free, held = "10.10.9.60", "10.10.9.61"

	// A free address: both keys on 22 in one scan.
	s.observe(t, db, t0, sshService(free, 22, rotOld))
	s.observe(t, db, t0, sshService(free, 22, rotNew))
	// A held address: a TLS-only asset first, then both keys on 22.
	s.observe(t, db, t0, tlsService(held, 443, rotCertA))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s.nextScan(t, db)
	s.observe(t, db, t0.Add(time.Hour), sshService(held, 22, rotOld))
	s.observe(t, db, t0.Add(time.Hour), sshService(held, 22, rotNew))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var assets, liveSSH, noCandidate, pendingHeld int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tid).Scan(&assets); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FROM asset_identity_keys WHERE tenant_id = $1 AND key_type = 'ssh_hostkey' AND valid_to IS NULL`, tid).Scan(&liveSSH); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'pending' AND cardinality(candidate_asset_ids) = 0 AND address = $2::inet`, tid, free).Scan(&noCandidate); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'pending' AND address = $2::inet`, tid, held).Scan(&pendingHeld)
	}); err != nil {
		t.Fatal(err)
	}
	if assets != 1 || liveSSH != 0 || noCandidate == 0 || pendingHeld == 0 {
		t.Fatalf("assets=%d live ssh keys=%d unplaceable items at the free address=%d pending at the held address=%d; "+
			"want only the TLS asset, no SSH key recorded anywhere, both groups queued", assets, liveSSH, noCandidate, pendingHeld)
	}

	// The held asset's contest is not FRESH — it holds no SSH key for either
	// value to contradict — so the occupant alone attaches and the items
	// expire, rather than the asset freezing on keys it never held.
	s.nextScan(t, db)
	s.observe(t, db, t0.Add(2*time.Hour), sshService(held, 22, rotOld))
	s.observe(t, db, t0.Add(2*time.Hour), tlsService(held, 443, rotCertA))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var expiredHeld int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx, `SELECT count(*) FROM asset_identity_keys WHERE tenant_id = $1 AND key_type = 'ssh_hostkey' AND valid_to IS NULL`, tid).Scan(&liveSSH); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'pending' AND address = $2::inet`, tid, held).Scan(&pendingHeld); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'expired' AND address = $2::inet`, tid, held).Scan(&expiredHeld)
	}); err != nil {
		t.Fatal(err)
	}
	if liveSSH != 1 || pendingHeld != 0 || expiredHeld == 0 {
		t.Fatalf("occupant alone after the ambiguous scan: live ssh keys=%d pending=%d expired=%d; "+
			"want its key recorded, the ambiguous items expired, nothing pending", liveSSH, pendingHeld, expiredHeld)
	}
}
