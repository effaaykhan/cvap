package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// mutate:subject internal/store/identity_queue.go
// mutate:test    ./internal/control/api/ -run TestConfirmReStamps|TestAnAmbiguousGroup|TestTheQueueLists|TestAChoiceBinds|TestDifferentHostRefuses
//
// mutate:case    confirm blesses a key the operator did not name (ADR-097)
// mutate:old     		if !have[n] {
// mutate:new     		if false {
//
// mutate:case    an operator's choice keeps the other key of the service instead of discarding it (ADR-097)
// mutate:old     			if it.KeyType == ch.Type && it.Source == ch.Source && it.KeyValue != ch.Value {
// mutate:new     			if false {
//
// mutate:case    a choice binds to a value wherever it is parked, not to the named service (ADR-097)
// mutate:old     			if it.KeyType == ch.Type && it.Source == ch.Source && it.KeyValue == ch.Value {
// mutate:new     			if it.KeyType == ch.Type && it.KeyValue == ch.Value {
//
// mutate:case    different host creates a keyless asset that takes the address (ADR-097)
// mutate:old     	if len(res.KeysRecorded) == 0 {
// mutate:new     	if false {

// The operator's verbs on the identity queue (ADR-097, B39), end to end:
// correlation parks a handover, the operator adjudicates it through the API,
// and the next sweep does what the decision said. Asserted on the database —
// the keys, the items, the audit row naming the operator, the trust root —
// not on the status code, which is the same for every outcome.

const (
	qOld  = "SHA256:qoldqoldqoldqoldqoldqoldqoldqoldqoldqoldqol"
	qNew  = "SHA256:qnewqnewqnewqnewqnewqnewqnewqnewqnewqnewqne"
	qAddr = "10.30.7.10"
)

type queueFixture struct {
	*fixture
	c            *correlate.Correlator
	spID         uuid.UUID
	subID        string
	taskID       uuid.UUID
	cookies      []*http.Cookie
	csrf         string
	scanAgain    func()
	observeAgain func(at time.Time, fp string)
}

// seedQueueScan gives the fixture's scan point a scan, a job and a task, and
// an accepted submission for observations to hang from — the occasion a
// sighting is counted on (ADR-094).
func seedQueueScan(ctx context.Context, c *store.Conn, spID uuid.UUID, policyID uuid.UUID, subID string) (uuid.UUID, error) {
	tenant := c.Tenant().UUID()
	var scanID, jobID, taskID uuid.UUID
	if err := c.QueryRow(ctx, `INSERT INTO scans (tenant_id, policy_id, scan_type, status) VALUES ($1, $2, 'discovery', 'running') RETURNING scan_id`,
		tenant, policyID).Scan(&scanID); err != nil {
		return uuid.Nil, err
	}
	if err := c.QueryRow(ctx, `INSERT INTO scan_jobs (tenant_id, scan_id, scan_point_id, engine) VALUES ($1, $2, $3, 'fingerprint') RETURNING job_id`,
		tenant, scanID, spID).Scan(&jobID); err != nil {
		return uuid.Nil, err
	}
	if err := c.QueryRow(ctx, `INSERT INTO scan_tasks (tenant_id, job_id, task_target) VALUES ($1, $2, $3) RETURNING task_id`,
		tenant, jobID, qAddr).Scan(&taskID); err != nil {
		return uuid.Nil, err
	}
	_, err := (store.Submissions{}).Begin(ctx, c, subID, jobID, 1, store.SubmitAccepted, false, "")
	return taskID, err
}

// parkedHandover seeds an ssh-only occupant at qAddr, then a contradicting key
// there, and sweeps: one asset, one contested address, items pending.
func parkedHandover(t *testing.T) (*queueFixture, uuid.UUID) {
	t.Helper()
	f := newFixture(t, `{"asset.read": true, "identity.resolve": true, "scan.read": true}`)
	q := &queueFixture{fixture: f, c: correlate.New(f.db, slog.New(slog.NewTextHandler(io.Discard, nil)))}
	q.cookies, q.csrf = f.login(t)
	q.spID = f.seedScanPoint(t)
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-3 * time.Hour)

	scan := func() {
		q.subID = "sub-" + uuid.NewString()
		if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
			var err error
			q.taskID, err = seedQueueScan(ctx, c, q.spID, f.policyID, q.subID)
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	observe := func(at time.Time, fp string) {
		payload, _ := json.Marshal(map[string]any{
			"address": qAddr, "port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.6",
			"method": "banner", "solicited": true, "safety_mode": "intrusive",
			"ssh": map[string]any{"host_key_type": "ssh-ed25519", "fingerprint": fp},
		})
		conf := 0.95
		if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
			return (store.Observations{}).Insert(ctx, c, store.Observation{
				ID: uuid.New(), SubmissionID: q.subID, TaskID: q.taskID, ScanPointID: q.spID, ZoneID: f.zoneID,
				Type: store.ObsService, Payload: payload, Confidence: &conf, ObservedAt: at,
			}, store.IngestAccepted)
		}); err != nil {
			t.Fatal(err)
		}
	}
	scan()
	observe(t0, qOld)
	if err := q.c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	scan()
	observe(t0.Add(time.Hour), qNew)
	if err := q.c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var asset uuid.UUID
	var pending int
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := c.QueryRow(ctx, `SELECT asset_id FROM assets WHERE tenant_id = $1`, c.Tenant().UUID()).Scan(&asset); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'pending'`, c.Tenant().UUID()).Scan(&pending)
	}); err != nil {
		t.Fatal(err)
	}
	if pending == 0 {
		t.Fatal("the handover did not park; nothing to adjudicate")
	}
	q.scanAgain = scan
	q.observeAgain = observe
	return q, asset
}

func (q *queueFixture) state(t *testing.T) (liveKeys map[string]string, pending int, states map[string]int, events map[string]int) {
	t.Helper()
	liveKeys, states, events = map[string]string{}, map[string]int{}, map[string]int{}
	if err := q.db.Read(context.Background(), q.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
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
			liveKeys[v] = p
		}
		rows.Close()
		rows, err = c.Query(ctx, `SELECT state::text, count(*) FROM asset_resolution_queue WHERE tenant_id = $1 GROUP BY 1`, tid)
		if err != nil {
			return err
		}
		for rows.Next() {
			var s string
			var n int
			if err := rows.Scan(&s, &n); err != nil {
				rows.Close()
				return err
			}
			states[s] = n
		}
		rows.Close()
		pending = states["pending"]
		rows, err = c.Query(ctx, `SELECT action, count(*) FROM audit_events WHERE tenant_id = $1 AND action LIKE 'identity.%' GROUP BY 1`, tid)
		if err != nil {
			return err
		}
		for rows.Next() {
			var a string
			var n int
			if err := rows.Scan(&a, &n); err != nil {
				rows.Close()
				return err
			}
			events[a] = n
		}
		rows.Close()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return
}

// seenThrough is the listing's last_seen for the contested address, as the
// console would send it back.
func (q *queueFixture) seenThrough(t *testing.T) string {
	t.Helper()
	w := q.do(t, http.MethodGet, "/v1/identity/queue", nil, q.cookies, q.csrf)
	var list api.IdentityQueueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Groups) == 0 {
		t.Fatal("nothing listed")
	}
	return list.Groups[0].LastSeen
}

func (q *queueFixture) trustAt(t *testing.T) []string {
	t.Helper()
	var fps []string
	if err := q.db.Read(context.Background(), q.tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		fps, err = (store.AssetIdentityKeys{}).SSHHostKeyFingerprintsAt(ctx, c, qAddr, 22, store.SightingWindow)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return fps
}

func TestTheQueueListsAParkedHandoverAndSameHostMergesIt(t *testing.T) {
	q, asset := parkedHandover(t)
	ctx := context.Background()

	w := q.do(t, http.MethodGet, "/v1/identity/queue", nil, q.cookies, q.csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("queue: %d %s", w.Code, w.Body.String())
	}
	var list api.IdentityQueueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Groups) != 1 || list.Groups[0].Address != qAddr || len(list.Groups[0].Candidates) != 1 ||
		list.Groups[0].Candidates[0] != asset.String() || len(list.Groups[0].Items) == 0 {
		t.Fatalf("queue = %+v; want one contested address naming the occupant", list.Groups)
	}

	// Same host: the parked key is the asset's. The held key retires, the
	// parked one is recorded as confirmed, the items close as merged naming
	// the operator, and the next sweep attaches the parked observation.
	w = q.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "same_host", AssetID: asset.String(), Reason: "reimaged on Tuesday", SeenThrough: list.Groups[0].LastSeen,
	}, q.cookies, q.csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("resolve: %d %s", w.Code, w.Body.String())
	}
	keys, pending, states, events := q.state(t)
	if pending != 0 || states["merged"] == 0 || keys[qNew] != "confirmed" || keys[qOld] != "" || events["identity.resolved"] != 1 {
		t.Fatalf("after same_host: pending=%d states=%v keys=%v events=%v; want the new key confirmed, the old retired, items merged, one identity.resolved",
			pending, states, keys, events)
	}
	var by *uuid.UUID
	if err := q.db.Read(ctx, q.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT actor_id FROM audit_events WHERE tenant_id = $1 AND action = 'identity.resolved'`, c.Tenant().UUID()).Scan(&by)
	}); err != nil {
		t.Fatal(err)
	}
	if by == nil {
		t.Fatal("identity.resolved names no operator")
	}
	if err := q.c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var assets, unresolved int
	if err := q.db.Read(ctx, q.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tid).Scan(&assets); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM observations WHERE tenant_id = $1 AND asset_id IS NULL AND ingest_state = 'accepted'`, tid).Scan(&unresolved)
	}); err != nil {
		t.Fatal(err)
	}
	if assets != 1 || unresolved != 0 {
		t.Fatalf("after the release sweep: assets=%d unresolved=%d; want the parked observation attached to the one asset", assets, unresolved)
	}
	// Confirmed is trust material on ADR-094's terms: one sighting so far.
	if fps := q.trustAt(t); len(fps) != 0 {
		t.Fatalf("trust root right after the merge = %v; want empty until the next sighting", fps)
	}
	q.scanAgain()
	q.observeAgain(time.Now().UTC().Add(-time.Hour), qNew)
	if err := q.c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if fps := q.trustAt(t); len(fps) != 1 || fps[0] != qNew {
		t.Fatalf("trust root after the next sighting = %v; want the confirmed key", fps)
	}
}

// The listing's keys and candidates are aggregated over EVERY item at the
// address, not the fifty newest: the review measured sixty-one items whose
// oldest carried the attacker's key and the only candidate — the screen
// showed neither, the verb recorded the unseen key as confirmed, and the
// only button offered was "different host".
func TestTheListingAggregatesKeysAndCandidatesOverEveryItem(t *testing.T) {
	q, asset := parkedHandover(t)
	ctx := context.Background()
	// Sixty keyless items parked AFTER the keyed one, naming nobody.
	if err := q.db.Write(ctx, q.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		for i := 0; i < 60; i++ {
			payload, _ := json.Marshal(map[string]any{"address": qAddr, "port": 8000 + i, "service": "http"})
			if _, err := c.Exec(ctx, `INSERT INTO asset_resolution_queue (tenant_id, observed_payload, key_type, key_value, candidate_asset_ids, conflict_reason, address, enqueued_at)
			    VALUES ($1, $2, 'ip_window', $3::text, '{}', 'straggler', $5::inet, now() + make_interval(secs => $4))`, tid, payload, qAddr, i+1, qAddr); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := q.do(t, http.MethodGet, "/v1/identity/queue", nil, q.cookies, q.csrf)
	var list api.IdentityQueueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Groups) != 1 {
		t.Fatalf("groups = %d; want 1", len(list.Groups))
	}
	g := list.Groups[0]
	keyed := 0
	for _, it := range g.Items {
		if it.KeyType != "ip_window" {
			keyed++
		}
	}
	if len(g.Items) != 50 || g.ItemsTotal != 61 || keyed != 0 {
		t.Fatalf("items shown=%d total=%d keyed shown=%d; the fixture must push the keyed item out of the page", len(g.Items), g.ItemsTotal, keyed)
	}
	if len(g.Keys) != 1 || g.Keys[0].KeyValue != qNew || len(g.Candidates) != 1 || g.Candidates[0] != asset.String() || len(g.Held) != 1 || g.Held[0].KeyValue != qOld {
		t.Fatalf("keys=%+v candidates=%v held=%+v; want the parked key, the holder and its held key, all from beyond the rendered page", g.Keys, g.Candidates, g.Held)
	}
}

func TestDifferentHostGivesTheParkedGroupItsOwnAsset(t *testing.T) {
	q, asset := parkedHandover(t)
	ctx := context.Background()

	w := q.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "different_host", Reason: "lease reused; the old box is decommissioned", SeenThrough: q.seenThrough(t),
	}, q.cookies, q.csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("resolve: %d %s", w.Code, w.Body.String())
	}
	var res api.ResolveIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	keys, pending, states, _ := q.state(t)
	if pending != 0 || states["new_asset"] == 0 || keys[qNew] != "confirmed" || keys[qOld] == "" || res.AssetID == asset.String() {
		t.Fatalf("after different_host: pending=%d states=%v keys=%v new=%s; want a second asset holding the new key, the occupant's key untouched",
			pending, states, keys, res.AssetID)
	}
	var holder uuid.UUID
	if err := q.db.Read(ctx, q.tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		holder, _, err = (store.AssetAddresses{}).LiveHolder(ctx, c, qAddr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if holder.String() != res.AssetID {
		t.Fatalf("address holder = %s; want the new asset %s", holder, res.AssetID)
	}
	if err := q.c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var assets, unresolved int
	if err := q.db.Read(ctx, q.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tid).Scan(&assets); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM observations WHERE tenant_id = $1 AND asset_id IS NULL AND ingest_state = 'accepted'`, tid).Scan(&unresolved)
	}); err != nil {
		t.Fatal(err)
	}
	if assets != 2 || unresolved != 0 {
		t.Fatalf("after the release sweep: assets=%d unresolved=%d; want two assets and the parked observation attached to the new one", assets, unresolved)
	}
}

func TestConfirmReStampsARotatedKeyAndNothingElse(t *testing.T) {
	f := newFixture(t, `{"asset.read": true, "identity.resolve": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()
	var asset uuid.UUID
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{})
		if err != nil {
			return err
		}
		asset = a.ID
		_, err = c.Exec(ctx, `INSERT INTO asset_identity_keys (tenant_id, asset_id, key_type, key_value, strength, valid_from, provenance)
		    VALUES ($1, $2, 'ssh_hostkey', $3, 2, now(), 'rotation'), ($1, $2, 'ssh_hostkey', $4, 2, now(), 'attach')`,
			c.Tenant().UUID(), asset, qNew, qOld)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// The asset page says which key waits for a word.
	w := f.do(t, http.MethodGet, "/v1/assets/"+asset.String(), nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("asset: %d %s", w.Code, w.Body.String())
	}
	var a api.AssetResponse
	if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
		t.Fatal(err)
	}
	waiting := 0
	for _, k := range a.IdentityKeys {
		if k.Provenance == "rotation" && !k.TrustMaterial {
			waiting++
		}
	}
	if len(a.IdentityKeys) != 2 || waiting != 1 {
		t.Fatalf("identity keys on the asset page = %+v; want two, one waiting for confirmation", a.IdentityKeys)
	}

	// Naming a key that is not rotated or lapsed confirms nothing.
	w = f.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/identity/confirm", api.ConfirmIdentityRequest{Keys: []string{"ssh_hostkey " + qOld}, Reason: "wrong key"}, cookies, csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("confirm naming a key that is not rotated: %d; want 409", w.Code)
	}
	// A second rotated key the operator does NOT name stays excluded: the
	// rotated set is one an attacker helps compose, and blessing all of it
	// for one genuine rotation was measured handing a planted key on
	// another port the credentialed dial.
	const planted = "SHA256:plantedplantedplantedplantedplantedplanted"
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `INSERT INTO asset_identity_keys (tenant_id, asset_id, key_type, key_value, strength, valid_from, provenance, merge_evidence_payload, merge_evidence_observation)
		    VALUES ($1, $2, 'ssh_hostkey', $3, 2, now(), 'rotation', '{"port":2222,"protocol":"tcp"}', gen_random_uuid())`, c.Tenant().UUID(), asset, planted)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w = f.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/identity/confirm", api.ConfirmIdentityRequest{Keys: []string{"ssh_hostkey " + qNew}, Reason: "I rotated it"}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm: %d %s", w.Code, w.Body.String())
	}
	var cres api.ConfirmIdentityResponse
	if err := json.Unmarshal(w.Body.Bytes(), &cres); err != nil {
		t.Fatal(err)
	}
	if len(cres.KeysConfirmed) != 1 || len(cres.KeysRemaining) != 1 || cres.KeysRemaining[0] != "ssh_hostkey "+planted {
		t.Fatalf("confirm response = %+v; want one confirmed and the unnamed planted key remaining", cres)
	}
	var prov map[string]string
	var events int
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		prov = map[string]string{}
		rows, err := c.Query(ctx, `SELECT key_value, provenance::text FROM asset_identity_keys WHERE tenant_id = $1`, tid)
		if err != nil {
			return err
		}
		for rows.Next() {
			var v, p string
			if err := rows.Scan(&v, &p); err != nil {
				rows.Close()
				return err
			}
			prov[v] = p
		}
		rows.Close()
		return c.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'identity.confirmed' AND actor_id IS NOT NULL`, tid).Scan(&events)
	}); err != nil {
		t.Fatal(err)
	}
	if prov[qNew] != "confirmed" || prov[qOld] != "attach" || prov[planted] != "rotation" || events != 1 {
		t.Fatalf("after confirm: provenance=%v events=%d; want only the named key re-stamped, the unnamed one still rotation, one identity.confirmed naming the operator", prov, events)
	}
	// Clean up the planted key so the "nothing left" case below is real.
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `UPDATE asset_identity_keys SET valid_to = now() WHERE tenant_id = $1 AND key_value = $2`, c.Tenant().UUID(), planted)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// Nothing left to confirm: a conflict, not a silent success.
	w = f.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/identity/confirm", api.ConfirmIdentityRequest{Keys: []string{"ssh_hostkey " + qNew}, Reason: "again"}, cookies, csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("second confirm: %d; want 409", w.Code)
	}
	// The page's predicate IS the wire's: give the confirmed key two sightings
	// at an address the asset holds, and the page's trust_material must agree
	// with SSHHostKeyFingerprintsAt in every state — held, then lost.
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := (store.AssetAddresses{}).Open(ctx, c, asset, qAddr, time.Now().UTC()); err != nil {
			return err
		}
		_, err := c.Exec(ctx, `INSERT INTO asset_identity_key_sightings (tenant_id, identity_key_id, address, port, scans_seen, last_seen_scan, last_seen_at)
		    SELECT $1, identity_key_id, $2::inet, 22, 2, gen_random_uuid(), now() FROM asset_identity_keys WHERE tenant_id = $1 AND asset_id = $3 AND key_value = $4`,
			tid, qAddr, asset, qNew)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	pageTrust := func() (trusted []string) {
		t.Helper()
		w := f.do(t, http.MethodGet, "/v1/assets/"+asset.String(), nil, cookies, csrf)
		var a api.AssetResponse
		if err := json.Unmarshal(w.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		for _, k := range a.IdentityKeys {
			if k.TrustMaterial {
				trusted = append(trusted, k.Fingerprint)
			}
		}
		return
	}
	wireTrust := func() []string {
		t.Helper()
		var fps []string
		if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
			var err error
			fps, err = (store.AssetIdentityKeys{}).SSHHostKeyFingerprintsAt(ctx, c, qAddr, 22, store.SightingWindow)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return fps
	}
	if p, wire := pageTrust(), wireTrust(); len(p) != 1 || len(wire) != 1 || p[0] != wire[0] || p[0] != qNew {
		t.Fatalf("held address: page trusts %v, wire trusts %v; want both exactly the confirmed key", p, wire)
	}
	// The address moves to another asset (an operator's "different host"
	// does exactly this): the wire returns nothing, and so must the page.
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		b, err := (store.Assets{}).Create(ctx, c, store.Asset{})
		if err != nil {
			return err
		}
		return (store.AssetAddresses{}).Open(ctx, c, b.ID, qAddr, time.Now().UTC())
	}); err != nil {
		t.Fatal(err)
	}
	if p, wire := pageTrust(), wireTrust(); len(p) != 0 || len(wire) != 0 {
		t.Fatalf("address lost: page trusts %v, wire trusts %v; want neither — a sighting at an address the asset lost is history", p, wire)
	}

	// Without the permission, no verb.
	g := newFixture(t, `{"asset.read": true}`)
	gc, gcsrf := g.login(t)
	w = g.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/identity/confirm", api.ConfirmIdentityRequest{Keys: []string{"ssh_hostkey " + qNew}, Reason: "x"}, gc, gcsrf)
	if w.Code != http.StatusForbidden {
		t.Fatalf("confirm without identity.resolve: %d; want 403", w.Code)
	}
}

// Two different keys from one service parked at one address (two hosts
// answered on one port, ADR-096): neither verb can say which is the host, and
// neither writes anything — a clear refusal, not a unique-index conflict.
func TestAnAmbiguousGroupIsRefusedByBothVerbs(t *testing.T) {
	f := newFixture(t, `{"asset.read": true, "identity.resolve": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		for _, fp := range []string{qOld, qNew} {
			payload, _ := json.Marshal(map[string]any{"address": qAddr, "port": 22, "protocol": "tcp", "service": "ssh",
				"ssh": map[string]any{"fingerprint": fp}})
			if _, err := c.Exec(ctx, `INSERT INTO asset_resolution_queue (tenant_id, observed_payload, key_type, key_value, candidate_asset_ids, conflict_reason, address, source)
			    VALUES ($1, $2, 'ssh_hostkey', $3, '{}', 'two keys on one port', $4::inet, '22/tcp')`, tid, payload, fp, qAddr); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "different_host", Reason: "guess", SeenThrough: time.Now().UTC().Format(time.RFC3339Nano),
	}, cookies, csrf)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("different_host on an ambiguous group: %d %s; want 422", w.Code, w.Body.String())
	}
	var assets, pending int
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, tid).Scan(&assets); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'pending'`, tid).Scan(&pending)
	}); err != nil {
		t.Fatal(err)
	}
	if assets != 0 || pending != 2 {
		t.Fatalf("after the refusal: assets=%d pending=%d; want nothing written", assets, pending)
	}
	// The listing names the ambiguous service over ALL items, so the console
	// can always offer the choice.
	w = f.do(t, http.MethodGet, "/v1/identity/queue", nil, cookies, csrf)
	var list api.IdentityQueueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Groups) != 1 || len(list.Groups[0].Ambiguous) != 1 || list.Groups[0].Ambiguous[0].Source != "22/tcp" || len(list.Groups[0].Ambiguous[0].Values) != 2 {
		t.Fatalf("ambiguous services in the listing = %+v; want 22/tcp with two values", list.Groups)
	}
	// Naming the host resolves it: the chosen key goes on the new asset, the
	// other closes as discarded, with the choice in the audit row.
	w = f.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "different_host", KeyChoices: []api.KeyChoiceRequest{{KeyType: "ssh_hostkey", Source: "22/tcp", KeyValue: qNew}}, Reason: "the old key is the decommissioned box", SeenThrough: time.Now().UTC().Format(time.RFC3339Nano),
	}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("different_host with a chosen key: %d %s", w.Code, w.Body.String())
	}
	var live map[string]string
	var discarded, newAsset int
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		live = map[string]string{}
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
			live[v] = p
		}
		rows.Close()
		if err := c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'discarded'`, tid).Scan(&discarded); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'new_asset'`, tid).Scan(&newAsset)
	}); err != nil {
		t.Fatal(err)
	}
	if live[qNew] != "confirmed" || live[qOld] != "" || discarded != 1 || newAsset != 1 {
		t.Fatalf("after choosing: live=%v discarded=%d new_asset=%d; want only the chosen key recorded, the other discarded", live, discarded, newAsset)
	}
}

// One public fingerprint parked on two ports: the genuine key on 2222 and on
// 22, an attacker's key on 22 too. The operator's choice must bind to the
// SERVICE it names — a value alone was measured binding to the first item
// carrying it (the 2222 one), refusing the genuine answer and accepting only
// the attacker's key for port 22.
func TestAChoiceBindsToItsServiceNotToTheFirstItemWithThatValue(t *testing.T) {
	f := newFixture(t, `{"asset.read": true, "identity.resolve": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()
	var asset uuid.UUID
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{})
		if err != nil {
			return err
		}
		asset = a.ID
		if err := (store.AssetAddresses{}).Open(ctx, c, asset, qAddr, time.Now().UTC()); err != nil {
			return err
		}
		tid := c.Tenant().UUID()
		for _, k := range []struct {
			port int
			fp   string
		}{{2222, qOld}, {22, qOld}, {22, qNew}} {
			payload, _ := json.Marshal(map[string]any{"address": qAddr, "port": k.port, "protocol": "tcp", "service": "ssh",
				"ssh": map[string]any{"fingerprint": k.fp}})
			if _, err := c.Exec(ctx, `INSERT INTO asset_resolution_queue (tenant_id, observed_payload, key_type, key_value, candidate_asset_ids, conflict_reason, address, source)
			    VALUES ($1, $2, 'ssh_hostkey', $3, ARRAY[$4::uuid], 'two keys on 22', $5::inet, $6)`, tid, payload, k.fp, asset, qAddr, fmt.Sprintf("%d/tcp", k.port)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodGet, "/v1/identity/queue", nil, cookies, csrf)
	var list api.IdentityQueueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Groups) != 1 || len(list.Groups[0].Ambiguous) != 1 || list.Groups[0].Ambiguous[0].Source != "22/tcp" {
		t.Fatalf("ambiguous = %+v; want exactly 22/tcp", list.Groups)
	}
	// A choice naming a service where that value is NOT parked is refused as
	// such — not as "still ambiguous": the value is parked on 22, not 2222.
	w = f.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "same_host", AssetID: asset.String(),
		KeyChoices: []api.KeyChoiceRequest{{KeyType: "ssh_hostkey", Source: "2222/tcp", KeyValue: qNew}}, Reason: "wrong service", SeenThrough: time.Now().UTC().Format(time.RFC3339Nano),
	}, cookies, csrf)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "not parked on that service") {
		t.Fatalf("choice naming a service the value is not parked on: %d %s; want 422 saying so", w.Code, w.Body.String())
	}
	w = f.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "same_host", AssetID: asset.String(),
		KeyChoices: []api.KeyChoiceRequest{{KeyType: "ssh_hostkey", Source: "22/tcp", KeyValue: qOld}}, Reason: "the genuine key answers on both ports", SeenThrough: time.Now().UTC().Format(time.RFC3339Nano),
	}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("choosing the genuine key for 22/tcp: %d %s; the operator's correct answer must be accepted", w.Code, w.Body.String())
	}
	var live map[string]string
	var discarded int
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		live = map[string]string{}
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
			live[v] = p
		}
		rows.Close()
		return c.QueryRow(ctx, `SELECT count(*) FROM asset_resolution_queue WHERE tenant_id = $1 AND state = 'discarded' AND key_value = $2`, tid, qNew).Scan(&discarded)
	}); err != nil {
		t.Fatal(err)
	}
	if live[qOld] != "confirmed" || live[qNew] != "" || discarded != 1 {
		t.Fatalf("after the choice: live=%v attacker item discarded=%d; want the genuine key confirmed and the attacker's discarded", live, discarded)
	}
}

// A key parked AFTER the operator's render is not theirs to decide: it stays
// pending, the address is listed again, and nothing about it is recorded.
// The review measured a screen showing no keys at all confirming a key that
// landed between the render and the click.
func TestAKeyParkedAfterTheRenderStaysPending(t *testing.T) {
	q, asset := parkedHandover(t)
	ctx := context.Background()
	seen := q.seenThrough(t)
	// Late park: a second key on another service, one second after the render.
	const late = "SHA256:latelatelatelatelatelatelatelatelatelatelate"
	if err := q.db.Write(ctx, q.tenant, func(ctx context.Context, c *store.Conn) error {
		payload, _ := json.Marshal(map[string]any{"address": qAddr, "port": 2222, "protocol": "tcp", "service": "ssh",
			"ssh": map[string]any{"fingerprint": late}})
		_, err := c.Exec(ctx, `INSERT INTO asset_resolution_queue (tenant_id, observed_payload, key_type, key_value, candidate_asset_ids, conflict_reason, address, source, enqueued_at)
		    VALUES ($1, $2, 'ssh_hostkey', $3, ARRAY[$4::uuid], 'late', $5::inet, '2222/tcp', $6::timestamptz + interval '1 second')`,
			c.Tenant().UUID(), payload, late, asset, qAddr, seen)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w := q.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "same_host", AssetID: asset.String(), Reason: "reimaged", SeenThrough: seen,
	}, q.cookies, q.csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("same_host: %d %s", w.Code, w.Body.String())
	}
	keys, pending, _, _ := q.state(t)
	if keys[qNew] != "confirmed" || keys[late] != "" || pending != 1 {
		t.Fatalf("after a decision rendered before the late park: keys=%v pending=%d; want only the seen key recorded and the late item still pending", keys, pending)
	}
}

// A decision covers exactly the keys the listing renders: an address with
// more distinct parked keys than a page shows is refused (the caps that let a
// verb act beyond the page were each measured recording an unseen key as
// confirmed), and the exit is discard — which records and trusts nothing.
func TestTooManyKeysIsRefusedAndDiscardIsTheExit(t *testing.T) {
	f := newFixture(t, `{"asset.read": true, "identity.resolve": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()
	var asset uuid.UUID
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{})
		if err != nil {
			return err
		}
		asset = a.ID
		if err := (store.AssetAddresses{}).Open(ctx, c, asset, qAddr, time.Now().UTC()); err != nil {
			return err
		}
		tid := c.Tenant().UUID()
		for i := 0; i <= store.MaxKeysPerGroup; i++ { // one more key than a page renders
			payload, _ := json.Marshal(map[string]any{"address": qAddr, "port": 2000 + i, "protocol": "tcp", "service": "ssh",
				"ssh": map[string]any{"fingerprint": fmt.Sprintf("SHA256:key%04d", i)}})
			if _, err := c.Exec(ctx, `INSERT INTO asset_resolution_queue (tenant_id, observed_payload, key_type, key_value, candidate_asset_ids, conflict_reason, address, source)
			    VALUES ($1, $2, 'ssh_hostkey', $3, ARRAY[$4::uuid], 'flood', $5::inet, $6)`, tid, payload, fmt.Sprintf("SHA256:key%04d", i), asset, qAddr, fmt.Sprintf("%d/tcp", 2000+i)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := f.do(t, http.MethodGet, "/v1/identity/queue", nil, cookies, csrf)
	var list api.IdentityQueueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	g := list.Groups[0]
	if len(g.Keys) != store.MaxKeysPerGroup || g.KeysTotal != store.MaxKeysPerGroup+1 {
		t.Fatalf("keys shown=%d total=%d; the fixture must exceed the page by one", len(g.Keys), g.KeysTotal)
	}
	future := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	w = f.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "same_host", AssetID: asset.String(), Reason: "all mine", SeenThrough: future,
	}, cookies, csrf)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("future seen_through: %d; want 400 — nothing was rendered then", w.Code)
	}
	// The zero time parses, is not in the future, and would mean no bound.
	w = f.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "discard", Reason: "unbounded", SeenThrough: "0001-01-01T00:00:00Z",
	}, cookies, csrf)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("zero seen_through: %d; want 400", w.Code)
	}
	// The listing carries the full address count and can be narrowed to one.
	if list.AddressesTotal != 1 {
		t.Fatalf("addresses_total = %d; want 1", list.AddressesTotal)
	}
	w = f.do(t, http.MethodGet, "/v1/identity/queue?address=10.30.7.99", nil, cookies, csrf)
	var none api.IdentityQueueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &none); err != nil {
		t.Fatal(err)
	}
	if len(none.Groups) != 0 || none.AddressesTotal != 1 {
		t.Fatalf("filtered listing = %d groups, total %d; want none listed, total unchanged", len(none.Groups), none.AddressesTotal)
	}
	w = f.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "same_host", AssetID: asset.String(), Reason: "all mine", SeenThrough: g.LastSeen,
	}, cookies, csrf)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("same_host over more keys than rendered: %d %s; want 422", w.Code, w.Body.String())
	}
	var live int
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM asset_identity_keys WHERE tenant_id = $1 AND valid_to IS NULL`, c.Tenant().UUID()).Scan(&live)
	}); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("live keys after the refusal = %d; want 0", live)
	}
	w = f.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "discard", Reason: "a flood, not a host", SeenThrough: g.LastSeen,
	}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("discard: %d %s", w.Code, w.Body.String())
	}
	var pending, discarded, events int
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx, `SELECT count(*) FILTER (WHERE state = 'pending'), count(*) FILTER (WHERE state = 'discarded' AND resolved_by IS NOT NULL) FROM asset_resolution_queue WHERE tenant_id = $1`, tid).Scan(&pending, &discarded); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `SELECT count(*) FROM asset_identity_keys WHERE tenant_id = $1 AND valid_to IS NULL`, tid).Scan(&live); err != nil {
			return err
		}
		return c.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'identity.resolved' AND detail ->> 'decision' = 'discard'`, tid).Scan(&events)
	}); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || discarded != store.MaxKeysPerGroup+1 || live != 0 || events != 1 {
		t.Fatalf("after discard: pending=%d discarded=%d live keys=%d events=%d; want everything discarded under the operator's name, nothing recorded", pending, discarded, live, events)
	}
}

// "Different host" must record a key, or it must not happen: an echo of the
// occupant's own public fingerprint from a second port, or an address-only
// group, would otherwise create a keyless asset that takes the address, can
// never merge, and leaves the occupant without trust (measured).
func TestDifferentHostRefusesToCreateAKeylessAsset(t *testing.T) {
	q, asset := parkedHandover(t)
	ctx := context.Background()
	// Replace the parked group with an echo of the occupant's own key on 2222.
	if err := q.db.Write(ctx, q.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if _, err := c.Exec(ctx, `UPDATE asset_resolution_queue SET state = 'discarded', resolved_at = now() WHERE tenant_id = $1 AND state = 'pending'`, tid); err != nil {
			return err
		}
		payload, _ := json.Marshal(map[string]any{"address": qAddr, "port": 2222, "protocol": "tcp", "service": "ssh",
			"ssh": map[string]any{"fingerprint": qOld}})
		_, err := c.Exec(ctx, `INSERT INTO asset_resolution_queue (tenant_id, observed_payload, key_type, key_value, candidate_asset_ids, conflict_reason, address, source)
		    VALUES ($1, $2, 'ssh_hostkey', $3, ARRAY[$4::uuid], 'echo', $5::inet, '2222/tcp')`, tid, payload, qOld, asset, qAddr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	w := q.do(t, http.MethodPost, "/v1/identity/queue/resolve", api.ResolveIdentityRequest{
		Address: qAddr, Decision: "different_host", Reason: "looks new", SeenThrough: q.seenThrough(t),
	}, q.cookies, q.csrf)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("different_host on an echo of the holder's own key: %d %s; want 422", w.Code, w.Body.String())
	}
	var assets int
	var holder uuid.UUID
	if err := q.db.Read(ctx, q.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := c.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`, c.Tenant().UUID()).Scan(&assets); err != nil {
			return err
		}
		var err error
		holder, _, err = (store.AssetAddresses{}).LiveHolder(ctx, c, qAddr)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if assets != 1 || holder != asset {
		t.Fatalf("after the refusal: assets=%d holder=%s; want the occupant untouched", assets, holder)
	}
}
