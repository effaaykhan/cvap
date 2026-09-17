package api_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/store"
)

// B39's second slice (ADR-100): the queue pages by keyset, and a refused verb
// leaves a record.

// parkAt parks one keyed item at an address, enqueued at `at`.
func (q *queueFixture) parkAt(t *testing.T, addr string, at time.Time) {
	t.Helper()
	if err := q.db.Write(context.Background(), q.tenant, func(ctx context.Context, c *store.Conn) error {
		payload, _ := json.Marshal(map[string]any{"address": addr, "port": 22, "protocol": "tcp", "service": "ssh"})
		_, err := c.Exec(ctx, `INSERT INTO asset_resolution_queue
		    (tenant_id, observation_id, observed_payload, key_type, key_value, candidate_asset_ids, conflict_reason, address, source, enqueued_at)
		    VALUES ($1, gen_random_uuid(), $2, 'ssh_hostkey', $3, '{}', 'paging', $4::inet, '22/tcp', $5)`,
			c.Tenant().UUID(), payload, "SHA256:page-"+addr, addr, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func (q *queueFixture) page(t *testing.T, query string) api.IdentityQueueResponse {
	t.Helper()
	w := q.do(t, http.MethodGet, "/v1/identity/queue"+query, nil, q.cookies, q.csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("list %q: %d %s", query, w.Code, w.Body.String())
	}
	var resp api.IdentityQueueResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestTheQueuePagesByLastSeenAndAddress: three contested addresses, a page of
// two, then the cursor reaches the third and nothing repeats. addresses_total
// is the whole queue on every page, so a client knows what it has not seen.
func TestTheQueuePagesByLastSeenAndAddress(t *testing.T) {
	q, _ := seededContest(t) // one address, parked now
	base := time.Now().UTC().Add(-time.Hour)
	q.parkAt(t, "10.77.0.2", base.Add(-time.Minute))
	q.parkAt(t, "10.77.0.3", base.Add(-2*time.Minute))

	first := q.page(t, "?limit=2")
	if len(first.Groups) != 2 || first.NextBefore == nil || first.NextBeforeAddress == nil || first.AddressesTotal != 3 {
		t.Fatalf("page 1 = %d groups, cursor %v/%v, total %d; want 2 groups, a cursor, total 3",
			len(first.Groups), first.NextBefore, first.NextBeforeAddress, first.AddressesTotal)
	}
	second := q.page(t, "?limit=2&before="+*first.NextBefore+"&before_address="+*first.NextBeforeAddress)
	if len(second.Groups) != 1 || second.Groups[0].Address != "10.77.0.3" || second.NextBefore != nil || second.AddressesTotal != 3 {
		t.Fatalf("page 2 = %+v (cursor %v), want exactly 10.77.0.3 and no cursor", second.Groups, second.NextBefore)
	}
	seen := map[string]bool{}
	for _, g := range append(first.Groups, second.Groups...) {
		if seen[g.Address] {
			t.Errorf("address %s appeared on two pages", g.Address)
		}
		seen[g.Address] = true
	}
	// A full last page offers no cursor: three groups, limit 3.
	if full := q.page(t, "?limit=3"); len(full.Groups) != 3 || full.NextBefore != nil {
		t.Errorf("a full last page = %d groups, cursor %v; want 3 and none", len(full.Groups), full.NextBefore)
	}

	// TIES are the normal case — one sweep parks every address it contests at
	// one instant — and the ADR-compliance review measured the tuple form of
	// the cursor re-serving page one on them. Four addresses at one instant,
	// pages of two: every address once, in address order, then nothing.
	at := base.Add(-time.Hour)
	for _, a := range []string{"10.78.0.1", "10.78.0.2", "10.78.0.3", "10.78.0.4"} {
		q.parkAt(t, a, at)
	}
	var walked []string
	var cur *api.IdentityQueueResponse
	for i := 0; i < 5; i++ {
		query := "?limit=2"
		if cur != nil {
			query += "&before=" + *cur.NextBefore + "&before_address=" + *cur.NextBeforeAddress
		}
		pg := q.page(t, query)
		for _, g := range pg.Groups {
			walked = append(walked, g.Address)
		}
		if pg.NextBefore == nil {
			break
		}
		cur = &pg
	}
	want := []string{qAddr, "10.77.0.2", "10.77.0.3", "10.78.0.1", "10.78.0.2", "10.78.0.3", "10.78.0.4"}
	if strings.Join(walked, ",") != strings.Join(want, ",") {
		t.Errorf("walking the cursor visited %v, want %v (each address once, ties in address order)", walked, want)
	}
	// Half a cursor pages from an arbitrary point, so it is refused.
	if w := q.do(t, http.MethodGet, "/v1/identity/queue?before="+*first.NextBefore, nil, q.cookies, q.csrf); w.Code != http.StatusBadRequest {
		t.Errorf("before without before_address: %d, want 400", w.Code)
	}
	// A named address is one group and never a cursor.
	one := q.page(t, "?address=10.77.0.3&limit=1")
	if len(one.Groups) != 1 || one.NextBefore != nil {
		t.Errorf("?address= page = %d groups, cursor %v; want 1 and none", len(one.Groups), one.NextBefore)
	}
}

// TestARefusedVerbIsAudited: a verb the store declines writes identity.refused
// in its own transaction, naming the verb, the refusal code and what was asked
// — probing the verbs was visible only in the request log before (ADR-097).
func TestARefusedVerbIsAudited(t *testing.T) {
	q, asset := seededContest(t)
	stranger := uuid.New()
	w := q.do(t, http.MethodPost, "/v1/identity/queue/resolve", map[string]any{
		"address": qAddr, "decision": "same_host", "asset_id": stranger.String(), "reason": "probe", "seen_through": q.seenThrough(t),
	}, q.cookies, q.csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("same_host for an asset with nothing pending: %d %s, want 409", w.Code, w.Body.String())
	}
	w = q.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/identity/confirm", map[string]any{
		"keys": []string{"ssh_hostkey " + qOld}, "reason": "probe",
	}, q.cookies, q.csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("confirm of a key that is not rotated: %d %s, want 409", w.Code, w.Body.String())
	}
	var rows []map[string]any
	if err := q.db.Read(context.Background(), q.tenant, func(ctx context.Context, c *store.Conn) error {
		r, err := c.Query(ctx, `SELECT detail FROM audit_events WHERE tenant_id = $1 AND action = 'identity.refused' ORDER BY occurred_at`, c.Tenant().UUID())
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var raw []byte
			if err := r.Scan(&raw); err != nil {
				return err
			}
			var d map[string]any
			_ = json.Unmarshal(raw, &d)
			rows = append(rows, d)
		}
		return r.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("identity.refused events = %d, want 2 (one per refused verb): %v", len(rows), rows)
	}
	if rows[0]["verb"] != "identity.resolve" || rows[0]["code"] != "nothing_pending" || rows[0]["address"] != qAddr {
		t.Errorf("resolve refusal detail = %v", rows[0])
	}
	if rows[1]["verb"] != "identity.confirm" || rows[1]["code"] != "nothing_pending" {
		t.Errorf("confirm refusal detail = %v", rows[1])
	}
	// The refusal changed nothing: the contest is still pending.
	if _, pending, _, _ := q.state(t); pending != 1 {
		t.Errorf("pending after two refusals = %d, want 1", pending)
	}

	// The refusal's detail is bounded: a junk keys array the size of a request
	// body is not copied into the log (measured: ~1 MiB per refusal, 400/s).
	junk := make([]string, 2000)
	for i := range junk {
		junk[i] = "ssh_hostkey SHA256:" + strings.Repeat("x", 400)
	}
	if w := q.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/identity/confirm", map[string]any{"keys": junk, "reason": "flood"}, q.cookies, q.csrf); w.Code != http.StatusConflict {
		t.Fatalf("junk keys confirm: %d, want 409", w.Code)
	}
	var biggest int
	if err := q.db.Read(context.Background(), q.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT max(octet_length(detail::text)) FROM audit_events WHERE tenant_id = $1 AND action = 'identity.refused'`, c.Tenant().UUID()).Scan(&biggest)
	}); err != nil {
		t.Fatal(err)
	}
	if biggest > 8192 {
		t.Errorf("largest identity.refused detail = %d bytes, want a bounded record (20 names of 128 bytes plus a count)", biggest)
	}

	// The record lands on the timeline of the asset HOLDING the address, not
	// on whatever asset id the caller named (which need not exist): a prober
	// does not choose where the mark lands. A refused discard at a held address
	// — a verb that names no asset at all — lands there too.
	w = q.do(t, http.MethodPost, "/v1/identity/queue/resolve", map[string]any{
		"address": qAddr, "decision": "discard", "reason": "probe", "seen_through": "2001-01-01T00:00:00Z",
	}, q.cookies, q.csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("discard with a seen_through before every item: %d %s, want 409", w.Code, w.Body.String())
	}
	w = q.do(t, http.MethodGet, "/v1/assets/"+asset.String()+"/events", nil, q.cookies, q.csrf)
	var tl api.AssetEventsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &tl)
	refused := 0
	for _, e := range tl.Events {
		if e.Action == "identity.refused" {
			refused++
			if e.Detail["asset_id"] == stranger.String() && e.Detail["decision"] == "same_host" {
				continue // the same_host refusal names the stranger in its detail, keyed to the holder
			}
		}
	}
	if refused != 4 {
		t.Errorf("identity.refused events on the holder's timeline = %d, want 4 (same_host naming a stranger, confirm, the junk confirm, discard)", refused)
	}
}

// TestTheAssetTimelineListsWhatHappenedToIt: the events keyed to an asset are
// readable where the asset is (ADR-100; ListByResource had no production
// caller). A refused confirm is the first entry; an unknown asset is 404.
func TestTheAssetTimelineListsWhatHappenedToIt(t *testing.T) {
	q, asset := seededContest(t)
	w := q.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/identity/confirm", map[string]any{
		"keys": []string{"ssh_hostkey " + qOld}, "reason": "probe"}, q.cookies, q.csrf)
	if w.Code != http.StatusConflict {
		t.Fatalf("confirm: %d, want 409", w.Code)
	}
	w = q.do(t, http.MethodGet, "/v1/assets/"+asset.String()+"/events", nil, q.cookies, q.csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("events: %d %s", w.Code, w.Body.String())
	}
	var resp api.AssetEventsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Events) == 0 || resp.Events[0].Action != "identity.refused" || resp.Events[0].ActorID == nil {
		t.Fatalf("timeline = %+v, want identity.refused first with the operator named", resp.Events)
	}
	if w := q.do(t, http.MethodGet, "/v1/assets/"+uuid.NewString()+"/events", nil, q.cookies, q.csrf); w.Code != http.StatusNotFound {
		t.Errorf("events of an unknown asset: %d, want 404", w.Code)
	}
}

// TestClearingAPinnedAttributionLetsInferenceLandAgain: an exact read outranks
// inference for ever (ADR-095); clearing it re-stamps the provenance so the next
// band vote lands, keeps the values until then, records who cleared it, and
// refuses when nothing exact is held.
func TestClearingAPinnedAttributionLetsInferenceLandAgain(t *testing.T) {
	f := newFixture(t, `{"asset.read": true, "identity.resolve": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()
	var asset uuid.UUID
	rel := "resolute"
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "pinned.corp"})
		if err != nil {
			return err
		}
		asset = a.ID
		if err := (store.Assets{}).SetAttribution(ctx, c, a.ID, "ubuntu", &rel, 1.0,
			[]byte(`{"source":"os-release","read_at":"2026-09-01T00:00:00Z"}`), true); err != nil {
			return err
		}
		return (store.Assets{}).SetRelease(ctx, c, a.ID, &rel, 1.0,
			[]byte(`{"source":"package_manager","read_at":"2026-09-01T00:00:00Z"}`), true)
	}); err != nil {
		t.Fatal(err)
	}
	// An inferred sweep cannot move it.
	deb := "bookworm"
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Assets{}).SetAttribution(ctx, c, asset, "debian", &deb, 0.8, []byte(`{"source":"band_vote"}`), false)
	}); err != nil {
		t.Fatal(err)
	}
	if fam := assetFamily(t, f, asset); fam != "ubuntu" {
		t.Fatalf("before clearing: distro_family = %q, want the exact ubuntu to hold", fam)
	}

	w := f.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/attribution/clear", map[string]any{"reason": "the host lied within the grammar"}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", w.Code, w.Body.String())
	}
	var resp api.ClearAttributionResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Cleared) != 2 {
		t.Fatalf("cleared = %v, want os and release", resp.Cleared)
	}
	if fam := assetFamily(t, f, asset); fam != "ubuntu" {
		t.Errorf("after clearing: distro_family = %q, want the value kept until a sweep re-derives", fam)
	}
	// Now the inferred sweep lands.
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Assets{}).SetAttribution(ctx, c, asset, "debian", &deb, 0.8, []byte(`{"source":"band_vote"}`), false)
	}); err != nil {
		t.Fatal(err)
	}
	if fam := assetFamily(t, f, asset); fam != "debian" {
		t.Errorf("after clearing, an inferred sweep: distro_family = %q, want debian (the pin is lifted)", fam)
	}
	// An asset that never held an exact attribution is the same refusal — not a
	// 500: the security review measured NULL provenance columns failing the
	// RETURNING scan on every plain asset.
	var plain uuid.UUID
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "plain.corp"})
		plain = a.ID
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if w := f.do(t, http.MethodPost, "/v1/assets/"+plain.String()+"/attribution/clear", map[string]any{"reason": "nothing"}, cookies, csrf); w.Code != http.StatusConflict {
		t.Errorf("clear on an unattributed asset: %d %s, want 409", w.Code, w.Body.String())
	}
	// Nothing exact is held now: a second clear is a refusal, and the first is on the timeline.
	if w := f.do(t, http.MethodPost, "/v1/assets/"+asset.String()+"/attribution/clear", map[string]any{"reason": "again"}, cookies, csrf); w.Code != http.StatusConflict {
		t.Errorf("second clear: %d, want 409", w.Code)
	}
	w = f.do(t, http.MethodGet, "/v1/assets/"+asset.String()+"/events", nil, cookies, csrf)
	var ev api.AssetEventsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &ev)
	if len(ev.Events) == 0 || ev.Events[0].Action != "asset.attribution_cleared" {
		t.Errorf("timeline = %+v, want asset.attribution_cleared", ev.Events)
	}
}

func assetFamily(t *testing.T, f *fixture, id uuid.UUID) string {
	t.Helper()
	var fam string
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT coalesce(distro_family,'') FROM assets WHERE tenant_id=$1 AND asset_id=$2`, c.Tenant().UUID(), id).Scan(&fam)
	}); err != nil {
		t.Fatal(err)
	}
	return fam
}

// TestTheSightingWindowIsATenantSettingTiedToScanCadence: the window reads as
// the default until set; setting it is audited; and a window under twice the
// measured cadence — two scans must land inside one window (ADR-094) — is
// refused with the cadence in the message, so an operator cannot turn the
// credentialed path off quietly.
func TestTheSightingWindowIsATenantSettingTiedToScanCadence(t *testing.T) {
	f := newFixture(t, `{"asset.read": true, "policy.write": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()

	get := func() api.IdentitySettingsResponse {
		w := f.do(t, http.MethodGet, "/v1/settings/identity", nil, cookies, csrf)
		if w.Code != http.StatusOK {
			t.Fatalf("get settings: %d %s", w.Code, w.Body.String())
		}
		var resp api.IdentitySettingsResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return resp
	}
	if s := get(); !s.IsDefault || s.SightingWindowHours != 168 || s.ScanCadenceHours != nil {
		t.Fatalf("fresh tenant: %+v, want the 168h default, unmeasured cadence", s)
	}
	put := func(hours int) *httptest.ResponseRecorder {
		return f.do(t, http.MethodPut, "/v1/settings/identity", map[string]any{"sighting_window_hours": hours, "reason": "test"}, cookies, csrf)
	}
	if w := put(72); w.Code != http.StatusOK {
		t.Fatalf("set 72h with no cadence measured: %d %s", w.Code, w.Body.String())
	}
	if s := get(); s.IsDefault || s.SightingWindowHours != 72 {
		t.Fatalf("after setting 72h: %+v", s)
	}
	if w := put(12); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("12h is under the 24h floor: %d, want 422", w.Code)
	}
	// Bounded before it becomes a Duration: 5 124 120 hours wrapped to 24h25m
	// and was ACCEPTED as the shortest window (security review).
	if w := put(5124120); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("5124120h: %d, want 422 (bounded as an integer, not after the multiply)", w.Code)
	}
	if s := get(); s.SightingWindowHours != 72 {
		t.Errorf("after the overflow attempt the window = %dh, want 72 unchanged", s.SightingWindowHours)
	}

	// Four completed scans twelve hours apart: cadence 12h, so anything under
	// 24h... is the floor anyway; make the cadence 30h so the cadence rule, not
	// the floor, is what refuses 48h.
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		base := time.Now().UTC().Add(-10 * 24 * time.Hour)
		for i := 0; i < 4; i++ {
			if _, err := c.Exec(ctx, `INSERT INTO scans (tenant_id, policy_id, scan_type, status, completed_at) VALUES ($1, $2, 'discovery', 'completed', $3)`,
				c.Tenant().UUID(), f.policyID, base.Add(time.Duration(i)*30*time.Hour)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if s := get(); s.ScanCadenceHours == nil || *s.ScanCadenceHours != 30 || s.ScanCadenceSamples != 4 {
		t.Fatalf("measured cadence = %+v, want 30h over 4 scans", s)
	}
	w := put(48)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "30.0 hours") {
		t.Errorf("48h under a 30h cadence: %d %s, want 422 naming the cadence", w.Code, w.Body.String())
	}
	if w := put(61); w.Code != http.StatusOK {
		t.Errorf("61h over a 30h cadence: %d %s, want 200", w.Code, w.Body.String())
	}
	var events int
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = 'identity.window_changed'`, c.Tenant().UUID()).Scan(&events)
	}); err != nil {
		t.Fatal(err)
	}
	if events != 2 {
		t.Errorf("identity.window_changed events = %d, want 2 (the two accepted changes; refusals record nothing)", events)
	}
}

// knownHostsLine is a real ed25519 known_hosts line for host.
func knownHostsLine(t *testing.T, host string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return host + " " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

// TestAnOperatorCanPinAndClearHostKeysOnAProfile: known_hosts had a reader and
// no writer (ADR-097's open item). The pin is validated, recorded with its
// fingerprints, visible on the listing, cleared by its own verb, and a second
// clear is refused. The secret never appears in any response.
func TestAnOperatorCanPinAndClearHostKeysOnAProfile(t *testing.T) {
	f := newFixture(t, `{"policy.read": true, "credential.pin": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()
	var pid uuid.UUID
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `INSERT INTO credential_profiles (tenant_id, name, cred_type, secret_ref, username)
		    VALUES ($1, 'lab-ssh', 'ssh', 'file:///secret/lab.key', 'lab') RETURNING credential_profile_id`, c.Tenant().UUID()).Scan(&pid)
	}); err != nil {
		t.Fatal(err)
	}
	list := func() api.CredentialProfileListResponse {
		w := f.do(t, http.MethodGet, "/v1/credential-profiles", nil, cookies, csrf)
		if w.Code != http.StatusOK {
			t.Fatalf("list: %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "secret") {
			t.Fatalf("the listing carries the secret pointer: %s", w.Body.String())
		}
		var resp api.CredentialProfileListResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return resp
	}
	if l := list(); len(l.Profiles) != 1 || l.Profiles[0].PinLines != 0 || l.Profiles[0].Name != "lab-ssh" {
		t.Fatalf("listing before the pin: %+v", l.Profiles)
	}
	path := "/v1/credential-profiles/" + pid.String() + "/known-hosts"
	// A marker line is refused, and nothing is written.
	if w := f.do(t, http.MethodPut, path, map[string]any{"known_hosts": "@revoked " + knownHostsLine(t, "10.0.0.5"), "reason": "x"}, cookies, csrf); w.Code != http.StatusUnprocessableEntity {
		t.Errorf("marker line: %d, want 422", w.Code)
	}
	lines := knownHostsLine(t, "10.0.0.5") + "\n" + knownHostsLine(t, "10.0.0.6,host6") + "\n"
	w := f.do(t, http.MethodPut, path, map[string]any{"known_hosts": lines, "reason": "reimaged .5 and .6; keys taken from the console"}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("pin: %d %s", w.Code, w.Body.String())
	}
	var pinned api.PinKnownHostsResponse
	_ = json.Unmarshal(w.Body.Bytes(), &pinned)
	if pinned.Lines != 2 || len(pinned.Fingerprints) != 2 {
		t.Fatalf("pinned = %+v, want 2 lines with fingerprints", pinned)
	}
	if l := list(); l.Profiles[0].PinLines != 2 {
		t.Errorf("listing after the pin: pin_lines = %d, want 2", l.Profiles[0].PinLines)
	}
	var stored string
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT known_hosts FROM credential_profiles WHERE credential_profile_id = $1`, pid).Scan(&stored)
	}); err != nil {
		t.Fatal(err)
	}
	if stored != lines {
		t.Errorf("stored pin = %q, want the canonical lines", stored)
	}
	w = f.do(t, http.MethodDelete, path, map[string]any{"reason": "back to observed"}, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("clear: %d %s", w.Code, w.Body.String())
	}
	if l := list(); l.Profiles[0].PinLines != 0 {
		t.Errorf("listing after the clear: pin_lines = %d, want 0", l.Profiles[0].PinLines)
	}
	if w := f.do(t, http.MethodDelete, path, map[string]any{"reason": "again"}, cookies, csrf); w.Code != http.StatusConflict {
		t.Errorf("second clear: %d, want 409", w.Code)
	}
	var actions []string
	if err := f.db.Read(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		r, err := c.Query(ctx, `SELECT action FROM audit_events WHERE tenant_id = $1 AND resource_type = 'credential_profile' ORDER BY occurred_at`, c.Tenant().UUID())
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var a string
			if err := r.Scan(&a); err != nil {
				return err
			}
			actions = append(actions, a)
		}
		return r.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(actions, ",") != "credential.pinned,credential.pin_cleared" {
		t.Errorf("audit actions = %v, want pinned then pin_cleared (a refused pin records nothing)", actions)
	}
	// Without the permission, neither verb.
	viewer := newFixture(t, `{"policy.read": true}`)
	vc, vx := viewer.login(t)
	if w := viewer.do(t, http.MethodPut, path, map[string]any{"known_hosts": lines, "reason": "x"}, vc, vx); w.Code != http.StatusForbidden {
		t.Errorf("pin without credential.pin: %d, want 403", w.Code)
	}
}

// TestTheAssetPageShowsTheRunningKernelAndRebootPending: the newest credentialed
// read's kernel facts on the asset (ADR-099's consequence, now shown): `uname -r`,
// each installed kernel package's state by the same classification the matcher
// uses, and reboot pending when a newer kernel is installed and not running.
func TestTheAssetPageShowsTheRunningKernelAndRebootPending(t *testing.T) {
	f := newFixture(t, `{"asset.read": true, "scan.read": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()
	var asset uuid.UUID
	observe := func(kernel string, at time.Time) {
		t.Helper()
		if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
			if asset == uuid.Nil {
				a, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "kernel.corp"})
				if err != nil {
					return err
				}
				asset = a.ID
			}
			sp, err := (store.ScanPoints{}).Create(ctx, c, f.zoneID, "kernel-sp", "1", "v1", "fp-"+uuid.NewString())
			if err != nil {
				return err
			}
			subID := "sub-" + uuid.NewString()
			taskID, err := seedQueueScan(ctx, c, sp.ID, f.policyID, subID)
			if err != nil {
				return err
			}
			payload, _ := json.Marshal(map[string]any{
				"address": "10.0.0.60", "family": "ubuntu", "release": "resolute", "release_source": "os-release", "kernel_release": kernel,
				"installed": []map[string]any{
					{"name": "linux", "binary": "linux-modules-7.0.0-31-generic", "version": "7.0.0-31.31"},
					{"name": "linux", "binary": "linux-modules-7.0.0-30-generic", "version": "7.0.0-30.30"},
					{"name": "linux", "binary": "linux-libc-dev", "version": "7.0.0-31.31"},
					{"name": "openssh", "binary": "openssh-server", "version": "1:9.6p1-3"},
				},
			})
			conf := 1.0
			o := store.Observation{ID: uuid.New(), SubmissionID: subID, TaskID: taskID, ScanPointID: sp.ID, ZoneID: f.zoneID,
				Type: store.ObsPackage, Payload: payload, Confidence: &conf, ObservedAt: at}
			if err := (store.Observations{}).Insert(ctx, c, o, store.IngestAccepted); err != nil {
				return err
			}
			return (store.Observations{}).Resolve(ctx, c, o.ID, at, asset)
		}); err != nil {
			t.Fatal(err)
		}
	}
	get := func() *api.AssetKernelResponse {
		t.Helper()
		w := f.do(t, http.MethodGet, "/v1/assets/"+asset.String(), nil, cookies, csrf)
		if w.Code != http.StatusOK {
			t.Fatalf("asset: %d %s", w.Code, w.Body.String())
		}
		var resp api.AssetResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		return resp.Kernel
	}
	now := time.Now().UTC()
	// Reboot pending: running ABI-30 with ABI-31 installed.
	observe("7.0.0-30-generic", now.Add(-2*time.Hour))
	k := get()
	if k == nil || k.RunningRelease != "7.0.0-30-generic" || k.RebootPending == nil || !*k.RebootPending || len(k.Installed) != 2 {
		t.Fatalf("kernel section = %+v, want running 7.0.0-30-generic, reboot pending, two kernel packages (libc-dev and openssh are not kernel packages)", k)
	}
	// The NEWEST read decides: after the reboot, nothing pending.
	observe("7.0.0-31-generic", now.Add(-time.Hour))
	if k = get(); k.RunningRelease != "7.0.0-31-generic" || k.RebootPending == nil || *k.RebootPending {
		t.Errorf("after the reboot: %+v, want running 7.0.0-31-generic and nothing pending", k)
	}
	// A read with no uname: states unknown, pending unjudged.
	observe("", now.Add(-30*time.Minute))
	if k = get(); k.RunningRelease != "" || k.RebootPending != nil || k.Installed[0].State != "kernel-unknown" {
		t.Errorf("no uname: %+v, want no release, no verdict, kernel-unknown rows", k)
	}
}
