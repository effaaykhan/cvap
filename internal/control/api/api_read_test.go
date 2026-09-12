package api_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// The read surface (session 18). The finding DETAIL is the deliverable: an
// analyst reads a finding, its exposures and the evidence, and verifies the
// claim without re-scanning. These tests seed through the store (the write path)
// and read back through the API (the read path), which is the first time the two
// meet outside a pipeline test.

// seededFinding is what seedFinding returns so a test can assert against it.
type seededFinding struct {
	assetID   uuid.UUID
	findingID uuid.UUID
	zoneA     uuid.UUID
	zoneB     uuid.UUID
	ruleName  string
}

// seedFinding writes an asset, a finding on it, evidence, and exposure from two
// zones. agedOut controls whether the evidence's observation_id is NULL (the
// aged-out case, ADR-016). It seeds through the store as the pipeline would.
func (f *fixture) seedFinding(t *testing.T, agedOut bool) seededFinding {
	t.Helper()
	var out seededFinding
	now := time.Now().UTC()

	err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		// A rule to hang the finding on. Rules are global and migration-seeded
		// (0032); any one serves — the read joins its name in.
		var ruleID uuid.UUID
		if err := c.QueryRow(ctx, `SELECT rule_id, name FROM rules WHERE engine='rules' ORDER BY name LIMIT 1`).
			Scan(&ruleID, &out.ruleName); err != nil {
			return err
		}

		asset, err := (store.Assets{}).Create(ctx, c, store.Asset{
			Hostname: "host-" + uuid.NewString()[:8] + ".corp", Environment: "production",
		})
		if err != nil {
			return err
		}
		out.assetID = asset.ID

		// A second zone besides the fixture's, so exposure-from-two-zones is real.
		// Name is unique per seed — scan_zones names are unique per tenant, and a
		// test may seed several findings.
		zb, err := (store.Zones{}).Create(ctx, c, "dmz-"+uuid.NewString()[:8], store.ZoneDMZ, 50, "")
		if err != nil {
			return err
		}
		out.zoneA, out.zoneB = f.zoneID, zb.ID

		id, _, err := (store.Findings{}).Upsert(ctx, c, store.Finding{
			AssetID: asset.ID, RuleID: ruleID, DedupKey: "dk-" + uuid.NewString(),
			Locator: "443/tcp", Severity: "high", Confidence: 0.9,
		}, now)
		if err != nil {
			return err
		}
		out.findingID = id

		obs := uuid.New()
		if agedOut {
			obs = uuid.Nil // written as NULL: the observation has aged out
		}
		if err := (store.Findings{}).ReplaceEvidence(ctx, c, id, []store.FindingEvidence{{
			ObservationID: obs, Type: "banner",
			Data: map[string]any{"banner": "220 vsftpd (CVAP lab)"}, CapturedAt: now,
		}}); err != nil {
			return err
		}
		// One finding, two zones — the case that must count as one finding.
		return (store.Findings{}).SetExposure(ctx, c, id, []uuid.UUID{out.zoneA, out.zoneB}, now)
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	return out
}

// TestFindingDetailCarriesEvidenceAndExposures — the deliverable.
func TestFindingDetailCarriesEvidenceAndExposures(t *testing.T) {
	f := newFixture(t, `{"finding.read": true}`)
	sf := f.seedFinding(t, false)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodGet, "/v1/findings/"+sf.findingID.String(), nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("get finding: %d %s", w.Code, w.Body.String())
	}
	var resp api.FindingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if resp.Rule != sf.ruleName {
		t.Errorf("rule = %q, want %q", resp.Rule, sf.ruleName)
	}
	if resp.DedupKey == "" || resp.Source != "network" {
		t.Errorf("dedup_key/source not read back: %q/%q", resp.DedupKey, resp.Source)
	}
	if len(resp.Exposures) != 2 {
		t.Errorf("exposures = %d, want 2 (one finding, two zones)", len(resp.Exposures))
	}
	// internet_reachable is DERIVED from zone_type (ADR-074), not the dropped column.
	// The finding is exposed from an internal zone (zoneA) and a DMZ zone (zoneB), so
	// exactly one exposure reads internet-reachable — the derivation, exercised end to
	// end through the API, not asserted. Before ADR-074 the dropped column read false
	// for both, so this assertion would have failed on the old inert value.
	reachable := 0
	for _, ex := range resp.Exposures {
		if ex.InternetReachable {
			reachable++
			if ex.ZoneType != "dmz" && ex.ZoneType != "external" {
				t.Errorf("internet_reachable true for zone_type %q, want external/dmz", ex.ZoneType)
			}
		}
	}
	if reachable != 1 {
		t.Errorf("internet-reachable exposures = %d, want 1 (the DMZ zone; the internal one is not)", reachable)
	}
	// The evidence is the point: it must carry the captured data a human checks.
	if len(resp.Evidence) != 1 {
		t.Fatalf("evidence = %d, want 1", len(resp.Evidence))
	}
	e := resp.Evidence[0]
	if e.Type != "banner" || e.Data["banner"] != "220 vsftpd (CVAP lab)" {
		t.Errorf("evidence not read back: %+v", e)
	}
	if e.ObservationAgedOut || e.ObservationID == nil {
		t.Errorf("a fresh finding's evidence should link its observation, got aged_out=%v id=%v",
			e.ObservationAgedOut, e.ObservationID)
	}
}

// TestFindingDetailShowsAgedOutObservationHonestly — note 3. When the source
// observation has aged out (observation_id NULL), the evidence remains and the
// response says so rather than showing a zero-uuid dead link.
func TestFindingDetailShowsAgedOutObservationHonestly(t *testing.T) {
	f := newFixture(t, `{"finding.read": true}`)
	sf := f.seedFinding(t, true)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodGet, "/v1/findings/"+sf.findingID.String(), nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("get finding: %d %s", w.Code, w.Body.String())
	}
	var resp api.FindingResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Evidence) != 1 {
		t.Fatalf("evidence = %d, want 1 (evidence outlives the observation)", len(resp.Evidence))
	}
	e := resp.Evidence[0]
	if !e.ObservationAgedOut {
		t.Error("an aged-out observation must be reported as such")
	}
	if e.ObservationID != nil {
		t.Errorf("aged-out evidence must carry no observation id, got %v — a zero-uuid link is the "+
			"dishonest provenance ADR-016 forbids", *e.ObservationID)
	}
	if e.Data["banner"] != "220 vsftpd (CVAP lab)" {
		t.Error("the evidence data must survive the observation aging out")
	}
	// Confirm it is genuinely NULL in the row, not a scan quirk.
	var nullCount int
	if err := f.db.Read(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT count(*) FROM evidence WHERE tenant_id=$1 AND finding_id=$2 AND observation_id IS NULL`,
			f.tenant.UUID(), sf.findingID).Scan(&nullCount)
	}); err != nil {
		t.Fatal(err)
	}
	if nullCount != 1 {
		t.Errorf("expected the evidence row's observation_id to be NULL, got %d null rows", nullCount)
	}
}

// TestExposureCountsDistinctFindingsPerZone — note 4. One finding exposed from
// two zones is one finding in each zone's count, never inflated, and the list's
// exposure_zones is 2.
func TestExposureCountsDistinctFindingsPerZone(t *testing.T) {
	f := newFixture(t, `{"finding.read": true}`)
	f.seedFinding(t, false)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodGet, "/v1/exposure", nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("exposure: %d %s", w.Code, w.Body.String())
	}
	var resp api.ExposureByZoneResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Zones) != 2 {
		t.Fatalf("exposure zones = %d, want 2", len(resp.Zones))
	}
	for _, z := range resp.Zones {
		if z.Total != 1 || z.High != 1 {
			t.Errorf("zone %s: total=%d high=%d, want 1/1 — a finding in two zones must count "+
				"once per zone, not as the join-row product", z.ZoneName, z.Total, z.High)
		}
	}

	// The list echoes the same: one finding, exposure_zones = 2.
	lw := f.do(t, http.MethodGet, "/v1/findings", nil, cookies, csrf)
	var list api.FindingListResponse
	if err := json.Unmarshal(lw.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Findings) != 1 {
		t.Fatalf("findings = %d, want 1 (one finding, not one per zone)", len(list.Findings))
	}
	if list.Findings[0].ExposureZones != 2 {
		t.Errorf("exposure_zones = %d, want 2", list.Findings[0].ExposureZones)
	}
}

// TestKnowledgeFreshnessReportsComputedState — the endpoint returns the STATE the
// server computed against each feed's own threshold, not a raw timestamp for the
// UI to judge. Knowledge tables are global (ADR-030), so the seeded feeds are
// visible under any tenant; the state is what proves the surface answers the
// question rather than deferring it to the panel.
func TestKnowledgeFreshnessReportsComputedState(t *testing.T) {
	importURL := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if importURL == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set; skipping freshness surface test (needs the cvap_knowledge_import role)")
	}
	f := newFixture(t, `{"finding.read": true}`)
	cookies, csrf := f.login(t)

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, importURL)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()

	current := "api-current-" + uuid.NewString()[:8]
	stale := "api-stale-" + uuid.NewString()[:8]
	for feed, fetched := range map[string]string{
		current: "now() - interval '1 hour'",
		stale:   "now() - interval '60 days'",
	} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO knowledge_feed_status (feed, source_url, last_fetched_at, advisory_count, staleness_threshold)
			 VALUES ($1, 'https://example.test/'||$1, `+fetched+`, 3, interval '7 days')`, feed); err != nil {
			t.Fatalf("seed feed %s: %v", feed, err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM knowledge_feed_status WHERE feed = ANY($1)`,
			[]string{current, stale})
	})

	w := f.do(t, http.MethodGet, "/v1/knowledge/freshness", nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("freshness: %d %s", w.Code, w.Body.String())
	}
	var resp api.KnowledgeFreshnessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, feed := range resp.Feeds {
		states[feed.Feed] = feed.State
	}
	if states[current] != "current" {
		t.Errorf("feed %s: state = %q, want current", current, states[current])
	}
	if states[stale] != "stale" {
		t.Errorf("feed %s: state = %q, want stale (fetched 60 days ago against a 7-day threshold)", stale, states[stale])
	}
}

// TestAssetDetailCarriesReleaseProvenance — the dashboard surface for P3.3
// (ADR-064): a resolved release reaches the asset page WITH its evidence (which
// services voted and which abstained), so an operator can check the claim. Seeds
// the asset state directly (the resolver itself is proven end to end in
// internal/correlate); this asserts the read path carries release_provenance.
// TestCoverageSurfaces — B29's dashboard (ADR-067): the knowledge panel reports
// each release's coverage state beside feed freshness, and an asset on an
// out-of-coverage release carries the caveat, so an operator never reads an empty
// finding list on such a host as "clean".
func TestCoverageSurfaces(t *testing.T) {
	importURL := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if importURL == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set; skipping coverage surface test (needs cvap_knowledge_import)")
	}
	f := newFixture(t, `{"finding.read": true, "asset.read": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, importURL)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()
	// hardy: out of coverage. Plus a hardy advisory so it appears in CoverageAll.
	for _, s := range []string{
		`INSERT INTO release_coverage (feed, distro_release, release_date, support_expires, esm_expires, coverage_source, last_fetched_at)
		 VALUES ('ubuntu-usn','hardy','2008-04-24','2008-04-24','2008-04-24','feed-degenerate', now())
		 ON CONFLICT (feed, distro_release) DO NOTHING`,
		`INSERT INTO vendor_advisories (advisory_ref, vendor) VALUES ('USN-1467-1','ubuntu') ON CONFLICT (advisory_ref) DO NOTHING`,
		`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
		 SELECT advisory_id, 'hardy', 'mysql-dfsg-5.0', '5.0.96-0ubuntu3', 'dpkg'::version_comparator
		   FROM vendor_advisories WHERE advisory_ref='USN-1467-1'
		 ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// Knowledge panel: coverage beside freshness.
	w := f.do(t, http.MethodGet, "/v1/knowledge/freshness", nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("freshness: %d %s", w.Code, w.Body.String())
	}
	var kr api.KnowledgeFreshnessResponse
	if err := json.Unmarshal(w.Body.Bytes(), &kr); err != nil {
		t.Fatal(err)
	}
	var hardyState string
	for _, c := range kr.Coverage {
		if c.Release == "hardy" {
			hardyState = c.State
		}
	}
	if hardyState != "out_of_coverage" {
		t.Errorf("knowledge coverage: hardy = %q, want out_of_coverage", hardyState)
	}

	// Asset caveat: a host resolved to hardy carries the out-of-coverage state.
	var assetID uuid.UUID
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "eol.corp", Environment: "production"})
		if err != nil {
			return err
		}
		assetID = a.ID
		rel := "hardy"
		return (store.Assets{}).SetAttribution(ctx, c, a.ID, "ubuntu", &rel, 0.9, []byte(`[]`), false)
	}); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	aw := f.do(t, http.MethodGet, "/v1/assets/"+assetID.String(), nil, cookies, csrf)
	var ar api.AssetResponse
	if err := json.Unmarshal(aw.Body.Bytes(), &ar); err != nil {
		t.Fatal(err)
	}
	if ar.ReleaseCoverageState == nil || *ar.ReleaseCoverageState != "out_of_coverage" {
		t.Fatalf("asset release_coverage_state = %v, want out_of_coverage — an EOL host must not read as clean (B29)", ar.ReleaseCoverageState)
	}
}

// TestAdvisoryStatusOnTheWire — ADR-068: the three states (plus no_release) reach
// the client as a first-class enum on the asset AND on the asset-scoped finding
// list, so an empty finding array is never read as clean. clean is reachable only
// for a resolved release in coverage.
func TestAdvisoryStatusOnTheWire(t *testing.T) {
	importURL := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if importURL == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set; skipping advisory-status wire test")
	}
	f := newFixture(t, `{"finding.read": true, "asset.read": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, importURL)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx,
		`INSERT INTO release_coverage (feed, distro_release, release_date, support_expires, esm_expires, coverage_source, last_fetched_at)
		 VALUES ('ubuntu-usn','hardy','2008-04-24','2008-04-24','2008-04-24','feed-degenerate', now()),
		        ('ubuntu-usn','jammy','2022-04-21','2027-04-30','2032-04-30','feed', now())
		 ON CONFLICT (feed, distro_release) DO NOTHING`); err != nil {
		t.Fatalf("seed coverage: %v", err)
	}

	// Three hosts: out-of-coverage release, covered release, no release.
	mk := func(family string, release *string) uuid.UUID {
		var id uuid.UUID
		if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
			a, e := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "h-" + uuid.NewString()[:8] + ".corp", Environment: "production"})
			if e != nil {
				return e
			}
			id = a.ID
			if family == "" {
				return nil // no attribution -> no release
			}
			return (store.Assets{}).SetAttribution(ctx, c, a.ID, family, release, 0.9, []byte(`[]`), false)
		}); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
		return id
	}
	hardy := "hardy"
	jammy := "jammy"
	out := mk("ubuntu", &hardy)     // out of coverage -> cannot_know
	covered := mk("ubuntu", &jammy) // covered -> clean
	noRel := mk("", nil)            // no release -> no_release

	want := map[uuid.UUID]string{out: "cannot_know", covered: "clean", noRel: "no_release"}
	for id, exp := range want {
		// Asset detail.
		w := f.do(t, http.MethodGet, "/v1/assets/"+id.String(), nil, cookies, csrf)
		var ar api.AssetResponse
		if err := json.Unmarshal(w.Body.Bytes(), &ar); err != nil {
			t.Fatal(err)
		}
		if ar.AdvisoryStatus != exp {
			t.Errorf("asset %s advisory_status = %q, want %q", id, ar.AdvisoryStatus, exp)
		}
		// Asset-scoped finding list carries the same verdict alongside an (empty) array.
		fw := f.do(t, http.MethodGet, "/v1/findings?asset_id="+id.String(), nil, cookies, csrf)
		var fr api.FindingListResponse
		if err := json.Unmarshal(fw.Body.Bytes(), &fr); err != nil {
			t.Fatal(err)
		}
		if fr.AssetAdvisoryStatus == nil || *fr.AssetAdvisoryStatus != exp {
			t.Errorf("findings?asset_id=%s asset_advisory_status = %v, want %q — an empty list must carry the verdict", id, fr.AssetAdvisoryStatus, exp)
		}
		if len(fr.Findings) != 0 {
			t.Errorf("expected no findings for the seeded host, got %d", len(fr.Findings))
		}
	}
	// The structural point: clean is reachable only for the covered host; the
	// out-of-coverage host is a DIFFERENT value, never clean.
	if want[out] == want[covered] {
		t.Fatal("out-of-coverage and covered hosts must not share an advisory_status")
	}
}

func TestAssetDetailCarriesReleaseProvenance(t *testing.T) {
	f := newFixture(t, `{"asset.read": true}`)
	cookies, csrf := f.login(t)
	ctx := context.Background()

	var assetID uuid.UUID
	prov := []byte(`[{"service":"ssh","port":22,"product":"OpenSSH","band":"4.7p1","role":"contributed","candidates":["hardy"]},` +
		`{"service":"smb","port":445,"product":"Samba","band":"3.0.20","role":"abstained","reason":"observed version matches no release's band"}]`)
	if err := f.db.Write(ctx, f.tenant, func(ctx context.Context, c *store.Conn) error {
		a, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "meta.corp", Environment: "production"})
		if err != nil {
			return err
		}
		assetID = a.ID
		if err := (store.Assets{}).SetAttribution(ctx, c, a.ID, "ubuntu", nil, 0.95, []byte(`[]`), false); err != nil {
			return err
		}
		rel := "hardy"
		return (store.Assets{}).SetRelease(ctx, c, a.ID, &rel, 1.0, prov, false)
	}); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	w := f.do(t, http.MethodGet, "/v1/assets/"+assetID.String(), nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("get asset: %d %s", w.Code, w.Body.String())
	}
	var resp api.AssetResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.DistroRelease == nil || *resp.DistroRelease != "hardy" {
		t.Fatalf("distro_release = %v, want hardy", resp.DistroRelease)
	}
	if len(resp.ReleaseProvenance) == 0 {
		t.Fatalf("release_provenance absent from the asset detail — the release has no visible evidence")
	}
	// release_confidence must surface too: it is stored and served, and the UI
	// now renders it (ADR-065's tiering makes it load-bearing). Asserting it
	// reaches the response guards against the write-carry-store-drop shape (§5.6)
	// — a field written and stored but read by no consumer.
	if resp.ReleaseConfidence == nil {
		t.Errorf("release_confidence absent from the asset detail — stored and served but never surfaced (§5.6)")
	}
	var sources []domain.ReleaseSource
	if err := json.Unmarshal(resp.ReleaseProvenance, &sources); err != nil {
		t.Fatalf("release_provenance not the expected shape: %v (%s)", err, resp.ReleaseProvenance)
	}
	var sawContributed, sawAbstained bool
	for _, s := range sources {
		if s.Role == domain.ReleaseContributed {
			sawContributed = true
		}
		if s.Role == domain.ReleaseAbstained && s.Reason != "" {
			sawAbstained = true
		}
	}
	if !sawContributed || !sawAbstained {
		t.Errorf("release provenance must surface both a contributor and an abstention-with-reason: %+v", sources)
	}
}

// TestReadEndpointsRequireTheirPermission — a session with no read permission is
// refused on every read route, server-side. The UI reflects RBAC; this is the
// check that actually holds.
func TestReadEndpointsRequireTheirPermission(t *testing.T) {
	f := newFixture(t, `{"scan.read": true}`) // deliberately NOT asset.read / finding.read
	sf := f.seedFinding(t, false)
	cookies, csrf := f.login(t)

	for _, path := range []string{
		"/v1/assets",
		"/v1/assets/" + sf.assetID.String(),
		"/v1/findings",
		"/v1/findings/" + sf.findingID.String(),
		"/v1/exposure",
		"/v1/knowledge/freshness",
		"/v1/findings.csv",
		"/v1/assets.csv",
	} {
		w := f.do(t, http.MethodGet, path, nil, cookies, csrf)
		if w.Code != http.StatusForbidden {
			t.Errorf("GET %s without its permission gave %d, want 403", path, w.Code)
		}
	}
}

// TestReadEndpointsAreTenantIsolated — a finding id from tenant A is 404 under
// tenant B, even with finding.read. "No such row" and "another tenant's row"
// are one answer under RLS.
func TestReadEndpointsAreTenantIsolated(t *testing.T) {
	a := newFixture(t, `{"finding.read": true, "asset.read": true}`)
	b := newFixture(t, `{"finding.read": true, "asset.read": true}`)
	sf := a.seedFinding(t, false)
	cookiesB, csrfB := b.login(t)

	for _, path := range []string{
		"/v1/findings/" + sf.findingID.String(),
		"/v1/assets/" + sf.assetID.String(),
	} {
		w := b.do(t, http.MethodGet, path, nil, cookiesB, csrfB)
		if w.Code != http.StatusNotFound {
			t.Errorf("tenant B reading tenant A's %s gave %d, want 404: %s", path, w.Code, w.Body.String())
		}
	}
}

// TestFindingsCSVExportRefusesOverTheCap — note 2. An export over the cap is
// refused with 422, never truncated, so an incomplete file cannot pass for
// complete. Driven with a cap of 1 so the refusal is provable without seeding
// the production cap's worth of rows.
//
// mutate:subject internal/control/api/handlers_export.go
// mutate:test    ./internal/control/api/ -run TestFindingsCSVExport
//
// mutate:case    an over-cap CSV export is truncated rather than refused
// mutate:old     if got > cap {
// mutate:new     if false {
func TestFindingsCSVExportRefusesOverTheCap(t *testing.T) {
	f := newFixture(t, `{"finding.export_all": true}`)
	f.seedFinding(t, false)
	f.seedFinding(t, false) // two findings, cap of one

	srv := f.serverWithExportCap(t, 1)
	cookies, csrf := f.login(t)

	w := f.doOn(t, srv, http.MethodGet, "/v1/findings.csv", cookies, csrf)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("over-cap export gave %d, want 422 (refuse, never truncate): %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "narrow") {
		t.Errorf("the refusal should tell the caller to narrow the filter: %s", w.Body.String())
	}
}

// TestFindingsCSVExportWritesACompleteFile — the success path: within the cap,
// a real text/csv body with the header row and one data row per finding.
func TestFindingsCSVExportWritesACompleteFile(t *testing.T) {
	f := newFixture(t, `{"finding.export_all": true}`)
	f.seedFinding(t, false)
	f.seedFinding(t, false)
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodGet, "/v1/findings.csv", nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("csv export: %d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 3 { // header + two findings
		t.Fatalf("csv has %d lines, want 3 (header + 2 findings): %q", len(lines), w.Body.String())
	}
	if !strings.HasPrefix(lines[0], "finding_id,rule,category,severity,status") {
		t.Errorf("header row wrong: %q", lines[0])
	}
}

// serverWithExportCap builds a second server on the same DB with a lowered export
// cap. The session cookie is a DB row scoped to the tenant, so a login on the
// fixture's server is valid here too.
func (f *fixture) serverWithExportCap(t *testing.T, capRows int) *api.Server {
	t.Helper()
	srv, err := api.New(f.db, slog.New(slog.NewJSONHandler(io.Discard, nil)), api.Config{
		Version: "test", LocalAuthEnabled: true, Insecure: true,
		ListenAddr: "127.0.0.1:0", SessionTTL: time.Hour, ExportRowCap: capRows,
	})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func (f *fixture) doOn(t *testing.T, srv *api.Server, method, path string, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, nil)
	r.Host = f.domain
	for _, c := range cookies {
		r.AddCookie(c)
	}
	if csrf != "" {
		r.Header.Set(api.CSRFHeader, csrf)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)
	return w
}

// TestFindingsCSVNeutralisesFormulaInjection — a hostname is derived from what a
// scanned host volunteered, so it is attacker-influenceable; a value starting
// with = must not reach a spreadsheet as a live formula.
func TestFindingsCSVNeutralisesFormulaInjection(t *testing.T) {
	f := newFixture(t, `{"finding.export_all": true}`)
	err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		var ruleID uuid.UUID
		if err := c.QueryRow(ctx, `SELECT rule_id FROM rules WHERE engine='rules' ORDER BY name LIMIT 1`).Scan(&ruleID); err != nil {
			return err
		}
		asset, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "=cmd|' /c calc'!A1"})
		if err != nil {
			return err
		}
		_, _, err = (store.Findings{}).Upsert(ctx, c, store.Finding{
			AssetID: asset.ID, RuleID: ruleID, DedupKey: "dk-" + uuid.NewString(),
			Locator: "80/tcp", Severity: "low", Confidence: 0.5,
		}, time.Now().UTC())
		return err
	})
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	cookies, csrf := f.login(t)

	w := f.do(t, http.MethodGet, "/v1/findings.csv", nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("csv: %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if strings.Contains(body, ",=cmd") {
		t.Errorf("a raw =formula reached the CSV: %q", body)
	}
	if !strings.Contains(body, "'=cmd") {
		t.Errorf("the dangerous hostname was not neutralised with a leading apostrophe: %q", body)
	}
}

// TestScanPointsFleetListIsWorstFirst — the fleet health list surfaces the
// scan points an operator worries about (never-heard-from, then longest-silent)
// at the top, matching the route's contract. An ordering assertion so the SQL
// and the Description cannot drift apart again.
func TestScanPointsFleetListIsWorstFirst(t *testing.T) {
	f := newFixture(t, `{"scanpoint.read": true}`)
	now := time.Now().UTC()

	// Cert fingerprints are GLOBALLY unique, and the test DB persists across runs,
	// so they must be unique per invocation, not fixed strings.
	silentFP := "fp-" + uuid.NewString()
	var silent, stale, fresh uuid.UUID
	err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		mk := func(host string) (uuid.UUID, error) {
			sp, err := (store.ScanPoints{}).Create(ctx, c, f.zoneID, host, "0.1.0", "1", "fp-"+uuid.NewString())
			if err != nil {
				return uuid.Nil, err
			}
			return sp.ID, nil
		}
		var err error
		if sp, e := (store.ScanPoints{}).Create(ctx, c, f.zoneID, "silent", "0.1.0", "1", silentFP); e != nil {
			return e
		} else {
			silent = sp.ID // no heartbeat: NULL, worst
		}
		if stale, err = mk("stale"); err != nil {
			return err
		}
		if fresh, err = mk("fresh"); err != nil {
			return err
		}
		if err := (store.ScanPoints{}).Heartbeat(ctx, c, stale, now.Add(-time.Hour)); err != nil {
			return err
		}
		return (store.ScanPoints{}).Heartbeat(ctx, c, fresh, now)
	})
	if err != nil {
		t.Fatalf("seed scan points: %v", err)
	}

	cookies, csrf := f.login(t)
	w := f.do(t, http.MethodGet, "/v1/scan-points", nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("scan-points: %d %s", w.Code, w.Body.String())
	}
	var resp api.ScanPointListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.ScanPoints) != 3 {
		t.Fatalf("scan points = %d, want 3", len(resp.ScanPoints))
	}
	want := []uuid.UUID{silent, stale, fresh} // never-heard-from, then oldest, then newest
	for i, id := range want {
		if resp.ScanPoints[i].ID != id.String() {
			t.Errorf("position %d = %s, want %s — the fleet list must be worst-first by liveness",
				i, resp.ScanPoints[i].Hostname, id)
		}
	}
	// Certificate fingerprints must never be rendered.
	if strings.Contains(w.Body.String(), silentFP) {
		t.Error("a certificate fingerprint reached the fleet scan-point response")
	}
}

// TestAssetsCSVExport — the asset export path: within the cap, a text/csv body
// with the header and one row per asset, gated by asset.export_all.
func TestAssetsCSVExport(t *testing.T) {
	f := newFixture(t, `{"asset.export_all": true}`)
	if err := f.db.Write(context.Background(), f.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Assets{}).Create(ctx, c, store.Asset{Hostname: "a1.corp", Environment: "production"})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	cookies, csrf := f.login(t)
	w := f.do(t, http.MethodGet, "/v1/assets.csv", nil, cookies, csrf)
	if w.Code != http.StatusOK {
		t.Fatalf("assets csv: %d %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type = %q, want text/csv", ct)
	}
	lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "asset_id,hostname,os_family") {
		t.Errorf("assets csv shape wrong: %q", w.Body.String())
	}
}

// TestExportRequiresExportPermissionNotRead — the separate-permission decision:
// a session that may READ findings and assets still may not EXPORT them. Reading
// a row is triage; walking out with the whole set is a heavier authority.
func TestExportRequiresExportPermissionNotRead(t *testing.T) {
	f := newFixture(t, `{"finding.read": true, "asset.read": true}`)
	cookies, csrf := f.login(t)
	for _, path := range []string{"/v1/findings.csv", "/v1/assets.csv"} {
		w := f.do(t, http.MethodGet, path, nil, cookies, csrf)
		if w.Code != http.StatusForbidden {
			t.Errorf("GET %s with read-but-not-export gave %d, want 403 — export is a separate "+
				"permission from read", path, w.Code)
		}
	}
}

// TestSPACatchAllServesWithoutShadowingTheAPI — the UI catch-all serves app
// paths (ADR-053) and does NOT shadow /v1/*. Build-agnostic: with the UI
// embedded GET / is 200 HTML, without it 503 "not built" — either way the
// catch-all handled it (not a 404), and the API still routes.
func TestSPACatchAllServesWithoutShadowingTheAPI(t *testing.T) {
	f := newFixture(t, `{}`)

	for _, p := range []string{"/", "/findings/anything", "/assets"} {
		w := f.do(t, http.MethodGet, p, nil, nil, "")
		if w.Code == http.StatusNotFound {
			t.Errorf("GET %s was 404; the SPA catch-all should serve it", p)
		}
		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("GET %s content-type = %q, want text/html", p, ct)
		}
	}

	// The API is not shadowed by the catch-all.
	w := f.do(t, http.MethodGet, "/v1/openapi.json", nil, nil, "")
	if w.Code != http.StatusOK {
		t.Errorf("GET /v1/openapi.json = %d, want 200 (the catch-all must not shadow the API)", w.Code)
	}
}
