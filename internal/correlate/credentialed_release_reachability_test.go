package correlate_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// observePackage writes one accepted `package` observation, the way the credentialed
// host engine's ingest would — the type the release-precedence rule reads.
func (s seeded) observePackage(t *testing.T, db *store.DB, at time.Time, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	conf := 1.0
	o := store.Observation{
		ID: uuid.New(), SubmissionID: s.subID, TaskID: s.taskID, ScanPointID: s.spID,
		ZoneID: s.zoneID, Type: store.ObsPackage, Payload: body,
		Confidence: &conf, ObservedAt: at,
	}
	if err := db.Write(context.Background(), s.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Observations{}).Insert(ctx, c, o, store.IngestAccepted)
	}); err != nil {
		t.Fatalf("insert package observation: %v", err)
	}
}

// TestCredentialedReleaseReachesResolutionWithoutInferredFamily is the ADR-089
// reachability proof, and it is deliberately an integration test, not a unit one.
// release_precedence_test.go proves credentialedAttribution READS the payload right;
// this proves the correlator REACHES it — the distinction ADR-089 turns on, and the
// [[dormant-rule-behind-a-gate]] lesson: a passing unit test is not proof the rule
// runs in the system.
//
// The host offers an SSH service (so an asset is created and identified) that yields
// NO OS family hint, plus a credentialed `package` observation. So the service-
// inferred family is "" — under the pre-ADR-089 code, `deriveRelease` sat behind an
// `if family != ""` gate and was skipped entirely, leaving the release NULL. The fix
// resolves family AND release from the exact /etc/os-release read, at confidence 1.0,
// with no dependence on the inferred family. That is the exact live failure measured
// on .146 (release stuck at the band vote because the package-only sweep had no
// family), now pinned so it cannot regress.
func TestCredentialedReleaseReachesResolutionWithoutInferredFamily(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "credreach")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	now := time.Now().UTC()

	// A service that identifies the host but carries no `os` hint: family stays "".
	ssh := sshService("10.0.0.9", 22, "SHA256:credreach-hostkey")
	s.observe(t, db, now, ssh)

	// The credentialed inventory: exact family + release read from /etc/os-release.
	s.observePackage(t, db, now, map[string]any{
		"address":        "10.0.0.9",
		"family":         "ubuntu",
		"release":        "jammy",
		"release_source": "os-release",
		"installed":      []map[string]any{{"name": "openssh-server", "version": "1:8.9p1-3"}},
	})

	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	var family string
	var release *string
	var relConf *float64
	var relProv, osProv []byte
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT coalesce(distro_family,''), distro_release, release_confidence,
		        release_provenance, os_provenance
		    FROM assets WHERE tenant_id=$1 LIMIT 1`, s.tenant.UUID()).Scan(&family, &release, &relConf, &relProv, &osProv)
	}); err != nil {
		t.Fatal(err)
	}

	// Family resolved from the exact read, NOT from any service hint (there was none).
	if family != "ubuntu" {
		t.Fatalf("distro_family = %q, want ubuntu (from /etc/os-release, no service hint present)", family)
	}
	// Release resolved even though the service-inferred family was empty — the gate
	// that made ADR-077 unreachable is gone.
	if release == nil || *release != "jammy" {
		t.Fatalf("distro_release = %v, want jammy (exact os-release, reached without inferred family)", release)
	}
	if relConf == nil || *relConf != 1.0 {
		t.Errorf("release_confidence = %v, want 1.0 (ground truth outranks the band vote — ADR-089)", relConf)
	}

	// Provenance names the exact source on both columns, so an operator sees it was
	// read, not inferred.
	assertProvSource(t, "release_provenance", relProv, "package_manager")
	assertProvSource(t, "os_provenance", osProv, "os-release")
}

func assertProvSource(t *testing.T, label string, prov []byte, want string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(prov, &m); err != nil {
		t.Errorf("%s not an object: %v (%s)", label, err, prov)
		return
	}
	if got, _ := m["source"].(string); got != want {
		t.Errorf("%s source = %q, want %q (%s)", label, got, want, prov)
	}
}

// TestAnInferredSweepNeverOverwritesAnExactAttribution is ADR-095's proof, and it
// is an integration test for the reason ADR-090's is: the clobber was measured on
// the deploy estate, not in a unit — the first fingerprint sweep after the
// credentialed run put .138 and .146 back to a 0.9 band vote, and every later
// sweep would have kept doing it. Provenance ranks regardless of recency: a band
// vote fills an absence and never overwrites an exact read; an exact read is
// superseded only by a later exact read; and the exact attribution carries the
// time it was read, so an operator sees its age rather than a silent reversion.
func TestAnInferredSweepNeverOverwritesAnExactAttribution(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "rank")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	first := time.Now().UTC().Add(-2 * time.Hour)

	var osConf float64
	read := func() (family, release string, relConf float64, relProv, osProv []byte) {
		t.Helper()
		var rel *string
		if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
			return cn.QueryRow(ctx, `SELECT coalesce(distro_family,''), distro_release, coalesce(release_confidence,0),
			        coalesce(os_confidence,0), release_provenance, os_provenance
			   FROM assets WHERE tenant_id=$1 ORDER BY first_seen LIMIT 1`,
				s.tenant.UUID()).Scan(&family, &rel, &relConf, &osConf, &relProv, &osProv)
		}); err != nil {
			t.Fatal(err)
		}
		if rel != nil {
			release = *rel
		}
		return
	}

	// Sweep 1: the credentialed read. Exact family and release at 1.0.
	s.observe(t, db, first, sshService("10.0.0.19", 22, "SHA256:rank-hostkey"))
	s.observePackage(t, db, first, map[string]any{
		"address": "10.0.0.19", "family": "ubuntu", "release": "jammy", "release_source": "os-release",
		"installed": []map[string]any{{"name": "openssh-server", "version": "1:8.9p1-3"}},
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if fam, rel, conf, _, _ := read(); fam != "ubuntu" || rel != "jammy" || conf != 1.0 {
		t.Fatalf("after the credentialed read: family=%q release=%q conf=%v, want ubuntu/jammy/1.0", fam, rel, conf)
	}

	// Sweep 2: a fingerprint pass whose banners carry a family hint and vote for
	// a release band — the inferred path, on a LATER scan. It must not touch
	// the exact attribution.
	s.nextScan(t, db)
	later := first.Add(time.Hour)
	s.observe(t, db, later, map[string]any{
		"address": "10.0.0.19", "port": 22, "protocol": "tcp", "service": "ssh",
		"product": "OpenSSH", "version": "8.9p1", "method": "banner", "solicited": true, "safety_mode": "intrusive",
		"os": map[string]any{"hint": "Debian", "confidence": 0.9},
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	fam, rel, conf, relProv, osProv := read()
	if fam != "ubuntu" || rel != "jammy" || conf != 1.0 || osConf != 1.0 {
		t.Fatalf("after a later inferred sweep: family=%q release=%q relConf=%v osConf=%v, want the exact ubuntu/jammy/1.0/1.0 kept", fam, rel, conf, osConf)
	}
	assertProvSource(t, "release_provenance", relProv, "package_manager")
	assertProvSource(t, "os_provenance", osProv, "os-release")
	for label, prov := range map[string][]byte{"release_provenance": relProv, "os_provenance": osProv} {
		var m map[string]any
		if err := json.Unmarshal(prov, &m); err != nil || m["read_at"] == nil {
			t.Fatalf("%s carries no read_at (%s): the exact attribution's age must be visible", label, prov)
		}
	}

	// Sweep 3: a later exact read with a different release supersedes the exact one.
	s.nextScan(t, db)
	s.observePackage(t, db, later.Add(time.Hour), map[string]any{
		"address": "10.0.0.19", "family": "ubuntu", "release": "noble", "release_source": "os-release",
		"installed": []map[string]any{{"name": "openssh-server", "version": "1:9.6p1-3"}},
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, rel, conf, _, _ := read(); rel != "noble" || conf != 1.0 {
		t.Fatalf("after a later exact read: release=%q conf=%v, want noble/1.0 (exact supersedes exact)", rel, conf)
	}
}

// TestAdvisoriesMatchAgainstTheHeldReleaseNotTheRefusedVote pins ADR-095 §4: the
// review measured the first cut refusing the band vote at the column and then
// matching advisories against it in the same transaction — a hardy-only CVE on a
// host held at jammy. Needs the knowledge role to seed the keyspace, like the
// other release-acceptance suites.
func TestAdvisoriesMatchAgainstTheHeldReleaseNotTheRefusedVote(t *testing.T) {
	db := testDB(t)
	seedReleaseKeyspace(t)
	s := seed(t, db, "heldrel")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	first := time.Now().UTC().Add(-2 * time.Hour)

	// Credentialed read: jammy, which has no rows in the seeded keyspace.
	s.observe(t, db, first, sshService("10.0.0.29", 22, "SHA256:heldrel-hostkey"))
	s.observePackage(t, db, first, map[string]any{
		"address": "10.0.0.29", "family": "ubuntu", "release": "jammy", "release_source": "os-release",
		"installed": []map[string]any{{"name": "openssh-server", "version": "1:8.9p1-3"}},
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// A later inferred sweep whose MySQL banner band-votes HARDY, where
	// USN-1467-1 fixes mysql-dfsg-5.0 above 5.0.51a: under hardy this raises
	// CVE-2012-2122; under the held jammy there is nothing to match.
	s.nextScan(t, db)
	s.observe(t, db, first.Add(time.Hour), map[string]any{
		"address": "10.0.0.29", "port": 3306, "protocol": "tcp", "service": "mysql",
		"product": "MySQL", "version": "5.0.51a-3ubuntu5", "method": "banner", "solicited": true, "safety_mode": "intrusive",
		"os": map[string]any{"hint": "Ubuntu", "confidence": 0.9},
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// The claim is about the hardy-only CVE specifically: the shared keyspace
	// may hold jammy rows other suites seeded, so a bare count is not the test.
	var hardyOnly int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT count(*) FROM findings f JOIN vulnerability_defs v ON v.vuln_def_id = f.vuln_def_id
		   WHERE f.tenant_id = $1 AND v.cve_id = 'CVE-2012-2122'`, s.tenant.UUID()).Scan(&hardyOnly)
	}); err != nil {
		t.Fatal(err)
	}
	if hardyOnly != 0 {
		t.Fatalf("CVE-2012-2122 (hardy-only) raised on a host held at jammy; the refused hardy vote must not key the keyspace")
	}
}

// The positive half of ADR-095 §4: a sweep that resolves no release of its own
// — a fingerprint pass with banners but no family hint — now matches its banner
// versions against the exact release a credentialed pass established, and the
// finding composes at the BANNER's confidence, not the exact release's 1.0.
func TestABannerSweepMatchesAgainstTheHeldExactReleaseBelowFullConfidence(t *testing.T) {
	db := testDB(t)
	seedReleaseKeyspace(t)
	seedJammyOpenSSH(t)
	s := seed(t, db, "heldpos")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	first := time.Now().UTC().Add(-2 * time.Hour)

	// Credentialed read: jammy, exact. The banner in this sweep is ABOVE the
	// jammy fix, so this sweep raises nothing; the finding must come from the
	// banner-only sweep below.
	ssh := sshService("10.0.0.39", 22, "SHA256:heldpos-hostkey")
	ssh["version"] = "1:9.9p1-1"
	s.observe(t, db, first, ssh)
	s.observePackage(t, db, first, map[string]any{
		"address": "10.0.0.39", "family": "ubuntu", "release": "jammy", "release_source": "os-release",
		"installed": []map[string]any{{"name": "openssh-server", "version": "1:8.9p1-3"}},
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// A later banner-only sweep, no family hint, so it resolves nothing itself:
	// OpenSSH 8.9p1 is below jammy's seeded fix, and the banner carries 0.95.
	s.nextScan(t, db)
	s.observe(t, db, first.Add(time.Hour), map[string]any{
		"address": "10.0.0.39", "port": 22, "protocol": "tcp", "service": "ssh",
		"product": "OpenSSH", "version": "1:8.9p1-3", "method": "banner", "solicited": true, "safety_mode": "intrusive",
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	var conf float64
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT count(*), coalesce(max(f.confidence),0) FROM findings f JOIN vulnerability_defs v ON v.vuln_def_id = f.vuln_def_id
		   WHERE f.tenant_id = $1 AND v.cve_id = 'CVE-2023-0001' AND f.source = 'network'`, s.tenant.UUID()).Scan(&n, &conf)
	}); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("%d network findings for the jammy-only CVE after a banner sweep against a held exact release, want 1: the held release must key the match", n)
	}
	if conf > 0.96 || conf < 0.94 {
		t.Fatalf("finding confidence = %.2f, want the banner's 0.95: an exact release does not make a banner version an exact claim", conf)
	}
}

// seedJammyOpenSSH adds one jammy row to the seeded keyspace (a fix above
// 8.9p1), through the knowledge role like seedReleaseKeyspace.
func seedJammyOpenSSH(t *testing.T) {
	t.Helper()
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()
	for _, q := range []string{
		`INSERT INTO vendor_advisories (advisory_ref, vendor) VALUES ('TEST-SSH-JAMMY','ubuntu') ON CONFLICT (advisory_ref) DO NOTHING`,
		`INSERT INTO vulnerability_defs (cve_id, title) VALUES ('CVE-2023-0001','CVE-2023-0001') ON CONFLICT (cve_id) DO NOTHING`,
		`INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
		 SELECT va.advisory_id, vd.vuln_def_id FROM vendor_advisories va, vulnerability_defs vd
		  WHERE va.advisory_ref='TEST-SSH-JAMMY' AND vd.cve_id='CVE-2023-0001' ON CONFLICT DO NOTHING`,
		`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
		 SELECT va.advisory_id, 'jammy', 'openssh', '1:8.9p1-3ubuntu0.6', 'dpkg'::version_comparator
		   FROM vendor_advisories va WHERE va.advisory_ref='TEST-SSH-JAMMY'
		 ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed jammy openssh: %v", err)
		}
	}
}
