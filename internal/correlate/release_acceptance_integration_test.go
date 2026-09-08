package correlate_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/version"
)

// P3.3 acceptance (ADR-064): a real host resolves to a real release, promoted to
// the asset, and the FULL chain runs — family + release -> P3.2 advisory match ->
// a CVE-backed vulnerability verdict. This is the first time family, release,
// comparator and advisory data meet on one machine.
//
// The observed versions are Metasploitable's (Ubuntu 8.04 "hardy"): OpenSSH
// 4.7p1, MySQL 5.0.51a-3ubuntu5, Apache 2.2.8 band-match hardy and agree; Samba
// 3.0.20 (older than any band) and vsftpd 2.3.4 (the backdoored build) match no
// release and abstain; ProFTPD has no advisory analogue and abstains.
//
// This is a RESOLVER-LOGIC test with a controlled observed set — it exercises the
// vote / abstain / dissent paths. It is NOT a claim about what the corpus
// identifies in safe mode: that is measured separately in scanpoint's
// TestMetasploitableVersionCoverageMeasured, which finds only four
// version-yielding services (Apache and Samba are not among them in safe mode).
// So a real safe-mode scan resolves hardy on TWO votes (openssh, mysql), still
// past the threshold; this test uses three to also cover the agreeing-plurality
// path. The gap is B28 (service ID), recorded honestly in ADR-065. The keyspace
// is seeded from the REAL fixed versions measured in session 30 (idempotent, so it
// coexists with the full real keyspace a dev DB already holds); the resolution is
// identical either way because the bands are the same. Skips without the import
// role, the same contract as the other knowledge-backed suites.
func seedReleaseKeyspace(t *testing.T) {
	t.Helper()
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set; skipping release-resolution acceptance (needs cvap_knowledge_import)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()

	stmts := []string{
		`INSERT INTO vendor_advisories (advisory_ref, vendor) VALUES
		   ('USN-1467-1','ubuntu'),('TEST-MYSQL-BASE','ubuntu'),('TEST-SSH','ubuntu'),
		   ('TEST-APACHE','ubuntu'),('TEST-SAMBA','ubuntu'),('TEST-VSFTPD','ubuntu')
		 ON CONFLICT (advisory_ref) DO NOTHING`,
		`INSERT INTO vulnerability_defs (cve_id, title) VALUES ('CVE-2012-2122','CVE-2012-2122')
		 ON CONFLICT (cve_id) DO NOTHING`,
		`INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
		 SELECT va.advisory_id, vd.vuln_def_id FROM vendor_advisories va, vulnerability_defs vd
		  WHERE va.advisory_ref='USN-1467-1' AND vd.cve_id='CVE-2012-2122' ON CONFLICT DO NOTHING`,
		// Fixed packages: hardy's band is unique per package; neighbours share none.
		`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
		 SELECT va.advisory_id, x.r, x.p, x.v, 'dpkg'::version_comparator
		   FROM vendor_advisories va
		   JOIN (VALUES
		     ('USN-1467-1','hardy','mysql-dfsg-5.0','5.0.96-0ubuntu3'),
		     ('TEST-MYSQL-BASE','hardy','mysql-dfsg-5.0','5.0.51a-3ubuntu5.4'),
		     ('TEST-MYSQL-BASE','dapper','mysql-dfsg-5.0','5.0.22-0ubuntu6.06.11'),
		     ('TEST-MYSQL-BASE','intrepid','mysql-dfsg-5.0','5.0.67-0ubuntu6.1'),
		     ('TEST-SSH','hardy','openssh','1:4.7p1-8ubuntu1.1'),
		     ('TEST-SSH','gutsy','openssh','1:4.6p1-5ubuntu0.3'),
		     ('TEST-SSH','feisty','openssh','1:4.3p2-8ubuntu1.3'),
		     ('TEST-APACHE','hardy','apache2','2.2.8-1ubuntu0.5'),
		     ('TEST-APACHE','intrepid','apache2','2.2.9-7ubuntu3.1'),
		     ('TEST-APACHE','lucid','apache2','2.2.14-5ubuntu8.2'),
		     ('TEST-SAMBA','hardy','samba','3.0.28a-1ubuntu4.2'),
		     ('TEST-SAMBA','dapper','samba','3.0.22-1ubuntu3.7'),
		     ('TEST-VSFTPD','hardy','vsftpd','2.0.6-1ubuntu1.2'),
		     ('TEST-VSFTPD','maverick','vsftpd','2.3.0~pre2-4ubuntu2.2')
		   ) AS x(ref,r,p,v) ON va.advisory_ref = x.ref
		 ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING`,
		// The product map: ProFTPD maps to a package with NO advisory rows, so it
		// abstains as no-analogue — distinct from the band-mismatch abstentions.
		`INSERT INTO product_packages (product, package_name) VALUES
		   ('OpenSSH','openssh'),('MySQL','mysql-dfsg-5.0'),('Apache','apache2'),
		   ('Samba','samba'),('vsftpd','vsftpd'),('ProFTPD','proftpd-dfsg')
		 ON CONFLICT DO NOTHING`,
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed keyspace: %v\nSQL: %s", err, s)
		}
	}
}

func TestReleaseResolvesEndToEndOnMetasploitable(t *testing.T) {
	db := testDB(t)
	seedReleaseKeyspace(t)
	s := seed(t, db, "release")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	now := time.Now().UTC()

	// One host, six services. SSH carries the Ubuntu family hint (so a family is
	// known and release resolution runs) and the OpenSSH version band.
	ssh := sshService("10.0.0.9", 22, "SHA256:metasploitable-hostkey")
	ssh["version"] = "4.7p1"
	ssh["os"] = map[string]any{"hint": "Ubuntu", "source": "service banner"}
	s.observe(t, db, now, ssh)

	svc := func(port int, service, product, ver string) map[string]any {
		return map[string]any{
			"address": "10.0.0.9", "port": port, "protocol": "tcp",
			"service": service, "product": product, "version": ver,
			"method": "banner", "solicited": true, "safety_mode": "intrusive",
		}
	}
	s.observe(t, db, now, svc(3306, "mysql", "MySQL", "5.0.51a-3ubuntu5")) // band 5.0.51a -> hardy
	// The SAME endpoint seen a second time (a rescan): it must cast ONE vote, not
	// two — otherwise a duplicated observation crosses the threshold on its own.
	s.observe(t, db, now.Add(time.Second), svc(3306, "mysql", "MySQL", "5.0.51a-3ubuntu5"))
	s.observe(t, db, now, svc(80, "http", "Apache", "2.2.8"))          // band 2.2.8   -> hardy
	s.observe(t, db, now, svc(445, "microsoft-ds", "Samba", "3.0.20")) // band matches nothing -> abstain
	s.observe(t, db, now, svc(21, "ftp", "vsftpd", "2.3.4"))           // backdoored build -> abstain
	s.observe(t, db, now, svc(2121, "ftp", "ProFTPD", "1.3.1"))        // no analogue -> abstain

	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// --- The release landed on the asset ---
	var family string
	var release *string
	var relConf *float64
	var prov []byte
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT coalesce(distro_family,''), distro_release, release_confidence, release_provenance
		    FROM assets WHERE tenant_id=$1 LIMIT 1`, s.tenant.UUID()).Scan(&family, &release, &relConf, &prov)
	}); err != nil {
		t.Fatal(err)
	}
	if family == "" {
		t.Fatalf("family not resolved; release resolution should not have run")
	}
	if release == nil || *release != "hardy" {
		t.Fatalf("distro_release = %v, want hardy (3 agreeing band votes)", release)
	}
	if relConf == nil || *relConf < 0.89 || *relConf > 0.91 {
		t.Errorf("release_confidence = %v, want ~0.90 (3 agreeing, unanimous — ADR-064)", relConf)
	}

	// --- The provenance shows who voted, agreed and abstained, and WHY ---
	var sources []domain.ReleaseSource
	if err := json.Unmarshal(prov, &sources); err != nil {
		t.Fatalf("release provenance not the expected shape: %v (%s)", err, prov)
	}
	role := map[string]domain.ReleaseRole{}
	reason := map[string]string{}
	voteCount := map[domain.ReleaseRole]int{}
	for _, s := range sources {
		role[s.Product] = s.Role
		reason[s.Product] = s.Reason
		voteCount[s.Role]++
	}
	for _, p := range []string{"OpenSSH", "MySQL", "Apache"} {
		if role[p] != domain.ReleaseContributed {
			t.Errorf("%s should be 'contributed', got %q", p, role[p])
		}
	}
	if role["Samba"] != domain.ReleaseAbstained || reason["Samba"] == "" {
		t.Errorf("Samba (band mismatch) should abstain with a reason, got role=%q reason=%q", role["Samba"], reason["Samba"])
	}
	if role["vsftpd"] != domain.ReleaseAbstained {
		t.Errorf("vsftpd (band mismatch) should abstain, got %q", role["vsftpd"])
	}
	if role["ProFTPD"] != domain.ReleaseAbstained {
		t.Errorf("ProFTPD (no analogue) should abstain, got %q", role["ProFTPD"])
	}
	// Absence is not evidence: the two abstention KINDS carry different reasons.
	if reason["Samba"] == reason["ProFTPD"] {
		t.Errorf("band-mismatch and no-analogue abstentions must differ; both were %q", reason["ProFTPD"])
	}
	if voteCount[domain.ReleaseContributed] != 3 {
		t.Errorf("want 3 contributing votes, got %d", voteCount[domain.ReleaseContributed])
	}
	t.Logf("in situ: family=%s release=%s conf=%.2f | contributed=%d abstained=%d",
		family, *release, *relConf, voteCount[domain.ReleaseContributed], voteCount[domain.ReleaseAbstained])

	// --- The full chain: resolved release -> P3.2 advisory match -> CVE verdict ---
	const installedMySQL = "5.0.51a-3ubuntu5" // the measured host version
	var fixes []store.AdvisoryFix
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		var e error
		fixes, e = (store.Advisories{}).FixesFor(ctx, cn, *release, "mysql-dfsg-5.0")
		return e
	}); err != nil {
		t.Fatalf("FixesFor: %v", err)
	}
	var vulnerable bool
	var matchedRef, matchedFix string
	for _, f := range fixes {
		if f.AdvisoryRef != "USN-1467-1" {
			continue
		}
		scheme, ok := version.SchemeByName(f.Comparator)
		if !ok {
			t.Fatalf("unknown comparator %q", f.Comparator)
		}
		if (version.AffectedRange{Fixed: f.FixedVersion}).Vulnerable(scheme, installedMySQL) {
			vulnerable, matchedRef, matchedFix = true, f.AdvisoryRef, f.FixedVersion
		}
	}
	if !vulnerable {
		t.Fatalf("the resolved release did not produce the expected CVE match against %s", installedMySQL)
	}
	t.Logf("full chain: release %s -> %s fixed %s vs installed %s -> vulnerable (CVE-2012-2122)",
		*release, matchedRef, matchedFix, installedMySQL)
}
