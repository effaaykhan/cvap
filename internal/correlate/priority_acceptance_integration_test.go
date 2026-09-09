package correlate_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// P3.4 acceptance (ADR-069): the finding set on a real host orders by PRIORITY,
// not severity — a KEV-listed CVE ranks above a higher-CVSS one that is not. This
// is the session's whole point, and it is demonstrated on findings the PIPELINE
// produces (ADR-070), not a fixture: the inversion is only meaningful on real
// advisory findings, which is why the acceptance waited for the advisory->finding
// path to exist.
//
// The pair is checked, not asserted. CVE-2012-2122 (Metasploitable's MySQL) is
// NOT in KEV (verified against the ingested feed: in_kev=f), so it does not show
// the inversion. The pair that does, both real on Metasploitable:
//
//	CVE-2012-1823  PHP-CGI arg injection   IN KEV,  EPSS 0.99998, CVSS 7.5
//	CVE-2007-2447  Samba usermap RCE       not KEV, EPSS 0.71,    CVSS 10.0
//
// The KEV PHP CVE (lower CVSS) must rank ABOVE the higher-CVSS non-KEV Samba CVE.
// KEV's 1e9 weight dominates the sum of every lower term, so the inversion is
// structural, not a matter of tuned weights.
//
// Seeds through cvap_knowledge_import (ADR-063), extending the release keyspace
// with the two CVEs' advisories, their KEV/EPSS signals, and the PHP product map.
// Idempotent, so it coexists with the dev DB's real feeds (where CVE-2012-1823 is
// already in KEV and both carry real EPSS) — the ordering is identical either way.
func seedPriorityKeyspace(t *testing.T) {
	t.Helper()
	seedReleaseKeyspace(t) // ssh/mysql/apache/samba/... keyspace + product map, for release resolution
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set; skipping priority acceptance (needs cvap_knowledge_import)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()

	for _, s := range []string{
		// CVSS on the two inversion CVEs (CVE-2012-2122 is seeded by the release
		// keyspace without a CVSS — it is not part of the inversion).
		`INSERT INTO vulnerability_defs (cve_id, title, cvss_base) VALUES
		   ('CVE-2012-1823','PHP-CGI query-string argument injection', 7.5),
		   ('CVE-2007-2447','Samba usermap script command execution', 10.0)
		 ON CONFLICT (cve_id) DO UPDATE SET cvss_base = excluded.cvss_base`,
		// A PHP advisory, and the CVE maps: TEST-PHP->CVE-2012-1823, and the
		// release keyspace's TEST-SAMBA now maps to CVE-2007-2447.
		`INSERT INTO vendor_advisories (advisory_ref, vendor) VALUES ('TEST-PHP','ubuntu')
		 ON CONFLICT (advisory_ref) DO NOTHING`,
		`INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
		 SELECT va.advisory_id, vd.vuln_def_id FROM vendor_advisories va, vulnerability_defs vd
		  WHERE (va.advisory_ref='TEST-PHP'   AND vd.cve_id='CVE-2012-1823')
		     OR (va.advisory_ref='TEST-SAMBA' AND vd.cve_id='CVE-2007-2447')
		 ON CONFLICT DO NOTHING`,
		// PHP's fixed version on hardy, above Metasploitable's 5.2.4 (dpkg: an empty
		// revision sorts below any, so 5.2.4 < 5.2.4-2ubuntu5.12 -> affected).
		`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
		 SELECT va.advisory_id, 'hardy', 'php5', '5.2.4-2ubuntu5.12', 'dpkg'::version_comparator
		   FROM vendor_advisories va WHERE va.advisory_ref='TEST-PHP'
		 ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING`,
		`INSERT INTO product_packages (product, package_name) VALUES ('PHP','php5')
		 ON CONFLICT DO NOTHING`,
		// KEV: only the PHP CVE — the driver of the inversion. Samba is deliberately
		// absent from KEV (unlisted, not known-unexploited — ADR-069's absence rule).
		`INSERT INTO kev (cve_id, date_added, known_ransomware, source, last_fetched_at)
		 VALUES ('CVE-2012-1823','2022-05-25', false, 'PHP Group', now())
		 ON CONFLICT (cve_id) DO UPDATE SET last_fetched_at = excluded.last_fetched_at`,
		`INSERT INTO epss (cve_id, score, percentile, scored_at, last_fetched_at) VALUES
		   ('CVE-2012-1823', 0.99998, 0.99999, current_date, now()),
		   ('CVE-2007-2447', 0.71000, 0.94000, current_date, now())
		 ON CONFLICT (cve_id) DO UPDATE SET score = excluded.score, last_fetched_at = excluded.last_fetched_at`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed priority keyspace: %v\nSQL: %s", err, s)
		}
	}
}

func TestFindingSetOrdersByPriorityOnMetasploitable(t *testing.T) {
	db := testDB(t)
	seedPriorityKeyspace(t)
	s := seed(t, db, "priority")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	now := time.Now().UTC()

	// SSH + MySQL resolve the release (hardy, ADR-065); PHP and Samba are the two
	// services whose advisory findings carry the inversion pair.
	ssh := sshService("10.0.0.9", 22, "SHA256:metasploitable-priority")
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
	s.observe(t, db, now, svc(3306, "mysql", "MySQL", "5.0.51a-3ubuntu5"))
	s.observe(t, db, now, svc(80, "http", "PHP", "5.2.4"))             // -> php5 -> CVE-2012-1823 (KEV)
	s.observe(t, db, now, svc(445, "microsoft-ds", "Samba", "3.0.20")) // -> samba -> CVE-2007-2447 (not KEV, CVSS 10.0)

	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// Read the finding set the way the operator API does: priority-ordered, scoped
	// to this asset. This is Findings.List's own order, not a re-sort in the test.
	var page *store.FindingPage
	cveOf := map[uuid.UUID]string{}
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		var assetID uuid.UUID
		if err := cn.QueryRow(ctx, `SELECT asset_id FROM assets WHERE tenant_id=$1 LIMIT 1`,
			s.tenant.UUID()).Scan(&assetID); err != nil {
			return err
		}
		p, err := (store.Findings{}).List(ctx, cn, store.FindingListFilter{AssetID: assetID}, 0, uuid.Nil, 200)
		if err != nil {
			return err
		}
		page = p
		// Map each listed finding to its CVE (List does not carry the cve_id).
		rows, err := cn.Query(ctx, `
			SELECT f.finding_id, vd.cve_id FROM findings f
			  JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
			 WHERE f.tenant_id=$1 AND f.asset_id=$2`, s.tenant.UUID(), assetID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			var cve string
			if err := rows.Scan(&id, &cve); err != nil {
				return err
			}
			cveOf[id] = cve
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("read priority-ordered findings: %v", err)
	}

	// Locate the two findings and their rank in the priority order.
	var php, samba *store.FindingSummary
	phpRank, sambaRank := -1, -1
	for i := range page.Findings {
		switch cveOf[page.Findings[i].ID] {
		case "CVE-2012-1823":
			php, phpRank = &page.Findings[i], i
		case "CVE-2007-2447":
			samba, sambaRank = &page.Findings[i], i
		}
	}
	if php == nil || samba == nil {
		t.Fatalf("pipeline did not produce both findings: php=%v samba=%v (cves=%v)", php != nil, samba != nil, cveOf)
	}

	// THE INVERSION: the KEV PHP CVE ranks ABOVE the higher-CVSS non-KEV Samba CVE.
	if phpRank >= sambaRank {
		t.Fatalf("KEV CVE-2012-1823 ranked at %d, non-KEV higher-CVSS CVE-2007-2447 at %d — the inversion FAILED",
			phpRank, sambaRank)
	}
	// And it wins because it is KEV, not because its CVSS is higher — it is NOT.
	if php.CVSS == nil || samba.CVSS == nil || *samba.CVSS <= *php.CVSS {
		t.Fatalf("the inversion is only meaningful if the loser's CVSS is genuinely higher: php=%v samba=%v", php.CVSS, samba.CVSS)
	}
	if !php.KEV {
		t.Errorf("CVE-2012-1823 should be KEV-listed")
	}
	if samba.KEV {
		t.Errorf("CVE-2007-2447 is not in KEV and must not read as KEV-listed (unlisted != unexploited)")
	}
	// KEV dominance is structural: the KEV finding is over the 1e9 boundary, the
	// non-KEV one below it, regardless of CVSS or EPSS.
	if php.PriorityScore < 1_000_000_000 {
		t.Errorf("KEV finding priority_score %d should clear the 1e9 KEV boundary", php.PriorityScore)
	}
	if samba.PriorityScore >= 1_000_000_000 {
		t.Errorf("non-KEV finding priority_score %d must be below the 1e9 KEV boundary", samba.PriorityScore)
	}
	t.Logf("inversion: CVE-2012-1823 (KEV, CVSS %.1f, score %d) @rank %d ABOVE CVE-2007-2447 (non-KEV, CVSS %.1f, score %d) @rank %d",
		*php.CVSS, php.PriorityScore, phpRank, *samba.CVSS, samba.PriorityScore, sambaRank)
}
