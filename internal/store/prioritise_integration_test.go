package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/store"
)

// P3.4 acceptance (ADR-069): the finding set orders by PRIORITY, not severity —
// a KEV-listed CVE ranks above a higher-CVSS one that is not. This is the whole
// point of the session: the inversion the finding list has never had.
//
// The demonstration is Metasploitable's own CVEs. CVE-2012-2122 (its MySQL) is
// NOT in KEV, so it does not show the inversion — checked, and it is not the
// case. CVE-2012-1823 (PHP-CGI) IS in KEV at CVSS ~7.5; CVE-2007-2447 (Samba
// usermap RCE) is NOT in KEV but is CVSS 10.0. The model must rank the KEV PHP
// CVE above the higher-CVSS non-KEV Samba CVE. Both are real on Metasploitable.
//
// Two more CVEs exercise "absence is not evidence" (ADR-069, fifth application):
// one with a CVSS but no EPSS row (unscored ≠ 0 — ranked by the CVSS we know,
// COALESCE(epss, cvss/10)), and one with neither (genuinely no-signal, flagged
// 'unscored', sinks to the severity tiebreak).
//
// The knowledge rows (vulnerability_defs, kev, epss) are global and written only
// by cvap_knowledge_import (ADR-063), so they are seeded through that role like
// seedCoverage does; idempotent so it coexists with the dev DB's real import.
// Deliberately, CVE-2012-1823's vulnerability_defs.in_kev stays false and its
// epss_score column stays null: the model reads the freshness-tracked kev/epss
// FEED tables (ADR-069), never those static 0010 columns, and this proves it.
const (
	cvePHPKev   = "CVE-2012-1823" // KEV, CVSS 7.5 — the KEV finding that must win
	cveSambaHi  = "CVE-2007-2447" // non-KEV, CVSS 10.0 — the higher-CVSS loser
	cveNoEPSS   = "CVE-2099-0001" // CVSS 5.0, no EPSS row — unscored ≠ 0
	cveUnscored = "CVE-2099-0002" // no CVSS, no EPSS, no KEV — genuinely no-signal
)

func seedRiskFeeds(t *testing.T) {
	t.Helper()
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
		// vulnerability_defs — in_kev/epss_score left at their defaults on purpose.
		`INSERT INTO vulnerability_defs (cve_id, title, cvss_base) VALUES
		   ('CVE-2012-1823','PHP-CGI query-string argument injection', 7.5),
		   ('CVE-2007-2447','Samba usermap script command execution', 10.0),
		   ('CVE-2099-0001','Test: scored by CVSS, unscored by EPSS', 5.0),
		   ('CVE-2099-0002','Test: no CVSS, no EPSS, no KEV', NULL)
		 ON CONFLICT (cve_id) DO UPDATE SET cvss_base = excluded.cvss_base`,
		// KEV — only the PHP CVE. The Samba CVE is deliberately absent (unlisted).
		`INSERT INTO kev (cve_id, date_added, known_ransomware, source, last_fetched_at)
		 VALUES ('CVE-2012-1823','2022-05-25', false, 'PHP Group', now())
		 ON CONFLICT (cve_id) DO UPDATE SET last_fetched_at = excluded.last_fetched_at`,
		// EPSS — the PHP CVE near-certain, the Samba CVE lower, the NoEPSS CVE absent.
		`INSERT INTO epss (cve_id, score, percentile, scored_at, last_fetched_at) VALUES
		   ('CVE-2012-1823', 0.99998, 0.99999, current_date, now()),
		   ('CVE-2007-2447', 0.71000, 0.94000, current_date, now())
		 ON CONFLICT (cve_id) DO UPDATE SET score = excluded.score, last_fetched_at = excluded.last_fetched_at`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed risk feeds: %v", err)
		}
	}
}

func TestFindingSetOrdersByPriorityNotSeverity(t *testing.T) {
	db := testDB(t)
	seedRiskFeeds(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "prio-"+uuid.NewString()[:8])

	// One asset, four findings on it — all the SAME severity, so severity cannot
	// be the discriminator and the priority signals are what order them.
	var page *store.FindingPage
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var ruleID uuid.UUID
		if err := c.QueryRow(ctx, `SELECT rule_id FROM rules WHERE engine='rules' ORDER BY name LIMIT 1`).
			Scan(&ruleID); err != nil {
			return err
		}
		asset, err := (store.Assets{}).Create(ctx, c, store.Asset{
			Hostname: "metasploitable-" + uuid.NewString()[:8] + ".lab", Environment: "production",
		})
		if err != nil {
			return err
		}
		for _, cve := range []string{cvePHPKev, cveSambaHi, cveNoEPSS, cveUnscored} {
			id, _, err := (store.Findings{}).Upsert(ctx, c, store.Finding{
				AssetID: asset.ID, RuleID: ruleID, DedupKey: "dk-" + uuid.NewString(),
				Locator: "80/tcp", Severity: "medium", Confidence: 0.9,
			}, time.Now().UTC())
			if err != nil {
				return err
			}
			// Attach the CVE. The advisory→finding link is not wired yet (a P3.3
			// remainder, ADR-069); the acceptance seeds it, as the ADR says.
			if _, err := c.Exec(ctx,
				`UPDATE findings SET vuln_def_id = (SELECT vuln_def_id FROM vulnerability_defs WHERE cve_id=$2)
				  WHERE tenant_id = current_setting('app.tenant_id')::uuid AND finding_id = $1`,
				id, cve); err != nil {
				return err
			}
		}
		return err
	}); err != nil {
		t.Fatalf("seed findings: %v", err)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var e error
		page, e = (store.Findings{}).List(ctx, c, store.FindingListFilter{}, 0, uuid.Nil, 50)
		return e
	}); err != nil {
		t.Fatalf("List: %v", err)
	}

	// Map cve → row by joining basis is fragile; index the four we seeded by their
	// priority order and check the CVEs land where the model must put them.
	if len(page.Findings) != 4 {
		t.Fatalf("listed %d findings, want the 4 seeded", len(page.Findings))
	}
	byCVE := map[string]store.FindingSummary{}
	order := make([]string, 0, 4)
	for _, f := range page.Findings {
		cve := cveOfBasisRow(t, db, tenant, f.ID)
		byCVE[cve] = f
		order = append(order, cve)
	}

	// The inversion, stated as the acceptance states it: the KEV PHP CVE ranks
	// ABOVE the higher-CVSS non-KEV Samba CVE.
	phpAt, sambaAt := indexOf(order, cvePHPKev), indexOf(order, cveSambaHi)
	if phpAt >= sambaAt {
		t.Fatalf("KEV %s ranked at %d, non-KEV higher-CVSS %s at %d — the inversion FAILED; order=%v",
			cvePHPKev, phpAt, cveSambaHi, sambaAt, order)
	}
	// And it wins because it is KEV, not because its CVSS is higher — it is not.
	if byCVE[cveSambaHi].CVSS == nil || *byCVE[cveSambaHi].CVSS <= derefF(byCVE[cvePHPKev].CVSS) {
		t.Fatalf("the test only proves the inversion if the loser's CVSS is genuinely higher: "+
			"php=%v samba=%v", byCVE[cvePHPKev].CVSS, byCVE[cveSambaHi].CVSS)
	}

	// The KEV row is flagged, and its basis names KEV as the dominant reason.
	php := byCVE[cvePHPKev]
	if !php.KEV || php.PriorityBasis != "KEV-listed" {
		t.Errorf("%s should be KEV-listed: kev=%v basis=%q", cvePHPKev, php.KEV, php.PriorityBasis)
	}
	if php.KEVDateAdded == nil {
		t.Errorf("%s KEV date_added not surfaced", cvePHPKev)
	}

	// Absence is not evidence. The Samba CVE is unlisted, not "unexploited".
	if byCVE[cveSambaHi].KEV {
		t.Errorf("%s is not in KEV and must not read as KEV-listed", cveSambaHi)
	}

	// EPSS unscored ≠ 0: the CVSS-only CVE ranks by the CVSS we know (0.5), ABOVE
	// the genuinely no-signal one — not dropped to the bottom for lacking a score.
	noEPSS, unscored := byCVE[cveNoEPSS], byCVE[cveUnscored]
	if noEPSS.EPSS != nil {
		t.Errorf("%s has no EPSS row; EPSS must be nil (unscored), got %v", cveNoEPSS, *noEPSS.EPSS)
	}
	if noEPSS.CVSS == nil || *noEPSS.CVSS != 5.0 {
		t.Errorf("%s CVSS should be 5.0, got %v", cveNoEPSS, noEPSS.CVSS)
	}
	if noEPSS.PriorityBasis != "CVSS 5.0" {
		t.Errorf("%s basis should name CVSS (unscored EPSS falls back to CVSS), got %q", cveNoEPSS, noEPSS.PriorityBasis)
	}
	if indexOf(order, cveNoEPSS) >= indexOf(order, cveUnscored) {
		t.Errorf("CVSS-only %s (%d) must rank above no-signal %s (%d) — absence is not a low value",
			cveNoEPSS, indexOf(order, cveNoEPSS), cveUnscored, indexOf(order, cveUnscored))
	}
	// The genuinely no-signal CVE: nil EPSS, nil CVSS, flagged 'unscored'.
	if unscored.EPSS != nil || unscored.CVSS != nil || unscored.PriorityBasis != "unscored" {
		t.Errorf("%s should be no-signal 'unscored': epss=%v cvss=%v basis=%q",
			cveUnscored, unscored.EPSS, unscored.CVSS, unscored.PriorityBasis)
	}
	if noEPSS.PriorityScore <= unscored.PriorityScore {
		t.Errorf("priority_score must rank CVSS-only above no-signal: %d vs %d",
			noEPSS.PriorityScore, unscored.PriorityScore)
	}

	// The detail path surfaces the same signals (dashboard requirement: priority
	// visible on the finding list AND detail). A finding that reads KEV in the list
	// must read KEV in its own view — the two must not disagree.
	var detail *store.FindingDetail
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var e error
		detail, e = (store.Findings{}).GetFinding(ctx, c, php.ID)
		return e
	}); err != nil {
		t.Fatalf("GetFinding: %v", err)
	}
	if !detail.KEV || detail.PriorityBasis != "KEV-listed" || detail.KEVDateAdded == nil {
		t.Errorf("detail must carry KEV: kev=%v basis=%q date=%v",
			detail.KEV, detail.PriorityBasis, detail.KEVDateAdded)
	}
	if detail.CVSS == nil || *detail.CVSS != 7.5 {
		t.Errorf("detail CVSS for %s should be 7.5, got %v", cvePHPKev, detail.CVSS)
	}

	t.Logf("priority order: %v", order)
}

func cveOfBasisRow(t *testing.T, db *store.DB, tenant store.TenantID, findingID uuid.UUID) string {
	t.Helper()
	var cve string
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT coalesce(vd.cve_id,'') FROM findings f
			   LEFT JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
			  WHERE f.tenant_id = current_setting('app.tenant_id')::uuid AND f.finding_id = $1`,
			findingID).Scan(&cve)
	}); err != nil {
		t.Fatalf("cve lookup: %v", err)
	}
	return cve
}

func indexOf(s []string, v string) int {
	for i, x := range s {
		if x == v {
			return i
		}
	}
	return -1
}

func derefF(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}
