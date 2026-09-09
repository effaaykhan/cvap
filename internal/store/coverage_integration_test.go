package store_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// B29 acceptance (ADR-067): a host on a release PAST its coverage window reports
// cannot-know, not clean — demonstrated, not asserted. Hardy is the case: its ESM
// ended long ago (the feed even returns a degenerate placeholder date), so the
// keyspace's newest hardy advisory predates any current host's exposure. A
// current release (jammy, ESM to 2032) is the control: there a no-match is
// honestly clean.
//
// Seeds release_coverage through cvap_knowledge_import (ADR-063), the real
// coverage rows the feed gives (hardy degenerate/past, jammy future), idempotent
// so it coexists with the dev DB's real import.
func seedCoverage(t *testing.T) {
	t.Helper()
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set; skipping coverage acceptance (needs cvap_knowledge_import)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()
	for _, s := range []string{
		`INSERT INTO release_coverage (feed, distro_release, release_date, support_expires, esm_expires, coverage_source, last_fetched_at)
		 VALUES ('ubuntu-usn','hardy','2008-04-24','2008-04-24','2008-04-24','feed-degenerate', now()),
		        ('ubuntu-usn','jammy','2022-04-21','2027-04-30','2032-04-30','feed', now())
		 ON CONFLICT (feed, distro_release) DO NOTHING`,
		// A hardy advisory WITH an issued_at, so CoverageAll's newest-advisory
		// display value is populated on a fresh CI database. Not relying on the
		// dev DB's real import (whose advisories carry dates) — a seed must stand
		// on its own, or it passes locally and fails on a clean CI checkout.
		`INSERT INTO vendor_advisories (advisory_ref, vendor, issued_at)
		 VALUES ('TEST-HARDY-COV','ubuntu','2012-05-01T00:00:00Z')
		 ON CONFLICT (advisory_ref) DO UPDATE SET issued_at = excluded.issued_at`,
		`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
		 SELECT advisory_id, 'hardy', 'coverage-probe-pkg', '1.0', 'dpkg'::version_comparator
		   FROM vendor_advisories WHERE advisory_ref='TEST-HARDY-COV'
		 ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING`,
	} {
		if _, err := pool.Exec(ctx, s); err != nil {
			t.Fatalf("seed coverage: %v", err)
		}
	}
}

func TestReleasePastCoverageWindowIsCannotKnow(t *testing.T) {
	db := testDB(t)
	seedCoverage(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "cov-"+uuid.NewString()[:8])

	var hardy, jammy store.ReleaseCoverage
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var e error
		if hardy, e = (store.Advisories{}).ReleaseCoverageFor(ctx, c, "hardy"); e != nil {
			return e
		}
		jammy, e = (store.Advisories{}).ReleaseCoverageFor(ctx, c, "jammy")
		return e
	}); err != nil {
		t.Fatalf("ReleaseCoverageFor: %v", err)
	}

	// The coverage state itself, computed from the window in the data.
	if hardy.State != store.CoverageOut {
		t.Errorf("hardy coverage = %q, want out_of_coverage (ESM ended 2008)", hardy.State)
	}
	if jammy.State != store.CoverageCovered {
		t.Errorf("jammy coverage = %q, want covered (ESM to 2032)", jammy.State)
	}

	// The load-bearing distinction: a NO-MATCH classifies differently by coverage.
	hardyNoMatch := domain.ClassifyMatch(false, hardy.InCoverage())
	jammyNoMatch := domain.ClassifyMatch(false, jammy.InCoverage())
	if hardyNoMatch != domain.MatchCannotKnow {
		t.Errorf("no-match on hardy = %q, want cannot_know (out of coverage — the B29 defect if it reads clean)", hardyNoMatch)
	}
	if jammyNoMatch != domain.MatchClean {
		t.Errorf("no-match on jammy = %q, want clean (in coverage)", jammyNoMatch)
	}
	if hardyNoMatch == jammyNoMatch {
		t.Fatalf("a no-match must differ by coverage; both were %q — cannot-know collapsed into clean, the exact silent false negative B29 exists to prevent", hardyNoMatch)
	}
	// A positive match stays vulnerable regardless of coverage.
	if domain.ClassifyMatch(true, hardy.InCoverage()) != domain.MatchVulnerable {
		t.Errorf("a matched advisory on hardy must still be vulnerable")
	}
	t.Logf("in situ: hardy (esm degenerate/2008, source=%s) -> %s -> no-match=%s | jammy (esm 2032) -> %s -> no-match=%s",
		hardy.CoverageSource, hardy.State, hardyNoMatch, jammy.State, jammyNoMatch)
}

func TestCoverageAllListsIngestedReleases(t *testing.T) {
	db := testDB(t)
	seedCoverage(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "covall-"+uuid.NewString()[:8])

	// seedCoverage seeds a hardy advisory WITH an issued_at, so hardy appears in
	// CoverageAll (which starts from releases the keyspace holds advisories for)
	// and its newest-advisory display value is populated on a fresh DB.

	var all []store.ReleaseCoverage
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var e error
		all, e = (store.Advisories{}).CoverageAll(ctx, c)
		return e
	}); err != nil {
		t.Fatalf("CoverageAll: %v", err)
	}
	var hardy *store.ReleaseCoverage
	for i := range all {
		if all[i].Release == "hardy" {
			hardy = &all[i]
		}
	}
	if hardy == nil {
		t.Fatalf("hardy absent from CoverageAll (%d releases) — it has advisories and a window", len(all))
	}
	if hardy.State != store.CoverageOut {
		t.Errorf("hardy in CoverageAll = %q, want out_of_coverage", hardy.State)
	}
	// The empirical newest advisory is the honest display value where the feed
	// date is degenerate.
	if hardy.NewestAdvisoryAt == nil {
		t.Errorf("hardy CoverageAll has no newest-advisory date — the display value where the feed date is degenerate")
	}
}
