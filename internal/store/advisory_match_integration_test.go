package store_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/version"
)

// P3.2 acceptance: a REAL advisory decides a REAL installed version.
//
// These constants are the output of the real USN feed — fetched this session by
// knowledge/usn_ingest.py against https://ubuntu.com/security/notices.json — and
// the installed version MEASURED on Metasploitable (Ubuntu 8.04 "hardy", the only
// real host in scope for session 29):
//
//	USN-1467-1  ->  CVE-2012-2122 (MySQL authentication-bypass)
//	hardy  mysql-dfsg-5.0  fixed 5.0.96-0ubuntu3   (dpkg versions)
//	measured on the host:  mysql-dfsg-5.0 5.0.51a-3ubuntu5
//
// They are not an invented fixture — they are what the feed said and what the
// host runs. The seed below writes exactly what the importer wrote, through the
// SAME write role (cvap_knowledge_import), so this stays a repeatable regression
// of the end-to-end decision without CI needing the live feed reachable. The
// live real-feed ingest was demonstrated once, out of band; this proves the
// matcher — the consumer of P3.1's comparators — against that data, in situ.
const (
	usnRef        = "USN-1467-1"
	usnCVE        = "CVE-2012-2122"
	usnRelease    = "hardy"
	usnPackage    = "mysql-dfsg-5.0"
	usnFixed      = "5.0.96-0ubuntu3"
	measuredMySQL = "5.0.51a-3ubuntu5" // measured on the real Metasploitable host
)

// seedUSNAdvisory writes USN-1467-1 through cvap_knowledge_import — the ADR-063
// role that is the ONLY identity allowed to write knowledge tables — mirroring
// the importer's upserts so the seed is idempotent. It skips (not fails) when the
// import DSN is absent, the same contract as the app DSN: a suite that silently
// passes without a database is the hazard, so the skip names what it skipped.
func seedUSNAdvisory(t *testing.T) {
	t.Helper()
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set; skipping advisory-match acceptance (needs the cvap_knowledge_import role)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()

	// One statement per table, ON CONFLICT idempotent — the importer's shape.
	stmts := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO vendor_advisories (advisory_ref, vendor)
		  VALUES ($1, 'ubuntu')
		  ON CONFLICT (advisory_ref) DO UPDATE SET vendor = excluded.vendor`,
			[]any{usnRef}},
		{`INSERT INTO vulnerability_defs (cve_id, title)
		  VALUES ($1, $1)
		  ON CONFLICT (cve_id) DO NOTHING`,
			[]any{usnCVE}},
		{`INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
		  SELECT va.advisory_id, vd.vuln_def_id
		    FROM vendor_advisories va, vulnerability_defs vd
		   WHERE va.advisory_ref = $1 AND vd.cve_id = $2
		  ON CONFLICT DO NOTHING`,
			[]any{usnRef, usnCVE}},
		{`INSERT INTO advisory_fixed_packages
		     (advisory_id, distro_release, package_name, fixed_version, comparator)
		  SELECT advisory_id, $2, $3, $4, 'dpkg'::version_comparator
		    FROM vendor_advisories WHERE advisory_ref = $1
		  ON CONFLICT (advisory_id, distro_release, package_name)
		     DO UPDATE SET fixed_version = excluded.fixed_version, comparator = excluded.comparator`,
			[]any{usnRef, usnRelease, usnPackage, usnFixed}},
	}
	for _, s := range stmts {
		if _, err := pool.Exec(ctx, s.sql, s.args...); err != nil {
			t.Fatalf("seed advisory (import role): %v\nSQL: %s", err, s.sql)
		}
	}
}

// TestAdvisoryMatchInSitu is the P3.2 acceptance. It reads the ingested advisory
// as cvap_app, then decides — with the comparator the ROW names, not one the code
// assumes — whether the measured installed version is affected. This is the join
// of the whole phase: ADR-014's advisory data, ADR-062's Go-authoritative
// comparator, and a real host's real version.
func TestAdvisoryMatchInSitu(t *testing.T) {
	db := testDB(t) // cvap_app: SELECT-only on knowledge
	seedUSNAdvisory(t)
	ctx := context.Background()

	// A global-table read from inside a tenant Read — the case the store CLAUDE.md
	// and ADR-030 anticipated; there is no unscoped knowledge read primitive.
	tenant := newTenant(t, db, "advmatch-"+uuid.NewString()[:8])
	var fixes []store.AdvisoryFix
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		fixes, err = (store.Advisories{}).FixesFor(ctx, c, usnRelease, usnPackage)
		return err
	}); err != nil {
		t.Fatalf("FixesFor: %v", err)
	}

	var fix *store.AdvisoryFix
	for i := range fixes {
		if fixes[i].AdvisoryRef == usnRef {
			fix = &fixes[i]
			break
		}
	}
	if fix == nil {
		t.Fatalf("USN-1467-1 not among %d fixes for (%s, %s) — ingest did not land the advisory",
			len(fixes), usnRelease, usnPackage)
	}
	if fix.FixedVersion != usnFixed {
		t.Fatalf("fixed version = %q, want %q (the advisory's own fixed revision)", fix.FixedVersion, usnFixed)
	}

	// The comparator is chosen by the DATA, not the code: a dpkg version compared
	// with rpm rules is silently wrong, so the matcher refuses an unknown name.
	scheme, ok := version.SchemeByName(fix.Comparator)
	if !ok {
		t.Fatalf("unknown comparator %q on the stored fix — the matcher must not guess one", fix.Comparator)
	}
	if scheme != version.SchemeDpkg {
		t.Fatalf("comparator = %q, want dpkg for a USN row", fix.Comparator)
	}

	rng := version.AffectedRange{Fixed: fix.FixedVersion}

	// THE ACCEPTANCE DECISION: the measured host version is strictly below the
	// fixed revision, so the host is affected (ADR-014). This is a real advisory
	// judging a real installed version — the phase's whole point.
	if !rng.Vulnerable(scheme, measuredMySQL) {
		t.Errorf("measured %s judged NOT vulnerable against fixed %s — the match is broken",
			measuredMySQL, fix.FixedVersion)
	}
	// Backport case (ADR-014): a host patched to EXACTLY the fixed revision is
	// cleared. The dpkg comparator, not SQL text order, is what makes this correct.
	if rng.Vulnerable(scheme, usnFixed) {
		t.Errorf("a host at the fixed version %s judged vulnerable — the backport clear-out failed", usnFixed)
	}
	// A revision above the fix is cleared.
	if rng.Vulnerable(scheme, "5.0.96-0ubuntu4") {
		t.Errorf("a host newer than the fix judged vulnerable")
	}

	t.Logf("in situ: %s (%s) fixed %s [%s] vs measured %s -> vulnerable=%t",
		fix.AdvisoryRef, usnCVE, fix.FixedVersion, fix.Comparator, measuredMySQL,
		rng.Vulnerable(scheme, measuredMySQL))
}

// TestFeedFreshnessStateInData proves the freshness verdict is computed from the
// threshold IN THE DATA, not inferred by the caller from a timestamp. Three feeds
// with the SAME rows but different last-fetched times and their OWN thresholds
// must come back current / stale / never — the answer the panel renders, decided
// against each feed's configured policy.
func TestFeedFreshnessStateInData(t *testing.T) {
	db := testDB(t)
	importURL := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if importURL == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set; skipping freshness-state test (needs the cvap_knowledge_import role)")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, importURL)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()

	// Distinct feed names so the test does not collide with a real ingested row.
	feeds := map[string]string{
		"test-current-" + uuid.NewString()[:8]: "now() - interval '1 day'",   // within a 7-day threshold
		"test-stale-" + uuid.NewString()[:8]:   "now() - interval '30 days'", // past it
		"test-never-" + uuid.NewString()[:8]:   "NULL",                       // no fetch yet
	}
	names := make([]string, 0, len(feeds))
	for feed, fetched := range feeds {
		names = append(names, feed)
		// The threshold is the feed's own (7 days), stored on the row — the state
		// computation reads it, so this is what makes current vs stale meaningful.
		_, err := pool.Exec(ctx,
			`INSERT INTO knowledge_feed_status
			     (feed, source_url, last_fetched_at, advisory_count, staleness_threshold)
			 VALUES ($1, 'https://example.test/'||$1, `+fetched+`, 0, interval '7 days')`, feed)
		if err != nil {
			t.Fatalf("seed feed %s: %v", feed, err)
		}
	}
	t.Cleanup(func() {
		for _, feed := range names {
			_, _ = pool.Exec(context.Background(), `DELETE FROM knowledge_feed_status WHERE feed = $1`, feed)
		}
	})

	tenant := newTenant(t, db, "freshness-"+uuid.NewString()[:8])
	var got []store.FeedFreshness
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var e error
		got, e = (store.Advisories{}).FeedFreshnessAll(ctx, c)
		return e
	}); err != nil {
		t.Fatalf("FeedFreshnessAll: %v", err)
	}

	states := map[string]store.FeedState{}
	for _, f := range got {
		states[f.Feed] = f.State
	}
	for feed := range feeds {
		want := store.FeedCurrent
		switch {
		case strings.HasPrefix(feed, "test-stale-"):
			want = store.FeedStale
		case strings.HasPrefix(feed, "test-never-"):
			want = store.FeedNever
		}
		if states[feed] != want {
			t.Errorf("feed %s: state = %q, want %q (the state is the feed's own threshold applied server-side)",
				feed, states[feed], want)
		}
	}
}

// TestAppRoleCannotWriteKnowledge asserts the other half of ADR-063: cvap_app
// may READ the knowledge tables (for the match above) but may not WRITE them.
// The negative is worth a test because a widened grant is invisible in review —
// the read path keeps working, and only an injected advisory reveals the hole.
func TestAppRoleCannotWriteKnowledge(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "advwrite-"+uuid.NewString()[:8])

	err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, e := c.Exec(ctx,
			`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
			 SELECT advisory_id, 'hardy', 'evil', '0', 'dpkg'::version_comparator
			   FROM vendor_advisories LIMIT 1`)
		return e
	})
	if !errors.Is(err, store.ErrNotPermitted) {
		t.Fatalf("cvap_app write to advisory_fixed_packages: got %v, want ErrNotPermitted (ADR-063: the app role is SELECT-only on knowledge)", err)
	}
}
