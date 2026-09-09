package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// Advisory matching reads (P3.2, ADR-014). The knowledge tables are global
// (no tenant, ADR-030); this read runs inside a tenant-scoped transaction the
// same way the finding path reads `rules` — a global table read from within a
// tenant Read is not an unscoped read of tenant data.
//
// ADR-062 splits the work: SQL NARROWS (by distro release and package name, the
// indexed hot path), and Go DECIDES the version relation with the comparator the
// row names. The database never compares versions — its text order disagrees
// with dpkg on the tilde, and the version verdict has one authority, Go.
type Advisories struct{}

// AdvisoryFix is one advisory's fix for a package on a release. FixedVersion and
// Comparator are handed to internal/version to decide whether an installed
// version is below the fix (and therefore vulnerable).
type AdvisoryFix struct {
	AdvisoryRef  string
	Release      string
	Package      string
	FixedVersion string
	Comparator   string // 'dpkg' | 'rpm' (version_comparator enum)
}

// FixesFor returns every advisory fix for a package on a distro release — the
// candidate set. It does NOT decide vulnerability; the caller compares each
// FixedVersion against the installed version with the named comparator.
func (Advisories) FixesFor(ctx context.Context, c *Conn, release, pkg string) ([]AdvisoryFix, error) {
	const q = `
		SELECT va.advisory_ref, afp.distro_release, afp.package_name,
		       afp.fixed_version, afp.comparator::text
		  FROM advisory_fixed_packages afp
		  JOIN vendor_advisories va USING (advisory_id)
		 WHERE afp.distro_release = $1 AND afp.package_name = $2
		 ORDER BY va.advisory_ref`
	rows, err := c.Query(ctx, q, release, pkg)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []AdvisoryFix
	for rows.Next() {
		var f AdvisoryFix
		if err := rows.Scan(&f.AdvisoryRef, &f.Release, &f.Package, &f.FixedVersion, &f.Comparator); err != nil {
			return nil, mapError(err)
		}
		out = append(out, f)
	}
	return out, mapError(rows.Err())
}

// PackagesForProduct returns the Ubuntu source packages an advisory keyspace uses
// for a fingerprint product string ("MySQL" -> mysql-dfsg-5.0, mysql-5.5, ...),
// the candidate set the matcher runs FixesFor over (ADR-064/070). A product maps
// to several packages across release lines; the release narrows which actually
// carry advisories, so a package a release never shipped simply returns no fix —
// absence of a fix, not evidence of safety (B30). Global-table read from inside a
// tenant Read (ADR-030), like FixesFor.
func (Advisories) PackagesForProduct(ctx context.Context, c *Conn, product string) ([]string, error) {
	const q = `SELECT package_name FROM product_packages WHERE product = $1 ORDER BY package_name`
	rows, err := c.Query(ctx, q, product)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, mapError(err)
		}
		out = append(out, p)
	}
	return out, mapError(rows.Err())
}

// AdvisoryVuln is one CVE an advisory fixes: the vuln_def_id that becomes an
// advisory finding's link, the human-readable CVE id (ADR-009/070), and the CVE's
// CVSS base if scored — the finding's severity is taken from its band, and nil
// (unscored) falls back to the rule default rather than reading as 0 (ADR-069's
// absence rule carried into the finding's own severity).
type AdvisoryVuln struct {
	VulnDefID uuid.UUID
	CVE       string
	CVSSBase  *float64
}

// AdvisoryVulnDefs returns every CVE an advisory maps to (advisory_vuln_map). One
// advisory (one USN) commonly fixes several CVEs, so a single vulnerable match
// raises one finding per CVE — the (asset, package, cve) dedup (ADR-070). Called
// only after the version comparison has judged the fix vulnerable, so the fan-out
// is over confirmed matches, not the whole keyspace.
func (Advisories) AdvisoryVulnDefs(ctx context.Context, c *Conn, advisoryRef string) ([]AdvisoryVuln, error) {
	const q = `
		SELECT vd.vuln_def_id, vd.cve_id, vd.cvss_base
		  FROM vendor_advisories va
		  JOIN advisory_vuln_map avm USING (advisory_id)
		  JOIN vulnerability_defs vd ON vd.vuln_def_id = avm.vuln_def_id
		 WHERE va.advisory_ref = $1
		 ORDER BY vd.cve_id`
	rows, err := c.Query(ctx, q, advisoryRef)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []AdvisoryVuln
	for rows.Next() {
		var v AdvisoryVuln
		if err := rows.Scan(&v.VulnDefID, &v.CVE, &v.CVSSBase); err != nil {
			return nil, mapError(err)
		}
		out = append(out, v)
	}
	return out, mapError(rows.Err())
}

// ReleaseFixedVersion is one advisory fixed version for a package on a release —
// the raw material for release-band voting (P3.3, ADR-064). The band is NOT
// extracted here: SQL narrows to the product's packages, and domain.UpstreamBand
// does the banding for both this and the observed version, so there is one band
// authority and it is Go (ADR-062, and the two-writers-one-fact hazard).
type ReleaseFixedVersion struct {
	Release      string
	Package      string
	FixedVersion string
}

// ReleasesForProduct returns every advisory fixed version, across all releases,
// for the packages an observed service Product maps to (product_packages, the
// content map of ADR-064). This is the design's "ReleasesForPackage" read: the
// caller bands each FixedVersion with domain.UpstreamBand and matches it against
// the observed band to compute which releases a service votes for. Empty result
// means the product has no advisory analogue in the keyspace at all (unmapped, or
// mapped to packages with no advisories) — the caller reads that as an abstention,
// never a vote against. Global-table read from inside a tenant Read, the case
// ADR-030 anticipated (like FixesFor).
func (Advisories) ReleasesForProduct(ctx context.Context, c *Conn, product string) ([]ReleaseFixedVersion, error) {
	const q = `
		SELECT afp.distro_release, afp.package_name, afp.fixed_version
		  FROM product_packages pp
		  JOIN advisory_fixed_packages afp ON afp.package_name = pp.package_name
		 WHERE pp.product = $1
		 ORDER BY afp.distro_release, afp.package_name, afp.fixed_version`
	rows, err := c.Query(ctx, q, product)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []ReleaseFixedVersion
	for rows.Next() {
		var v ReleaseFixedVersion
		if err := rows.Scan(&v.Release, &v.Package, &v.FixedVersion); err != nil {
			return nil, mapError(err)
		}
		out = append(out, v)
	}
	return out, mapError(rows.Err())
}

// CoverageState is a release's advisory-coverage status, computed from the
// coverage window in the data (release_coverage.esm_expires) against now — the
// same "put the answer in the data, not the UI" rule as feed freshness (ADR-063).
// A release past its window is out of coverage: a no-match on it is cannot-know,
// not clean (B29, ADR-067).
type CoverageState string

const (
	CoverageCovered CoverageState = "covered"         // esm_expires >= now: advisories still flow
	CoverageOut     CoverageState = "out_of_coverage" // esm_expires < now: keyspace stopped for this release
	CoverageUnknown CoverageState = "unknown"         // no coverage window recorded for the release
)

// ReleaseCoverage is one release's coverage window and computed state.
// NewestAdvisoryAt is the empirical last advisory the keyspace holds for the
// release — the honest display value where the feed gave only a degenerate date
// (coverage_source = 'feed-degenerate', e.g. hardy's placeholder 2008 date). The
// state itself is decided by esm_expires, the feed's authoritative coverage end.
type ReleaseCoverage struct {
	Release          string
	State            CoverageState
	ESMExpires       *time.Time
	SupportExpires   *time.Time
	CoverageSource   string
	NewestAdvisoryAt *time.Time
}

// InCoverage is the boolean the matcher's ClassifyMatch consumes: covered is in,
// out and unknown are both NOT in — an unrecorded window cannot be presented as
// coverage (absence is not evidence, B29/ADR-067).
func (rc ReleaseCoverage) InCoverage() bool { return rc.State == CoverageCovered }

const coverageStateSQL = `CASE
	    WHEN rc.esm_expires IS NULL THEN 'unknown'
	    WHEN rc.esm_expires < now()::date THEN 'out_of_coverage'
	    ELSE 'covered' END`

// ReleaseCoverageFor returns the coverage window and computed state for one
// release, plus the empirical newest advisory the keyspace holds for it. A
// release with no coverage row comes back as CoverageUnknown — not an error, and
// not covered. Global-table read from inside a tenant Read (ADR-030), like FixesFor.
func (Advisories) ReleaseCoverageFor(ctx context.Context, c *Conn, release string) (ReleaseCoverage, error) {
	const q = `
		SELECT rc.support_expires, rc.esm_expires, COALESCE(rc.coverage_source, ''),
		       (SELECT max(va.issued_at) FROM advisory_fixed_packages afp
		          JOIN vendor_advisories va USING (advisory_id)
		         WHERE afp.distro_release = $1) AS newest_advisory_at,
		       ` + coverageStateSQL + ` AS state
		  FROM release_coverage rc
		 WHERE rc.distro_release = $1`
	out := ReleaseCoverage{Release: release, State: CoverageUnknown}
	var state string
	err := c.QueryRow(ctx, q, release).
		Scan(&out.SupportExpires, &out.ESMExpires, &out.CoverageSource, &out.NewestAdvisoryAt, &state)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// No window recorded: unknown, and the newest-advisory fallback is worth
			// having for display even without a window row.
			return out, nil
		}
		return out, mapError(err)
	}
	out.State = CoverageState(state)
	return out, nil
}

// CoverageAll returns, per release the keyspace actually holds advisories for, its
// coverage state and newest advisory — the dashboard's coverage surface beside
// feed freshness. Starts from the releases in advisory_fixed_packages so it shows
// what a host could resolve to, LEFT JOINed to the window (a release with
// advisories but no window row reads as unknown).
func (Advisories) CoverageAll(ctx context.Context, c *Conn) ([]ReleaseCoverage, error) {
	const q = `
		SELECT r.release, rc.support_expires, rc.esm_expires, COALESCE(rc.coverage_source, ''),
		       r.newest_advisory_at,
		       CASE WHEN rc.esm_expires IS NULL THEN 'unknown'
		            WHEN rc.esm_expires < now()::date THEN 'out_of_coverage'
		            ELSE 'covered' END AS state
		  FROM (SELECT afp.distro_release AS release, max(va.issued_at) AS newest_advisory_at
		          FROM advisory_fixed_packages afp JOIN vendor_advisories va USING (advisory_id)
		         GROUP BY afp.distro_release) r
		  LEFT JOIN release_coverage rc ON rc.distro_release = r.release
		 ORDER BY r.release`
	rows, err := c.Query(ctx, q)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []ReleaseCoverage
	for rows.Next() {
		var rc ReleaseCoverage
		var state string
		if err := rows.Scan(&rc.Release, &rc.SupportExpires, &rc.ESMExpires, &rc.CoverageSource,
			&rc.NewestAdvisoryAt, &state); err != nil {
			return nil, mapError(err)
		}
		rc.State = CoverageState(state)
		out = append(out, rc)
	}
	return out, mapError(rows.Err())
}

// FeedState is a knowledge feed's freshness, computed — not raw. "stale" is a
// STATE the API hands the panel, not a timestamp comparison the operator eyeballs
// (the exposure-count lesson: put the answer in the data). The threshold lives in
// the row (knowledge_feed_status.staleness_threshold), so the database decides
// current vs stale against the feed's OWN policy, and the panel renders the word.
type FeedState string

const (
	FeedCurrent FeedState = "current" // fetched within the feed's staleness threshold
	FeedStale   FeedState = "stale"   // last fetch older than the threshold — matching under-reports
	FeedNever   FeedState = "never"   // no successful fetch yet (last_fetched_at is null)
)

// FeedFreshness is one feed's status for the freshness surface. State is the
// answer; the timestamp and threshold are shown alongside it for context, but the
// panel must render State, never recompute the verdict from LastFetchedAt.
type FeedFreshness struct {
	Feed               string
	SourceURL          string
	LastFetchedAt      *time.Time // nil when never fetched
	SourceETag         string
	AdvisoryCount      int
	StalenessThreshold time.Duration
	State              FeedState
}

// FeedFreshnessAll returns every ingested feed's freshness. Global knowledge read
// (no tenant_id, ADR-030) from inside a tenant Read — the case ADR-030 anticipated
// and migration 0034 granted cvap_app SELECT for. The CASE puts the state in the
// result: the threshold is a column, so the verdict is the feed's own, not a UI
// constant that drifts from what the pipeline was configured with.
func (Advisories) FeedFreshnessAll(ctx context.Context, c *Conn) ([]FeedFreshness, error) {
	const q = `
		SELECT feed, source_url, last_fetched_at, COALESCE(source_etag, '') AS source_etag, advisory_count,
		       EXTRACT(EPOCH FROM staleness_threshold)::bigint AS threshold_seconds,
		       CASE
		           WHEN last_fetched_at IS NULL THEN 'never'
		           WHEN now() - last_fetched_at > staleness_threshold THEN 'stale'
		           ELSE 'current'
		       END AS state
		  FROM knowledge_feed_status
		 ORDER BY feed`
	rows, err := c.Query(ctx, q)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	var out []FeedFreshness
	for rows.Next() {
		var f FeedFreshness
		var thresholdSeconds int64
		var state string
		if err := rows.Scan(&f.Feed, &f.SourceURL, &f.LastFetchedAt, &f.SourceETag,
			&f.AdvisoryCount, &thresholdSeconds, &state); err != nil {
			return nil, mapError(err)
		}
		f.StalenessThreshold = time.Duration(thresholdSeconds) * time.Second
		f.State = FeedState(state)
		out = append(out, f)
	}
	return out, mapError(rows.Err())
}
