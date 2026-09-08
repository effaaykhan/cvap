package store

import (
	"context"
	"time"
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
