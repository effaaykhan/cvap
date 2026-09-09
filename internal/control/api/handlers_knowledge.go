package api

import (
	"context"
	"net/http"
	"time"

	"github.com/effaaykhan/cvap/internal/store"
)

// The knowledge-freshness surface (P3.2). An operator trusting an advisory-matched
// finding needs to know whether the advisory data behind it is current — a stale
// feed means matching is under-reporting, which is a silent false negative.
//
// "stale" is a STATE the server computes from the threshold IN THE DATA
// (knowledge_feed_status.staleness_threshold, per feed), not a timestamp the UI
// eyeballs. The response carries the raw last-fetched time and the threshold for
// context, but `state` is the answer — the same "put the verdict in the data"
// rule the scan-point health surface (handlers_ops.go) and the exposure count
// follow. The panel renders `state`; it must not recompute the verdict.

// KnowledgeFeedResponse is one ingested feed's freshness.
type KnowledgeFeedResponse struct {
	Feed                      string     `json:"feed"`
	SourceURL                 string     `json:"source_url"`
	LastFetchedAt             *time.Time `json:"last_fetched_at"`
	SourceETag                string     `json:"source_etag,omitempty"`
	AdvisoryCount             int        `json:"advisory_count"`
	StalenessThresholdSeconds int64      `json:"staleness_threshold_seconds"`
	// State is current | stale | never — computed server-side against this feed's
	// own threshold. The word the panel renders.
	State string `json:"state"`
}

// ReleaseCoverageResponse is one ingested release's advisory-coverage window and
// its computed state — beside feed freshness, because a stale feed and an
// out-of-coverage release are two different ways matching can silently
// under-report, and an operator needs to see both (B29, ADR-067).
type ReleaseCoverageResponse struct {
	Release string `json:"release"`
	// State is covered | out_of_coverage | unknown — computed server-side from the
	// coverage window in the data, never inferred in the UI.
	State            string  `json:"state"`
	ESMExpires       *string `json:"esm_expires,omitempty" doc:"Coverage end (ESM), the last date advisories flow for this release."`
	CoverageSource   string  `json:"coverage_source,omitempty" doc:"'feed' when the feed gave a real support window; 'feed-degenerate' when it returned only the release date (a placeholder for pre-ESM-tracking releases)."`
	NewestAdvisoryAt *string `json:"newest_advisory_at,omitempty" doc:"The newest advisory the keyspace holds for this release — the honest coverage-end where the feed date is degenerate."`
}

// KnowledgeFreshnessResponse is the freshness of every ingested feed, and the
// per-release coverage windows.
type KnowledgeFreshnessResponse struct {
	Feeds    []KnowledgeFeedResponse   `json:"feeds"`
	Coverage []ReleaseCoverageResponse `json:"coverage"`
}

func (s *Server) knowledgeFreshness(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())
	var feeds []store.FeedFreshness
	var coverage []store.ReleaseCoverage
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		if feeds, err = (store.Advisories{}).FeedFreshnessAll(ctx, c); err != nil {
			return err
		}
		coverage, err = (store.Advisories{}).CoverageAll(ctx, c)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := KnowledgeFreshnessResponse{
		Feeds:    make([]KnowledgeFeedResponse, 0, len(feeds)),
		Coverage: make([]ReleaseCoverageResponse, 0, len(coverage)),
	}
	for _, f := range feeds {
		out.Feeds = append(out.Feeds, KnowledgeFeedResponse{
			Feed:                      f.Feed,
			SourceURL:                 f.SourceURL,
			LastFetchedAt:             f.LastFetchedAt,
			SourceETag:                f.SourceETag,
			AdvisoryCount:             f.AdvisoryCount,
			StalenessThresholdSeconds: int64(f.StalenessThreshold.Seconds()),
			State:                     string(f.State),
		})
	}
	for _, rc := range coverage {
		out.Coverage = append(out.Coverage, ReleaseCoverageResponse{
			Release:          rc.Release,
			State:            string(rc.State),
			ESMExpires:       dateOrNil(rc.ESMExpires),
			CoverageSource:   rc.CoverageSource,
			NewestAdvisoryAt: dateOrNil(rc.NewestAdvisoryAt),
		})
	}
	writeJSON(w, r, s.log, http.StatusOK, out)
}

// dateOrNil renders a nullable time as a YYYY-MM-DD string, or nil. Coverage is a
// date, not a moment; the UI shows the day.
func dateOrNil(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := t.Format("2006-01-02")
	return &s
}
