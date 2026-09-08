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

// KnowledgeFreshnessResponse is the freshness of every ingested feed.
type KnowledgeFreshnessResponse struct {
	Feeds []KnowledgeFeedResponse `json:"feeds"`
}

func (s *Server) knowledgeFreshness(w http.ResponseWriter, r *http.Request) {
	tenant, _ := tenantFrom(r.Context())
	var feeds []store.FeedFreshness
	err := s.db.Read(r.Context(), tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		feeds, err = (store.Advisories{}).FeedFreshnessAll(ctx, c)
		return err
	})
	if err != nil {
		storeError(w, r, s.log, err)
		return
	}
	out := KnowledgeFreshnessResponse{Feeds: make([]KnowledgeFeedResponse, 0, len(feeds))}
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
	writeJSON(w, r, s.log, http.StatusOK, out)
}
