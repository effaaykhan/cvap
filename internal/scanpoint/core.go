package scanpoint

import (
	"context"
	"net"
	"net/netip"

	"github.com/effaaykhan/cvap/internal/target"
)

// CoreEndpoints is where this scan point reaches Core: the enrollment endpoint
// it was configured with and the dispatch, ingest and rule-pack endpoints Core
// returned at enrollment. Resolved once, here, at startup.
//
// The runtime refuses every one of these addresses as a scan target (ADR-110),
// because the Scan Point's kernel packet ceiling exempts traffic to Core. A
// scan point that cannot build the set does not start: an empty set would
// refuse nothing, which is the failure the refusal exists to prevent.
func CoreEndpoints(ctx context.Context, cfg Config, id *Identity) (target.CoreEndpoints, error) {
	eps := []string{cfg.EnrollEndpoint}
	if id != nil {
		eps = append(eps, id.DispatchAddr, id.IngestAddr, id.RulePacksAddr)
	}
	return target.NewCoreEndpoints(ctx, eps, func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	})
}
