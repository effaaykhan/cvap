package scanpoint

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

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
	resolved, err := target.NewCoreEndpoints(ctx, eps, func(ctx context.Context, host string) ([]netip.Addr, error) {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	})
	if err != nil {
		return target.CoreEndpoints{}, err
	}
	return crossCheck(resolved, cfg.PolicyCoreEndpoints)
}

// ErrExemptNotRefused means the holder exempts a Core address from the packet
// ceiling that this runtime would not refuse as a scan target.
var ErrExemptNotRefused = errors.New("scanpoint: the network policy exempts an address this runtime does not recognise as Core")

// crossCheck requires the holder's exempt set E (the CVAP_NP_CORE_ENDPOINTS
// literal it was started with) to be covered by the addresses this runtime
// resolved for Core. E is IP literals only - the holder refuses names - so no
// resolver is involved, and a literal that fails to parse is an error, never
// skipped: an E this runtime cannot read is an E it cannot promise to refuse.
func crossCheck(resolved target.CoreEndpoints, policy string) (target.CoreEndpoints, error) {
	if strings.TrimSpace(policy) == "" {
		return resolved, nil
	}
	var eps []string
	for _, ep := range strings.Split(policy, ",") {
		if ep = strings.TrimSpace(ep); ep != "" {
			eps = append(eps, ep)
		}
	}
	exempt, err := target.NewCoreEndpoints(context.Background(), eps, nil)
	if err != nil {
		return target.CoreEndpoints{}, fmt.Errorf("scanpoint: CVAP_NP_CORE_ENDPOINTS: %w", err)
	}
	if missing := resolved.Missing(exempt); len(missing) > 0 {
		return target.CoreEndpoints{}, fmt.Errorf("%w: exempt %v, but Core resolved to %v (ADR-110)",
			ErrExemptNotRefused, missing, resolved.Addrs())
	}
	return resolved, nil
}
