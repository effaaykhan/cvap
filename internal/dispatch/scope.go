package dispatch

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/effaaykhan/cvap/internal/store"
)

// ============================================================================
// ADR-024 control 1, site one. It was empty.
// ============================================================================
//
// Scope enforcement is duplicated: Core validates during planning, and the scan
// point checks again before packets leave. Neither side trusts the other. The
// ADR rejected "enforce at the scan point only" outright, because scan points
// run months-old builds and Core cannot rely on their check being current.
//
// A safety audit found we had arrived at exactly that rejected alternative by
// accident: Core computed an allowlist, put it on the wire, and never compared a
// single task target against it. The allowlist was advisory, and the only
// enforcement was in a runtime that does not exist yet.

// scopePlan turns a policy's scope rules into the two wire fields.
//
// Returns an error rather than dropping anything it cannot express. The previous
// version skipped `tag` rules before looking at their effect, which was
// fail-closed for an allow and fail-OPEN for a deny: a policy reading
// "allow 10.10.0.0/24, deny tag medical" produced a non-empty allowlist, so the
// job dispatched with no warning, and the exclusion protecting the medical
// devices inside that range reached neither enforcement site. Exclusions take
// precedence over allows (ADR-024), and a precedence you can delete by choosing
// a match type is not a precedence.
//
// So: allows and denies share no drop path. Anything that cannot travel fails
// the job. A tag is a Core-side concept the runtime cannot resolve; an
// unparseable CIDR is a rule nothing can evaluate. Both are planning defects,
// and a planning defect that silently narrows an exclusion is the worst
// available outcome.
func scopePlan(rules []store.ScopeRule) (allowed, exclusions []string, err error) {
	for _, r := range rules {
		switch r.MatchType {
		case store.MatchCIDR:
			if _, perr := netip.ParsePrefix(r.MatchValue); perr != nil {
				// Core validates CIDR at planning (ADR-024 control 1). Without
				// this, `0.0.0.0/33` reaches the wire as an exclusion a runtime
				// cannot parse and will most likely skip — a deleted exclusion
				// again, one layer down.
				return nil, nil, fmt.Errorf("scope rule %s: %q is not a valid CIDR: %w",
					r.ID, r.MatchValue, perr)
			}
		case store.MatchHostname, store.MatchURL:
			if strings.TrimSpace(r.MatchValue) == "" {
				return nil, nil, fmt.Errorf("scope rule %s: empty %s value", r.ID, r.MatchType)
			}
		default:
			// tag, and anything a later migration adds to the enum. A new match
			// type that Core forwards without knowing how to evaluate is a rule
			// enforced nowhere; failing here means adding one has to come past
			// this switch.
			return nil, nil, fmt.Errorf("scope rule %s: match type %q cannot travel to a scan point",
				r.ID, r.MatchType)
		}

		switch r.Effect {
		case store.ScopeAllow:
			allowed = append(allowed, r.MatchValue)
		case store.ScopeDeny:
			exclusions = append(exclusions, r.MatchValue)
		default:
			return nil, nil, fmt.Errorf("scope rule %s: unknown effect %q", r.ID, r.Effect)
		}
	}
	return allowed, exclusions, nil
}

// The matcher itself lives in internal/scope, called from here and from the scan
// point runtime.
//
// ADR-024 wants two enforcement SITES, and it wants them to agree: "scope rules
// must be evaluated identically on both sides or valid scans are silently
// dropped". Two copies of this arithmetic would drift, and neither direction of
// drift announces itself — a target Core permits and the runtime denies is a
// scan that stops for no stated reason, and the reverse is a packet nobody
// authorised. scope_conformance_test.go runs this site over the shared table in
// internal/scope/scopetest; internal/scanpoint runs the other one over the same
// table.
//
// Core still cannot import the runtime and the runtime still cannot import Core.
// internal/scope depends on neither.
