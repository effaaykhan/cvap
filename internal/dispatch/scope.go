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

// permits answers whether one task target is in scope, and why not if it is not.
//
// Exclusions are evaluated first and win outright, regardless of precedence
// value or ordering (ADR-024). An empty allowlist denies everything: empty and
// absent are indistinguishable in proto3, so they must mean the same thing, and
// for a field whose other reading is "scan anything" the safe reading is the
// only defensible one.
//
// Addresses are compared after Unmap(). Without it, an exclusion of 10.10.0.5
// does not exclude ::ffff:10.10.0.5, which is the same host wearing a different
// notation — the oldest way there is to walk past an IP-based denylist.
func permits(target string, allowed, exclusions []string) (bool, string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return false, "empty task target"
	}

	addr, isAddr := parseTargetAddr(target)

	for _, e := range exclusions {
		if scopeMatches(e, target, addr, isAddr) {
			return false, "excluded by scope rule " + e
		}
	}
	for _, a := range allowed {
		if scopeMatches(a, target, addr, isAddr) {
			return true, ""
		}
	}
	if len(allowed) == 0 {
		return false, "the policy has no allow rules, which denies everything"
	}
	return false, "not covered by any allow rule"
}

func parseTargetAddr(target string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(target); err == nil {
		return a.Unmap(), true
	}
	// A bare host in CIDR form, e.g. a task target written as 10.0.0.5/32.
	if p, err := netip.ParsePrefix(target); err == nil && p.Bits() == p.Addr().BitLen() {
		return p.Addr().Unmap(), true
	}
	return netip.Addr{}, false
}

// scopeMatches compares one rule value against one target.
//
// A CIDR rule matches only an address. A hostname rule matches only by exact,
// case-insensitive string equality: nothing here resolves DNS, deliberately,
// because a resolution done at planning is a different answer from the one the
// scan point would get, and an allowlist that depends on which side asked is not
// an allowlist. The consequence is stated rather than hidden — a hostname rule
// does not cover the address that name resolves to, in either direction.
func scopeMatches(rule, target string, addr netip.Addr, isAddr bool) bool {
	if p, err := netip.ParsePrefix(rule); err == nil {
		// The rule is unmapped as well as the target. Only the target was, so
		// an exclusion written as ::ffff:10.0.0.0/120 did not cover 10.0.0.5 —
		// while the bare-address form ::ffff:10.0.0.5 did, because that path
		// calls Unmap(). An asymmetry that deletes an exclusion, which is the
		// direction ADR-024 cannot afford: the v4-mapped form of an address is
		// the oldest way there is to walk past an IP denylist, and writing the
		// DENY in that form must not be the way to disarm it.
		//
		// The prefix length moves with the address: a v4-mapped /120 covers the
		// same hosts as a v4 /24, so 96 comes off the bits. A prefix shorter
		// than /96 is not naming a v4 range at all — Prefix() rejects the
		// negative and the rule is left exactly as written.
		if a := p.Addr(); a.Is4In6() {
			if q, err := p.Addr().Unmap().Prefix(p.Bits() - 96); err == nil {
				p = q
			}
		}
		return isAddr && p.Contains(addr)
	}
	if a, err := netip.ParseAddr(rule); err == nil {
		return isAddr && a.Unmap() == addr
	}
	return strings.EqualFold(strings.TrimSpace(rule), target)
}
