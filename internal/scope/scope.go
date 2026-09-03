// Package scope decides whether one target is inside a job's authorised scope.
//
// # Why this is a package and not a method on either side
//
// ADR-024 control 1 requires scope to be enforced at exactly two sites: Core at
// planning, and the scan point runtime on the send path. Neither side trusts the
// other, and the ADR rejected collapsing them — Core alone leaves a planning bug
// with no second line of defence, and the scan point alone relies on a check
// running in a months-old build we do not control.
//
// Two enforcement SITES is the requirement. Two IMPLEMENTATIONS is not, and
// would be a defect: ADR-024's own Consequences say scope rules "must be
// evaluated identically on both sides or valid scans are silently dropped", and
// a divergence between two copies of this logic announces itself in neither
// direction. A target Core permits and the runtime denies is a scan that stops
// for no stated reason; one the runtime permits and Core denies is a packet
// nobody authorised.
//
// So: one function, called from both sites, with the arguments each site holds.
// internal/scope/scopetest carries the case table both sites are tested against,
// which is what keeps the two callers honest about HOW they call it — a site
// that stopped passing exclusions would still compile and still pass its own
// unit tests.
//
// This package is a leaf on purpose. The scan point runtime may not import
// internal/store or internal/control (see internal/scanpoint/CLAUDE.md), so
// anything shared with Core has to depend on neither.
package scope

import (
	"net/netip"
	"strings"
)

// Permits answers whether one target is in scope, and why not if it is not.
//
// Exclusions are evaluated first and win outright, regardless of ordering or of
// any precedence value the rules carried before they reached the wire: ADR-024
// says exclusions take precedence over allows, full stop.
//
// An EMPTY allowlist denies everything. Empty and absent are indistinguishable
// in proto3, so they must mean the same thing, and for a field whose other
// reading is "scan anything" the safe reading is the only defensible one
// (ADR-037). This is the one list in the system whose empty case denies; the
// policy's zone and window lists are constraints and read the other way, which
// is the asymmetry ADR-037 exists to record.
//
// Addresses are compared after Unmap(), on both the rule and the target. Without
// it an exclusion of 10.10.0.5 does not exclude ::ffff:10.10.0.5, and an
// exclusion written as ::ffff:10.10.0.0/120 excludes nothing at all — the same
// host wearing a different notation, which is the oldest way there is past an
// IP-based denylist.
func Permits(target string, allowed, exclusions []string) (bool, string) {
	target = strings.TrimSpace(target)
	if target == "" {
		return false, "empty task target"
	}

	addr, isAddr := parseTargetAddr(target)

	for _, e := range exclusions {
		if matches(e, target, addr, isAddr) {
			return false, "excluded by scope rule " + e
		}
	}
	for _, a := range allowed {
		if matches(a, target, addr, isAddr) {
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
		// WithZone("") strips an IPv6 zone before any comparison.
		//
		// netip.Prefix.Contains returns false for ANY zoned address, and Addr
		// equality includes the zone — so `fe80::1%eth0` was not excluded by a
		// rule naming `fe80::1`, and no CIDR exclusion could ever match a zoned
		// target at all. A zone identifies a local interface, not a different
		// host, so it must not be able to carry a target out of scope.
		return a.WithZone("").Unmap(), true
	}
	// A bare host in CIDR form, e.g. a task target written as 10.0.0.5/32.
	if p, err := netip.ParsePrefix(target); err == nil && p.Bits() == p.Addr().BitLen() {
		return p.Addr().WithZone("").Unmap(), true
	}
	return netip.Addr{}, false
}

// matches compares one rule value against one target.
//
// A CIDR rule matches only an address. A hostname rule matches only by exact,
// case-insensitive string equality: nothing here resolves DNS, deliberately,
// because a resolution done at planning is a different answer from the one the
// scan point would get, and an allowlist that depends on which side asked is not
// an allowlist. The consequence is stated rather than hidden — a hostname rule
// does not cover the address that name resolves to, in either direction.
func matches(rule, target string, addr netip.Addr, isAddr bool) bool {
	if p, err := netip.ParsePrefix(rule); err == nil {
		// The rule is unmapped as well as the target. Only the target was, so
		// an exclusion written as ::ffff:10.0.0.0/120 did not cover 10.0.0.5 —
		// while the bare-address form ::ffff:10.0.0.5 did, because that path
		// calls Unmap(). An asymmetry that deletes an exclusion, which is the
		// direction ADR-024 cannot afford.
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
	// Hostnames compare with a trailing dot removed from both sides. The root
	// label is syntax, not a different name: `printer.corp.example.` resolves
	// to exactly what `printer.corp.example` does, and an exclusion that one
	// spelling defeats is not an exclusion.
	return strings.EqualFold(trimRoot(strings.TrimSpace(rule)), trimRoot(target))
}

func trimRoot(host string) string {
	return strings.TrimSuffix(host, ".")
}
