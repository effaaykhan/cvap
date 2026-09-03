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

	"github.com/effaaykhan/cvap/internal/target"
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
// Addresses are compared after Unmap() on the RULE side. The target side needs
// none of that any more: internal/target reduced it to one form before this
// function ever saw it.
func Permits(t target.Canonical, allowed, exclusions []string) (bool, string) {
	if t.Value == "" {
		return false, "empty task target"
	}
	// The target arrives CANONICAL. Deciding what it is happened at planning,
	// in internal/target, and the runtime re-computed it independently before
	// calling here — so this function matches one string per host and does not
	// have to reason about notation at all. That narrowing is the point: three
	// audits found bypasses in the classification, and none of them can be
	// reached from a value that has already been reduced to one form.
	//
	// Rules are NOT canonical. They are policy text an operator wrote, so the
	// rule side still parses, trims and expands.
	targetStr := t.Value
	addr, isAddr := t.Addr, t.Kind == target.KindAddress

	// Exclusions EXPAND through translation; allows do not. ADR-039 records the
	// asymmetry, and both halves fail closed:
	//
	//   excluding 10.0.0.5 also excludes 64:ff9b::10.0.0.5, because the packet
	//   reaches the same host — an operator who excluded a medical device would
	//   otherwise find it scanned through a translator;
	//
	//   allowing 10.0.0.0/24 does NOT authorise 64:ff9b::10.0.0.5, because the
	//   operator authorised a v4 range and the translated form goes through
	//   infrastructure they may not own. An allowlist that silently widens is
	//   the failure ADR-037's permission/constraint split exists to prevent.
	// A URL is judged on the host it would reach, in BOTH directions.
	//
	// This started as an asymmetry — exclusions reach the host, allows do not —
	// and an audit showed the code did not implement it and could not: `addr`
	// comes from the normalised host, and the address branch of `matches` never
	// looks at the string, so a cidr allow already authorised every URL on that
	// address. The asymmetry held for hostname URLs only, which made the rule
	// depend on what the host happened to be rather than on anything a reader
	// could predict.
	//
	// Judged on the host in both directions is the coherent rule. Scope
	// authorises HOSTS: if the packet reaches a host the operator allowed, the
	// URL is in scope, and if it reaches one they excluded, it is not. What is
	// requested from that host is safety_mode's question (ADR-021), not this
	// one. ADR-039's allow/deny asymmetry still stands where it belongs — a
	// TRANSLATED form reaches a host through infrastructure the operator may
	// not own, which a path on an authorised host does not.
	for _, e := range exclusions {
		if matchesExclusion(e, targetStr, addr, isAddr) {
			return false, "excluded by scope rule " + e
		}
	}
	for _, a := range allowed {
		if matches(a, targetStr, addr, isAddr) {
			return true, ""
		}
	}
	if len(allowed) == 0 {
		return false, "the policy has no allow rules, which denies everything"
	}
	return false, "not covered by any allow rule"
}

// matchesExclusion is matches(), widened through translation.
//
// Two widenings, and the second is narrower than it looks:
//
//   - the TARGET may be a translated form, so its embedded v4 is tested against
//     the rule as well. This is the case an operator hits: they excluded
//     10.0.0.5 and something offered 64:ff9b::10.0.0.5.
//   - the RULE may be a translated ADDRESS, so its embedded v4 is tested
//     against the target. Someone who excluded 64:ff9b::10.0.0.5 plainly means
//     that host by either name.
//
// A translated PREFIX rule is deliberately not widened. `64:ff9b::/96` covers
// every IPv4 address in existence, so expanding it to v4 would turn one
// exclusion into a denial of the entire internet — an operator excluding their
// NAT64 range means the translated path, not every host reachable through it.
func matchesExclusion(rule, value string, addr netip.Addr, isAddr bool) bool {
	if matches(rule, value, addr, isAddr) {
		return true
	}

	// The target's embedded addresses, tested against the rule as written.
	var targetV4s []netip.Addr
	if isAddr {
		targetV4s = target.TranslatedV4s(addr)
		for _, v4 := range targetV4s {
			if matches(rule, v4.String(), v4, true) {
				return true
			}
		}
	}

	// And the rule's, tested against the target.
	//
	// parseRuleAddr rather than netip.ParseAddr: ParseAddr fails on anything
	// containing a slash, so a rule written as 64:ff9b::192.0.2.5/128 expanded
	// nothing — and that is the ONLY spelling a `cidr`-typed rule can use,
	// because scopePlan validates those with ParsePrefix and rejects the bare
	// form outright. For the natural match type for an address, this half of
	// the rule reached nothing at all.
	ruleAddr, ok := parseRuleAddr(rule)
	if !ok {
		return false
	}
	for _, ruleV4 := range target.TranslatedV4s(ruleAddr) {
		if isAddr && ruleV4 == addr {
			return true
		}
		// Embedded against embedded, so one translated form covers the same
		// host written in another. An operator who excluded the NAT64 form
		// means that host by every name it has, and there are five.
		for _, tv4 := range targetV4s {
			if ruleV4 == tv4 {
				return true
			}
		}
	}
	return false
}

// parseRuleAddr reads a rule as a single address, accepting the host-prefix
// spelling. It mirrors parseTargetAddr, which the target side has had all along.
func parseRuleAddr(rule string) (netip.Addr, bool) {
	rule = strings.TrimSpace(rule)
	if a, err := netip.ParseAddr(rule); err == nil {
		return a.WithZone("").Unmap(), true
	}
	if p, err := netip.ParsePrefix(rule); err == nil && p.Bits() == p.Addr().BitLen() {
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
func matches(rule, value string, addr netip.Addr, isAddr bool) bool {
	// Trimmed once, here, rather than in the hostname branch alone. A rule
	// stored with surrounding whitespace survives planning — scopePlan only
	// trims for its emptiness check — and an untrimmed address rule silently
	// stopped matching anything, which is a deleted exclusion with no signal.
	rule = strings.TrimSpace(rule)

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
		// Zone stripped on the rule side too. A zone names a local interface,
		// not a different host, and stripping it on only one side made
		// `fe80::1%eth0` as a RULE fail to cover `fe80::1` as a target.
		return isAddr && a.WithZone("").Unmap() == addr
	}
	// Hostnames compare with a trailing dot removed from both sides. The root
	// label is syntax, not a different name: `printer.corp.example.` resolves
	// to exactly what `printer.corp.example` does, and an exclusion that one
	// spelling defeats is not an exclusion.
	return strings.EqualFold(trimRoot(rule), trimRoot(strings.TrimSpace(value)))
}

func trimRoot(host string) string {
	return strings.TrimSuffix(host, ".")
}
