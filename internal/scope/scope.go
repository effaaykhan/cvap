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
	for _, e := range exclusions {
		if matchesExclusion(e, target, addr, isAddr) {
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

// Translation prefixes that carry an IPv4 address inside an IPv6 one.
//
// Each of these is a real, routable IPv6 address that reaches a v4 host through
// translating infrastructure — which is what makes them different from
// ::ffff:0:0/96. A v4-mapped address is a NOTATION for a v4 address inside a
// socket API; it is not routable as IPv6 and reaches the host by the same path
// the bare v4 form does. That is why Unmap applies in both directions and these
// apply only to exclusions.
var (
	// RFC 6052 well-known prefix. The v4 address is the low 32 bits.
	//
	// Only the well-known prefix. A network-specific NAT64 prefix (RFC 6052 §2.2)
	// can be any of five lengths with the v4 address at a different offset in
	// each, and guessing which one a /96-looking address uses would produce
	// wrong extractions — an exclusion matching a host it does not name is as
	// bad as one missing the host it does.
	nat64 = netip.MustParsePrefix("64:ff9b::/96")

	// RFC 3056. The v4 address is bytes 2-5.
	sixToFour = netip.MustParsePrefix("2002::/16")

	// RFC 4380. The client's v4 address is the low 32 bits, obfuscated by
	// XOR with all ones — so it must be inverted, not simply read.
	teredo = netip.MustParsePrefix("2001::/32")

	// RFC 4291 IPv4-compatible, deprecated and still routed by things that
	// have not noticed. The v4 address is the low 32 bits.
	v4Compatible = netip.MustParsePrefix("::/96")
)

// translatedV4s returns every IPv4 address an IPv6 form could be carrying.
//
// A SLICE rather than one answer, and the reason is ISATAP. Its marker is an
// interface identifier rather than a prefix, so an address can satisfy two
// mechanisms at once — an ISATAP identifier inside 2002::/16, say — and picking
// one by switch order would silently discard the other. For exclusions, testing
// every candidate over-matches, which is the direction that fails closed; a
// wrong single extraction matches a host the operator never named, which the
// audit that found this rightly called as bad as missing one.
//
// Only for exclusions. See Permits.
func translatedV4s(a netip.Addr) []netip.Addr {
	if !a.Is6() || a.Is4In6() {
		return nil
	}
	b := a.As16()
	low := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})

	var out []netip.Addr
	add := func(v4 netip.Addr) {
		// 0.0.0.0 and 255.255.255.255 are not hosts a scan reaches, and every
		// mechanism produces one of them for its own bare prefix — 2002:: and
		// 64:ff9b:: give the unspecified address, 2001:: gives the broadcast.
		// Reading those as addresses would make an exclusion of either match a
		// prefix that names no host at all.
		if !v4.IsValid() || v4.IsUnspecified() || v4 == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			return
		}
		// ::1 is the loopback written inside ::/96 and names nothing either.
		if v4 == netip.AddrFrom4([4]byte{0, 0, 0, 1}) {
			return
		}
		for _, seen := range out {
			if seen == v4 {
				return
			}
		}
		out = append(out, v4)
	}

	if nat64.Contains(a) {
		add(low)
	}
	if sixToFour.Contains(a) {
		add(netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]}))
	}
	if teredo.Contains(a) {
		add(netip.AddrFrom4([4]byte{^b[12], ^b[13], ^b[14], ^b[15]}))
	}
	if v4Compatible.Contains(a) {
		add(low)
	}
	// ISATAP (RFC 5214): the interface identifier carries the marker, so it is
	// independent of the prefix and appears under link-local and global ones
	// alike. Detectable exactly as reliably as the prefix-based mechanisms —
	// bytes 8-11 are 00:00:5e:fe or 02:00:5e:fe and the v4 is the low 32 bits —
	// which is why declining it would not have the justification RFC 6052 §2.2
	// gives. Still common in Windows enterprise networks, which is the estate
	// this product is aimed at.
	if (b[8] == 0x00 || b[8] == 0x02) && b[9] == 0x00 && b[10] == 0x5e && b[11] == 0xfe {
		add(low)
	}
	return out
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
func matchesExclusion(rule, target string, addr netip.Addr, isAddr bool) bool {
	if matches(rule, target, addr, isAddr) {
		return true
	}

	// The target's embedded addresses, tested against the rule as written.
	var targetV4s []netip.Addr
	if isAddr {
		targetV4s = translatedV4s(addr)
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
	for _, ruleV4 := range translatedV4s(ruleAddr) {
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
	return strings.EqualFold(trimRoot(rule), trimRoot(strings.TrimSpace(target)))
}

func trimRoot(host string) string {
	return strings.TrimSuffix(host, ".")
}
