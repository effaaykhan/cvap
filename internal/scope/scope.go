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
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
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

	addr, isAddr, host, refuse := classifyTarget(target)
	if refuse != "" {
		// A string that NAMES an address and will not parse as one. Refused
		// outright rather than compared as a hostname — see classifyTarget.
		return false, refuse
	}

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
		if matchesExclusion(e, target, addr, isAddr) ||
			(host != target && matchesExclusion(e, host, addr, isAddr)) {
			return false, "excluded by scope rule " + e
		}
	}
	for _, a := range allowed {
		if matches(a, target, addr, isAddr) ||
			(host != target && matches(a, host, addr, isAddr)) {
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

// classifyTarget decides what kind of thing a task target is.
//
// ============================================================================
// A string that names an address and will not parse as one is refused.
// ============================================================================
//
// Everything unparseable used to fall through to case-insensitive string
// equality against hostname rules, which is the wrong matcher for a string that
// names an address: `192.0.2.5:443`, `[192.0.2.5]` and `192.0.2.5.` are one host
// wearing notation, and no CIDR or address exclusion could reach any of them. A
// scan-safety audit demonstrated it through supported configuration — a
// hostname- or url-typed allow carrying the same string — so an operator's
// exclusion of a device could be walked past by writing its address with a port.
//
// Three branches, and ADR-040 records why the middle one exists:
//
//   - It normalises and PARSES. Then it is an address, and IP rules apply.
//     Normalisation strips a port, brackets and the DNS root label, because none
//     of those changes which host is reached — the same argument that makes
//     ::ffff: a notation rather than a route (ADR-039).
//   - It plainly is not an address — it has letters outside a URL host, so no
//     notation of an address could produce it. Hostname equality, as before. A
//     genuine target like scanner.example.com is unaffected, and so is one that
//     merely starts with a digit, which the obvious leading-character test would
//     have refused.
//   - It LOOKS like an address and will not parse. Refused, and the caller fails
//     the whole job: skipping the target would leave a scan reporting success
//     over coverage it did not have, which is the under-scanning-that-looks-
//     clean failure this package refuses everywhere else.
//
// A URL is unwrapped to its host first, so a url-typed target is judged on the
// host it would reach rather than on its own punctuation.
func classifyTarget(target string) (addr netip.Addr, isAddr bool, host, refuse string) {
	host = target

	// A URL is judged on its host. url.Parse accepts almost anything, so a
	// scheme AND a host are both required before treating it as one — otherwise
	// "192.0.2.5:443" parses as scheme "192.0.2.5" with opaque "443", which is
	// exactly the string this function exists to catch. u.Host is set only when
	// an authority was parsed, which already implies "//"; no separate check for
	// it, because a contains-anywhere test would not constrain the position and
	// would read as load-bearing when it is not.
	if u, err := url.Parse(target); err == nil && u.Scheme != "" && u.Host != "" {
		host = u.Host
	}

	host, bracketed := normaliseHost(host)
	if host == "" {
		return netip.Addr{}, false, target, "task target " + quote(target) + " has no host"
	}

	if a, ok := parseTargetAddr(host); ok {
		return a, true, host, ""
	}
	// A range target parses as a prefix and is left alone: matching treats it as
	// it always has, which is to say no CIDR allow covers it. Not refused,
	// because it is well formed — see the case in scopetest.
	if _, err := netip.ParsePrefix(host); err == nil {
		return netip.Addr{}, false, host, ""
	}

	// Brackets are an address signal in themselves, and they are consumed by
	// normalisation — so the fact of them has to travel. Without this,
	// "[ 192.0.2.5 ]" lost its strongest signal before the test ran.
	if bracketed || looksLikeAddress(host) {
		return netip.Addr{}, false, host,
			"task target " + quote(target) + " names an address and does not parse as one"
	}
	return netip.Addr{}, false, host, ""
}

// normaliseHost removes notation that does not change which host is reached,
// and reports whether the form was bracketed.
//
// Port stripping is tried BEFORE the bare-bracket case, because "[v6]:port" has
// to reach SplitHostPort intact — stripping the brackets first would leave
// "v6]:port", which is not a host.
func normaliseHost(host string) (string, bool) {
	host = strings.TrimSpace(host)
	bracketed := strings.HasPrefix(host, "[") || strings.Contains(host, "]")

	// "[v6]:port" and "host:port".
	if h, port, err := net.SplitHostPort(host); err == nil && h != "" && validPort(port) {
		return strings.TrimSuffix(strings.TrimSpace(h), "."), bracketed
	}

	// A bare "[v6]", with whatever whitespace was inside it.
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		inner := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		return strings.TrimSuffix(strings.TrimSpace(inner), "."), true
	}

	// The DNS root label, for the no-port case.
	return strings.TrimSuffix(host, "."), bracketed
}

// validPort is what makes SplitHostPort safe to use here.
//
// SplitHostPort does not validate the port: it splits on the LAST colon and
// hands back whatever follows. So "https://printer.corp.example /x" split
// cleanly into host "https" and port "//printer.corp.example /x", and the whole
// normalisation then reported the scheme as the host — which disabled the
// exclusion check and the shape test at once, because "https" is neither the
// target nor address-shaped. Every malformed URL took that path.
func validPort(port string) bool {
	if port == "" || len(port) > 5 {
		return false
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 0 && n <= 65535
}

// looksLikeAddress reports whether a string is trying to be an IP address.
//
// ============================================================================
// A test on the COMPONENTS, not on the character set.
// ============================================================================
//
// The first version asked whether the string was digits, dots and slashes. That
// is an enumeration of two spellings, which is the failure ADR-040 criticises in
// its own rejected alternatives — and an audit walked straight past it with
// 0xC0000205, 0xC0.0x00.0x02.0x05, 192.0.0x2.5, 192.0.2.1-50 and
// 192.0.2.5,192.0.2.6. Every one reaches 192.0.2.5 (or a range containing it)
// through inet_aton semantics, and every one fell through to hostname equality
// where no address exclusion could touch it. The hyphen range is the one that
// matters most: it is how an operator writes a range by hand, and it names up
// to 256 hosts.
//
// The question that generalises is whether every COMPONENT is a number. Split on
// the separators an address or an address range can use — dot, slash, hyphen,
// comma — and ask whether each piece parses as an integer in some base.
// ParseUint with base 0 gives decimal, 0-octal and 0x-hex in one call, which is
// exactly the set inet_aton accepts.
//
// This does not over-refuse hostnames, because bare hex is not a number to
// ParseUint: "dead.beef" and "cafe.example" are hostnames, while "0xdead.0xbeef"
// is not. "1host.corp.example" stays a hostname for the same reason, which is
// why the obvious leading-digit test was wrong.
//
// A colon or a bracket is still decisive on its own: a hostname contains
// neither, and normaliseHost has already removed a valid port.
func looksLikeAddress(s string) bool {
	if s == "" {
		return false
	}
	// Fullwidth and other Unicode decimal digits are folded to ASCII for the
	// SHAPE test only. UTS-46 maps them before resolution, so "２.０.２.５"
	// reaches 2.0.2.5 — and it must not reach hostname equality on the way.
	// The unfolded string is what gets parsed, so a folded-only match still
	// ends in a refusal rather than in a silent reinterpretation.
	s = foldDigits(s)

	if strings.ContainsAny(s, ":[]") {
		return true
	}

	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == '.' || r == '/' || r == '-' || r == ','
	})
	if len(fields) == 0 {
		return false
	}
	for _, f := range fields {
		if _, err := strconv.ParseUint(f, 0, 64); err != nil {
			return false
		}
	}
	return true
}

// foldDigits maps Unicode decimal digits onto ASCII.
func foldDigits(s string) string {
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r > 0x7f && unicode.IsDigit(r) {
			// digitValue returns 0-9 by construction, so the addition cannot
			// leave ASCII — but it is written as a rune throughout rather than
			// converted, because an int-to-rune conversion is the shape that
			// wraps and gosec is right to ask about it.
			b.WriteRune('0' + digitValue(r))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// digitValue returns 0-9 for any Unicode decimal digit.
//
// Every Unicode decimal-digit block is ten contiguous code points in order, so
// counting back to the first non-digit gives the value without a lookup table.
func digitValue(r rune) rune {
	for v := rune(0); v < 10; v++ {
		if !unicode.IsDigit(r - v) {
			return v - 1
		}
	}
	return 9
}

// quote renders a target for an operator-facing reason without letting a
// control character reach a log line or an audit detail.
func quote(s string) string {
	const max = 100
	if len(s) > max {
		s = s[:max] + "..."
	}
	return strconv.Quote(s)
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
