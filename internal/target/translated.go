package target

import "net/netip"

// Address translation: the IPv4 addresses an IPv6 form can be carrying.
//
// ============================================================================
// This lives here, in the leaf, because TWO subsystems need the same answer.
// ============================================================================
//
// ADR-039 established the rule for scope: an exclusion of 192.0.2.5 must also
// exclude 64:ff9b::192.0.2.5, because a packet to either reaches the host the
// operator excluded. `internal/scope` uses it for that.
//
// An ADR-compliance pass then found the same rule needed on the other side of
// the codebase, half-implemented: the OIDC issuer SSRF guard refuses private and
// link-local addresses, which is a refusal list and therefore exclusion-shaped,
// and it recognised exactly one of the five mechanisms — so a private address
// spelled `64:ff9b::a00:5` walked past it on any deployment with DNS64/NAT64,
// which is an ordinary IPv6-only subnet feature.
//
// Two half-implementations of the same rule is the divergence ADR-044 put
// canonicalisation in this package to prevent. One function, two callers.
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
// Exported because internal/scope and internal/control/api both need it, and
// neither may import the other.
func TranslatedV4s(a netip.Addr) []netip.Addr {
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
