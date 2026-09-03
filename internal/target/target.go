// Package target turns whatever an operator wrote into the one form the system
// stores, compares and sends.
//
// # Why canonicalisation is a package and why it runs at planning
//
// Three consecutive scan-safety audits found the same class of defect in
// scope matching: a host can be named many ways, and a decision made about one
// spelling said nothing about the others. v4-mapped prefixes, then NAT64/6to4/
// Teredo/ISATAP, then ports, brackets, root labels, hex and octal integer forms
// and hyphen ranges. Each fix was correct and each left a neighbouring notation
// open, because the question kept being "what spellings reach this host" and
// that answer space is larger than it looks from inside any one fix.
//
// The answer that generalises is to stop comparing spellings. A target is
// canonicalised ONCE, at decomposition, and `scan_tasks.task_target` holds that
// canonical form. Everything downstream — the matcher, the wire, an engine, a
// future per-target rate budget — sees one string per host.
//
// This narrows internal/scope, which is the point: it no longer classifies a
// target, only matches one. Rules are still arbitrary operator text and still
// need their own handling, because a rule is policy rather than a target.
//
// # Refusing is part of the contract
//
// A string that NAMES an address and will not parse as one is refused rather
// than passed along as a hostname (ADR-040), at three places and for three
// different audiences:
//
//   - at scan CREATION, where an operator is standing in front of the error;
//   - at PLANNING, because a scan_targets row can be written by something other
//     than that handler, and because that is where the canonical form is
//     produced (ADR-044);
//   - at the scan point, where the question is not "is this canonical" but
//     "is this MY canonical form of this" — see Matches.
//
// The first of those is a courtesy and the other two are the control. An earlier
// version of this comment claimed only the first, at a time when the handler did
// not call this package at all.
//
// This package is a leaf. Both Core and the scan point runtime import it, so it
// may depend on neither.
package target

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

// Kind is what a canonical target turned out to be.
type Kind int

const (
	// KindAddress is a single host.
	KindAddress Kind = iota
	// KindPrefix is a range. It reaches the matcher unchanged: no allow rule
	// covers a range-shaped target, which is fail-safe and long-standing.
	KindPrefix
	// KindHostname is a name nothing here resolves. Resolution at decision time
	// is a different answer from the one a scan point would get, and an
	// allowlist that depends on which side asked is not an allowlist.
	KindHostname
)

func (k Kind) String() string {
	switch k {
	case KindAddress:
		return "address"
	case KindPrefix:
		return "prefix"
	default:
		return "hostname"
	}
}

// Canonical is a target in the one form the system stores.
//
// Value is what goes in scan_tasks.task_target and on the wire. The typed
// fields are what the matcher uses, so it never re-parses the string.
type Canonical struct {
	Value  string
	Kind   Kind
	Addr   netip.Addr
	Prefix netip.Prefix
}

// ErrNotCanonical means a string names an address and does not parse as one.
var ErrNotCanonical = errors.New("target: names an address and does not parse as one")

// MaxLength bounds a target before any of this runs.
//
// The value reaches an audit event, a log line and a wire message. Everything
// here is linear in its length, but a megabyte of digits is still a megabyte
// copied into three places to say it was refused.
const MaxLength = 512

// Canonicalise turns a raw target into the one form the system uses.
//
// Normalisation removes only notation that does not change WHICH HOST is
// reached: a port, surrounding brackets, the DNS root label, and a URL's
// path/query/fragment. It does not touch userinfo, which changes who the
// request authenticates as, and it does not resolve anything.
func Canonicalise(raw string) (Canonical, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Canonical{}, fmt.Errorf("%w: empty target", ErrNotCanonical)
	}
	if len(s) > MaxLength {
		return Canonical{}, fmt.Errorf("%w: target is %d bytes, over the %d limit",
			ErrNotCanonical, len(s), MaxLength)
	}

	host := s
	// A URL is judged on the host it would reach. url.Parse accepts almost
	// anything, so a scheme AND a host are both required — otherwise
	// "192.0.2.5:443" parses as scheme "192.0.2.5" with opaque "443", which is
	// exactly the string this function exists to catch.
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		host = u.Host
	}

	host, bracketed := normaliseHost(host)
	if host == "" {
		return Canonical{}, fmt.Errorf("%w: %s has no host", ErrNotCanonical, quote(raw))
	}

	if a, err := netip.ParseAddr(host); err == nil {
		a = a.WithZone("").Unmap()
		return Canonical{Value: a.String(), Kind: KindAddress, Addr: a}, nil
	}
	// A bare host written as a full-length prefix is that host.
	if p, err := netip.ParsePrefix(host); err == nil {
		if p.Bits() == p.Addr().BitLen() {
			a := p.Addr().WithZone("").Unmap()
			return Canonical{Value: a.String(), Kind: KindAddress, Addr: a}, nil
		}
		// Masked, so 192.0.2.5/24 and 192.0.2.0/24 are one range rather than
		// two spellings of it.
		m := p.Masked()
		return Canonical{Value: m.String(), Kind: KindPrefix, Prefix: m}, nil
	}

	if bracketed || LooksLikeAddress(host) {
		return Canonical{}, fmt.Errorf("%w: %s", ErrNotCanonical, quote(raw))
	}

	// A hostname. Lowercased and root-stripped, so one name has one spelling.
	return Canonical{Value: strings.ToLower(host), Kind: KindHostname}, nil
}

// Matches reports whether a raw string is already in canonical form.
//
// ============================================================================
// The scan point's second site RE-COMPUTES. It does not validate.
// ============================================================================
//
// A runtime that asked "is this canonical" would accept a canonical form of the
// WRONG HOST, which is precisely what a bug in Core's canonicalisation
// produces — and three sessions of scope findings say to expect one. Asking
// instead "does my own canonicalisation of this string equal what arrived"
// makes the second site an independent computation whose result can disagree,
// which is what ADR-024's "neither side trusts the other" actually requires.
//
// One function run twice on two machines is not two implementations. The
// comparison catches a target mutated in transit, a Core that skipped the step,
// and a Core whose step produced something else.
func Matches(raw string) (Canonical, bool) {
	c, err := Canonicalise(raw)
	if err != nil {
		return Canonical{}, false
	}
	// Compared against raw UNCHANGED. Trimming first — or any other tidying
	// before the comparison — reintroduces exactly the tolerance this function
	// exists to remove: it would make " 192.0.2.5" equal to its canonical form,
	// which is the shape of "close enough" that a validator has and a
	// re-computation does not.
	return c, c.Value == raw
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

	if h, port, err := net.SplitHostPort(host); err == nil && h != "" && validPort(port) {
		return strings.TrimSuffix(strings.TrimSpace(h), "."), bracketed
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		inner := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		return strings.TrimSuffix(strings.TrimSpace(inner), "."), true
	}
	return strings.TrimSuffix(host, "."), bracketed
}

// validPort is what makes SplitHostPort safe to use here.
//
// SplitHostPort does not validate the port: it splits on the LAST colon and
// hands back whatever follows. So "https://printer.corp.example /x" split into
// host "https" and port "//printer.corp.example /x", and normalisation then
// reported the scheme as the host — which disabled every downstream check at
// once. An audit found it; this is the guard.
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

// LooksLikeAddress reports whether a string is trying to be an IP address.
//
// A test on the COMPONENTS, not on the character set. "Digits, dots and
// slashes" is an enumeration of two spellings, and an audit walked past it with
// 0xC0000205, 0xC0.0x00.0x02.0x05, 192.0.0x2.5, 192.0.2.1-50 and
// 192.0.2.5,192.0.2.6 — each of which reaches 192.0.2.5, or a range containing
// it, under inet_aton semantics.
//
// The question that generalises is whether every component is a number. Split
// on the separators an address or an address range can use, and ask whether each
// piece parses as an integer in some base; ParseUint with base 0 gives decimal,
// 0-octal and 0x-hex in one call, which is the set inet_aton accepts. Bare hex
// is not a number to it, so dead.beef and 1host.corp.example stay hostnames —
// which is what stops this over-refusing.
func LooksLikeAddress(s string) bool {
	if s == "" {
		return false
	}
	// Unicode decimal digits fold to ASCII for the SHAPE test only. UTS-46 maps
	// them before resolution, so a fullwidth form reaches a v4 host — and must
	// not reach hostname comparison on the way. The unfolded string is what
	// gets parsed, so a folded-only match still ends in a refusal rather than a
	// silent reinterpretation.
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

func foldDigits(s string) string {
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r > 0x7f && unicode.IsDigit(r) {
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
