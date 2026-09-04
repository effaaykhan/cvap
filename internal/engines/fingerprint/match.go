package fingerprint

import (
	"regexp"
	"strings"
)

// Matching: bytes a host returned, against rules the runtime handed over.
//
// ============================================================================
// This file evaluates rules. It does not contain any.
// ============================================================================
//
// Every pattern arrives on the wire, from a signed pack or the runtime's
// built-in set, filtered by a static safety policy this process cannot see and
// cannot widen. That is the same shape as the probe corpus and the rate slice:
// the engine cannot use what it was never given.

// Match is one rule. Mirrors enginewire.Match, which this package cannot import
// — the process shell translates (see cmd/cvap-engine-fingerprint).
type Match struct {
	Pattern    string
	Service    string
	Product    string
	Soft       bool
	Confidence float32
	OSHint     string
	Ports      []uint16

	// re is the compiled pattern, filled by compileMatches. A rule whose pattern
	// will not compile is DROPPED there rather than skipped here, so a bad
	// pattern cannot silently mean "matches nothing" once per response.
	re *regexp.Regexp
}

// Result is what a rule produced.
type Result struct {
	Service    string
	Product    string
	Version    string
	Info       string
	OSHint     string
	Confidence float32

	// Soft is derived, not copied.
	//
	// A rule declares Soft as intent, and the RESOLVED product is what decides:
	// the generic `Server: (?P<product>...)` rule carries no Product field and
	// still names a product through a capture group, and a rule that matched with
	// nothing to show for it is soft whatever it declared. Recomputing here means
	// the two cannot disagree.
	Soft bool

	// Pattern is the rule that fired, carried into the observation so a service
	// claim can be traced to the exact rule that made it.
	Pattern string
}

// compileMatches prepares rules for evaluation, dropping any that will not
// compile.
//
// The runtime already refused uncompilable patterns before sending them
// (internal/scanpoint/corpus.go), so this is the second of the two sites. It is
// here anyway because "the sender validated it" is an assumption, and the
// failure mode it protects against — a rule that silently matches nothing — is
// invisible by construction.
func compileMatches(in []Match) []Match {
	out := make([]Match, 0, len(in))
	for _, m := range in {
		re, err := regexp.Compile(m.Pattern)
		if err != nil {
			continue
		}
		m.re = re
		out = append(out, m)
	}
	return out
}

// latin1 maps each byte of a response to the rune of the same value.
//
// ============================================================================
// A banner is BYTES. Without this, every pattern with a high byte matches
// nothing.
// ============================================================================
//
// Go regexps run over UTF-8. A response containing the byte 0xff — Telnet's IAC,
// the first byte of a MySQL error packet — is not valid UTF-8, and a pattern
// written as `\xff` compiles to the rune U+00FF, which encodes as two bytes and
// therefore never matches the one byte that is actually there.
//
// Mapping byte to rune makes `\xff` mean the byte 0xff and `.` mean exactly one
// byte, which is what a pattern author writing a binary protocol rule expects.
// The cost is one allocation per response, against a read already bounded by
// ReadBytes.
func latin1(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		sb.WriteRune(rune(c))
	}
	return sb.String()
}

// evaluate runs rules against a response, first hit wins.
//
// Ordering is the caller's: rules that name a product precede the generic rule
// for their protocol, so the specific answer is reached before the vague one.
func evaluate(rules []Match, response []byte, port uint16) (Result, bool) {
	subject := latin1(response)
	for _, m := range rules {
		if !appliesTo(m.Ports, port) {
			continue
		}
		hit := m.re.FindStringSubmatch(subject)
		if hit == nil {
			continue
		}
		r := Result{
			Service:    m.Service,
			Product:    m.Product,
			OSHint:     m.OSHint,
			Confidence: m.Confidence,
			Pattern:    m.Pattern,
		}
		for i, name := range m.re.SubexpNames() {
			if i >= len(hit) || hit[i] == "" {
				continue
			}
			switch name {
			case "version":
				r.Version = strings.TrimSpace(hit[i])
			case "product":
				// A capture beats the rule's static Product, which is empty
				// whenever a rule uses this group. One rule then covers every
				// server that names itself in the conventional shape.
				r.Product = strings.TrimSpace(hit[i])
			case "info":
				r.Info = strings.TrimSpace(hit[i])
			}
		}
		r.Soft = r.Product == ""
		return r, true
	}
	return Result{}, false
}

// appliesTo reports whether a port-scoped rule or probe covers this port.
//
// Empty means every port. For a MATCH that is the common case — a pattern
// naming a product is evidence wherever it appears. For a PROBE the runtime
// refuses it outright, because "every open port" includes the ones where bytes
// are not inert.
func appliesTo(ports []uint16, port uint16) bool {
	if len(ports) == 0 {
		return true
	}
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}
