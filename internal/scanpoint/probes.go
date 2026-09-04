package scanpoint

import "github.com/effaaykhan/cvap/internal/enginewire"

// The probe corpus lives HERE, in the runtime, and not in the engine.
//
// ============================================================================
// An engine holds no probes, so "safe mode" is not a branch it could get wrong.
// ============================================================================
//
// ADR-021 makes safe the default for every policy, which means it is the mode
// most deployments run and the one that must be unable to provoke anything. Two
// ways to get that: tell the engine which mode it is in and trust it, or hand it
// nothing to send. The second is the same shape as ADR-027's rate budget — the
// engine cannot exceed an allocation it was never given — and it is the one that
// survives a bug in the engine, a rule that asks for a probe, and an engine
// written by somebody else later.
//
// # What counts as safe
//
// SAFE reads what a service volunteers on connect and sends nothing. SSH, FTP,
// SMTP, POP3, IMAP and MySQL all announce themselves; a connect and a bounded
// read identify them without a byte leaving in the other direction.
//
// INTRUSIVE sends one of these. The cost of the line is concrete and worth
// naming rather than discovering: **HTTP does not volunteer**, so in safe mode a
// web server is an open port with no service attached. That is the trade ADR-021
// asks for — the default mode identifies less — and it is why the mode is
// recorded on every observation rather than inferred later.
//
// # Why these are small and dull
//
// Each is a minimal, well-formed request that any conforming server answers, and
// none of them is a payload that achieves anything. Invariant 9: detection
// establishes evidence without achieving impact. A probe that exercised a parser
// bug to identify a version would be an exploit with a fingerprinting
// justification.

// ProbeCorpus is what an intrusive job may send.
//
// Returned as a fresh slice each call. The runtime hands this to an engine over
// a pipe and a shared backing array would be a mutable global reachable from the
// job path — cheap to avoid, and the kind of aliasing nobody finds later.
func ProbeCorpus() []enginewire.Probe {
	return []enginewire.Probe{
		{
			// The one that matters most, because HTTP is silent until asked.
			//
			// HEAD rather than GET: it returns the status line and headers,
			// which is everything a service identification needs, and no body —
			// so a probe against an unexpected endpoint cannot pull a megabyte
			// of content back through the scan point.
			//
			// Host is required by HTTP/1.1 and a bare "*" is not valid for it,
			// so a literal placeholder travels; the engine substitutes the
			// target it was authorised for and constructs no other.
			Name:      "http-head",
			Ports:     []uint32{80, 81, 88, 591, 8000, 8008, 8080, 8081, 8443, 8888},
			Payload:   []byte("HEAD / HTTP/1.1\r\nHost: {{target}}\r\nUser-Agent: CVAP\r\nConnection: close\r\nAccept: */*\r\n\r\n"),
			ReadBytes: 8 << 10,
		},
		{
			// A newline, to services that answer a bare line with a usage
			// message or an error banner. Costs one byte and identifies several
			// text protocols that stay silent on connect.
			Name:      "newline",
			Payload:   []byte("\r\n"),
			ReadBytes: 4 << 10,
		},
	}
}

// ProbeTargetPlaceholder is what an engine substitutes with the target it was
// given.
//
// A placeholder rather than a target-shaped field, so that the corpus stays a
// constant and the only address a probe can carry is the one the runtime already
// authorised. An engine that could compose its own Host header could name a host
// nobody approved — which is target construction, and ADR-027 forbids it.
const ProbeTargetPlaceholder = "{{target}}"
