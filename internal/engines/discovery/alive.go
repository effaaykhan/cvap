package discovery

import (
	"context"
	"errors"
	"net"
	"strconv"
)

// Host discovery: is anything there, and how do we know.
//
// ============================================================================
// "Not alive" is a statement about what was OBSERVED, never a claim of absence.
// ============================================================================
//
// Connect scanning cannot tell a fully filtered host from one that is not there
// — both give nothing back. That is the accepted cost of TCP-only discovery
// (ADR-047), and the honest way to carry it is in the observation: every host
// result names the METHOD that produced it, and a negative carries a confidence
// below 1 rather than being reported as fact.
//
// # Why there is no ICMP here
//
// There was, briefly, and it never ran. `net.ListenPacket("udp4", ...)` does not
// create an unprivileged ICMP socket — it creates a UDP one, and with the
// address form the code used it did not even do that. The path returned
// "unavailable" on every call and fell through to TCP, which is a discovery
// method that silently does nothing: exactly the under-reporting that looks like
// a clean run.
//
// Go's standard library has no unprivileged ICMP. Getting one needs
// golang.org/x/net/icmp or syscall, and both are wider exceptions to the engine
// import allowlist than the single `net` ADR-047 argues for — syscall especially,
// since it is the raw-socket path the whole deferral exists to keep out. So ICMP
// joins SYN and ARP in the deferral, on a line that is coherent rather than
// arbitrary: **`net` gives TCP connect, and every other discovery method needs a
// socket the standard library will not create.**

// probeAlive returns whether anything answered and what answered.
//
// The rate limiter governs it: a connect made to decide liveness is a packet and
// spends a token exactly as a port scan connect does.
func probeAlive(ctx context.Context, cfg Config, address string, limiter *bucket, count func(uint32)) (bool, string) {
	for _, port := range HostDiscoveryPorts() {
		if err := ctx.Err(); err != nil {
			return false, "cancelled"
		}
		// The SYN train up front, like the port scan: ADR-024's ceiling is in
		// packets and a connect against a filtered host is a SYN plus its
		// retransmissions. Host discovery dials the same way the port scan does
		// and must be charged the same way, or the cheapest path to exceeding
		// the ceiling is to have many silent hosts.
		attemptCost := synCost(cfg.ConnectTimeout)
		if err := limiter.takeN(ctx, attemptCost); err != nil {
			return false, "cancelled"
		}

		d := net.Dialer{Timeout: cfg.ConnectTimeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(int(port))))
		if err == nil {
			// Established: one SYN, the ACK and the FIN. The retransmissions
			// charged up front did not happen.
			count(1 + establishedCost)
			_ = conn.Close()
			return true, "tcp-connect:" + strconv.Itoa(int(port))
		}

		// ================================================================
		// Only a REFUSAL proves a host. Everything else is silence or a
		// local failure, and neither is evidence of anything.
		// ================================================================
		//
		// The first version was `not a timeout, therefore alive`, which folded
		// ECONNREFUSED together with ENETUNREACH, EHOSTUNREACH, a DNS failure
		// and a malformed address. A packet-capture audit measured three hosts
		// reported alive at confidence 1.0 with ZERO outbound packets — the
		// kernel had refused to route and the engine called it a live host.
		//
		// Core derives assets from observations, so a sweep of a range that is
		// mostly unroutable would fabricate an asset per address at full
		// confidence. A false finding is the thing this product cannot afford.
		if !isRefused(err) {
			// A timeout DID send the SYN train; a routing failure sent nothing.
			// Charged accordingly, so the budget reflects the wire rather than
			// the loop.
			if isTimeout(err) {
				count(attemptCost)
			}
			continue
		}
		// Refused: one SYN out, a RST back.
		count(1)
		return true, "tcp-refused:" + strconv.Itoa(int(port))
	}
	return false, "no-response"
}

// isRefused reports whether the error is an active refusal — a RST from
// something that exists.
//
// A refusal proves a host as well as an accepted connection does: something sent
// the reset. A timeout proves nothing, and a routing or resolution failure
// proves only that this machine could not ask.
//
// # Why this compares a string
//
// The clean expression is errors.Is(err, syscall.ECONNREFUSED), and `syscall` is
// not on this engine's import allowlist — it is the raw-socket path ADR-047's
// deferral exists to keep out, and widening the exception to name one constant
// would be the cheapest possible reason to take it.
//
// Go's syscall.Errno.Error() renders from a fixed internal table and is not
// localised, so the text is stable on a given platform. That is a weaker
// guarantee than a constant and it is why TestRefusalIsDistinguishedFromEveryOther
// drives a REAL refusal and a REAL unreachable address rather than constructing
// errors: if this ever stops classifying correctly, a test fails rather than a
// scan quietly inventing hosts.
//
// It errs toward NOT alive. A refusal misread as something else loses a host
// from the results, which is visible in the coverage record; the opposite
// fabricates an asset at full confidence, which is a false finding.
func isRefused(err error) bool {
	// The unwrap chain is walked by hand, and NOT via os.SyscallError.
	//
	// The obvious expression is errors.As(err, &*os.SyscallError) — and `os` is
	// not on this engine's allowlist either, because os.StartProcess spawns a
	// subprocess without naming os/exec. The guard caught that; the first
	// version of this function imported it.
	//
	// An EXACT match on each level's message, never a substring of the whole
	// error: the full text is "dial tcp 1.2.3.4:80: connect: connection
	// refused", and a substring test against that would also match a hostname
	// that happened to contain the phrase. Only the innermost errno renders as
	// exactly "connection refused".
	for e := err; e != nil; {
		if e.Error() == "connection refused" {
			return true
		}
		u, ok := e.(interface{ Unwrap() error }) //nolint:errorlint // walking deliberately
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// isTimeout separates "we waited and nothing came" from "the kernel would not
// route".
//
// The distinction is a rate question as well as an evidence one: a timeout means
// the SYN train went out and must be charged, and a routing failure means
// nothing left the machine and must not be.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
