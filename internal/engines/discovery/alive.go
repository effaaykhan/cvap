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
		if err := limiter.take(ctx); err != nil {
			return false, "cancelled"
		}
		count(1)

		d := net.Dialer{Timeout: cfg.ConnectTimeout}
		conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(address, strconv.Itoa(int(port))))
		if err == nil {
			_ = conn.Close()
			return true, "tcp-connect:" + strconv.Itoa(int(port))
		}
		// A REFUSED connection proves a host is there just as well as an
		// accepted one — something sent the RST. Only a timeout is silence.
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return true, "tcp-refused:" + strconv.Itoa(int(port))
		}
	}
	return false, "no-response"
}
