package fingerprint

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/enginerate"
)

// What this engine puts on the wire, admitted before it is put there (M0 R2a).
//
// ============================================================================
// Settle cannot make a packet that already left safe.
// ============================================================================
//
// The engine used to take SynCost tokens before a connect and reconcile the
// rest afterwards. A per-connection capture measured the gap: an open port with
// nothing to say cost 4 packets against 3 admitted (1 at a 500ms timeout), a
// banner port 5, an HTTP probe 6 against 5. Settle charged the difference to the
// NEXT attempt, which keeps the sustained rate honest and does nothing for the
// packets already sent.
//
// So: every connection admits its whole engine-originated cost first, and every
// byte this engine writes goes through meteredConn, which refuses a write the
// admission did not cover rather than sending it and charging afterwards.
//
// What is NOT here is the traffic a peer can extract from this end — the ACKs
// of its data, and segments made smaller than SegmentPayload by a tiny MSS or
// window. A receive-window experiment showed a hostile peer sending one-byte
// segments drew over a thousand ACKs whatever the buffer, so no pre-connect
// setting bounds it. That class is R2-B and is bounded separately.

// tlsClientSegments is the most segments a TLS client handshake may write:
// a ClientHello (about 1.5 KB with the post-quantum key share, three segments),
// a second one after a HelloRetryRequest (three more), the client's closing
// flight (two), and an alert (one). TestTLSHandshakeWritesStayInsideTheirAdmission
// drives TLS 1.3, TLS 1.2 and a retry against real servers and measures it.
const tlsClientSegments = 9

// tlsRecordOverhead bounds what TLS adds around one application-data record:
// header, explicit IV, MAC and padding of the widest CBC suite this client can
// negotiate is under 70 bytes. Doubled, because a TLS 1.0 CBC write is split
// one byte and the rest (1/n-1) — two records, two writes.
const tlsRecordOverhead = 2 * 64

// sshClientSegments is the three messages sshHostKey writes: the version line,
// KEXINIT and KEX_ECDH_INIT, each a single write well under SegmentPayload.
const sshClientSegments = 3

// ClampConnectTimeout is the connect timeout Run actually uses: the default
// when none was given, never above the compiled-in ceiling. Exported so the
// safety gate computes admissions at the same timeout the engine dials with.
func ClampConnectTimeout(d time.Duration) time.Duration {
	if d <= 0 {
		return 3 * time.Second
	}
	return min(d, platformMaxConnectTimeout)
}

// PortAdmission is what a port's first connection — connect, listen for a
// banner, close — is admitted before it is dialled. It writes nothing.
func PortAdmission(timeout time.Duration) uint32 {
	return enginerate.ConnectionBound(timeout)
}

// ProbeAdmission is what one probe is admitted before its connection is
// dialled: never less than the packet model probeCost paces by, and never less
// than the connection plus every segment the probe may write, with the payload
// at its worst-case substituted size.
func ProbeAdmission(p Probe, timeout time.Duration) uint32 {
	// Saturating, so the subtraction in probeWriteAllowance can never underflow
	// into an enormous allowance: a saturated sum is still >= ConnectionBound.
	bound := enginerate.SaturatingAdd(enginerate.ConnectionBound(timeout), probeWriteSegments(p))
	if model := probeCost(p, timeout); model > bound {
		return model
	}
	return bound
}

// probeWriteSegments is every segment a probe may write.
func probeWriteSegments(p Probe) uint32 {
	var n uint32
	if p.Kind == probeKindSSHHostKey {
		n += sshClientSegments
	}
	size := 0
	if len(p.Payload) > 0 {
		size = substitutedSize(p.Payload)
	}
	if p.TLS {
		n += tlsClientSegments
		if size > 0 {
			size += tlsRecordOverhead
			// The 1/n-1 split makes the payload two writes, each its own segment.
			n++
		}
	}
	return enginerate.SaturatingAdd(n, enginerate.Segments(size))
}

// probeWriteAllowance is what a probe's meteredConn may write: everything its
// admission covers beyond the bare connection.
func probeWriteAllowance(p Probe, timeout time.Duration) uint32 {
	return ProbeAdmission(p, timeout) - enginerate.ConnectionBound(timeout)
}

// errWireBudget is a write meteredConn refused. Nothing was sent.
var errWireBudget = errors.New("fingerprint: write refused: it exceeds the wire budget admitted for this operation")

// meteredConn charges every write against the segments its operation was
// admitted, and refuses one that would exceed them before it reaches the socket.
//
// A refused write fails the probe, which is the right failure: a TLS handshake
// that would have needed more than was paid for loses its certificate, and the
// ceiling holds. TLS and SSH write through this, so their client flights are
// metered by the same rule as a payload.
type meteredConn struct {
	net.Conn

	mu      sync.Mutex
	allowed uint32
	used    uint32
}

func meter(c net.Conn, allowed uint32) *meteredConn {
	return &meteredConn{Conn: c, allowed: allowed}
}

func (m *meteredConn) Write(b []byte) (int, error) {
	need := enginerate.Segments(len(b))
	m.mu.Lock()
	// Compared as headroom rather than as used+need, which would wrap for a
	// write of a few terabytes and admit it. used never exceeds allowed.
	if need > m.allowed-m.used {
		m.mu.Unlock()
		return 0, errWireBudget
	}
	// Charged before the write and never given back: a write that fails part
	// way may still have sent some of it.
	m.used += need
	m.mu.Unlock()
	return m.Conn.Write(b)
}

// segments is what has been charged so far.
func (m *meteredConn) segments() uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.used
}
