package fingerprint

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/enginerate"
)

// R2a: what this engine writes is admitted before it is written. Real sockets,
// as everywhere in this package; the packet-level half is the safety gate's.

// sink accepts connections and records every byte the client sends.
type sink struct {
	port uint16
	mu   sync.Mutex
	got  []byte
}

func newSink(t *testing.T) *sink {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &sink{port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				b, _ := io.ReadAll(c)
				s.mu.Lock()
				s.got = append(s.got, b...)
				s.mu.Unlock()
			}()
		}
	}()
	return s
}

func (s *sink) received(t *testing.T) []byte {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.got...)
}

func dialSink(t *testing.T, port uint16) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestAWriteBeyondTheAdmissionIsRefusedAndNothingLeaves: the meter refuses
// before the socket sees the bytes, so the peer receives exactly what was
// admitted and not one byte of the refused write.
func TestAWriteBeyondTheAdmissionIsRefusedAndNothingLeaves(t *testing.T) {
	s := newSink(t)
	raw := dialSink(t, s.port)
	m := meter(raw, 1)

	first := bytes.Repeat([]byte("a"), enginerate.SegmentPayload)
	if _, err := m.Write(first); err != nil {
		t.Fatalf("an admitted write was refused: %v", err)
	}
	if _, err := m.Write([]byte("b")); !errors.Is(err, errWireBudget) {
		t.Fatalf("a write past the admission returned %v, want errWireBudget", err)
	}
	_ = raw.Close()

	if got := s.received(t); !bytes.Equal(got, first) {
		t.Errorf("peer received %d byte(s), want exactly the %d admitted", len(got), len(first))
	}
	if m.segments() != 1 {
		t.Errorf("charged %d segment(s), want 1", m.segments())
	}
}

// TestAWriteThatSpansSegmentsIsChargedForEach: one write is as many segments
// as its bytes need, not one.
func TestAWriteThatSpansSegmentsIsChargedForEach(t *testing.T) {
	s := newSink(t)
	raw := dialSink(t, s.port)
	defer func() { _ = raw.Close() }()
	m := meter(raw, 2)
	if _, err := m.Write(make([]byte, 2*enginerate.SegmentPayload+1)); !errors.Is(err, errWireBudget) {
		t.Fatalf("a three-segment write under a two-segment admission returned %v", err)
	}
	if m.segments() != 0 {
		t.Errorf("a refused write was charged %d segment(s)", m.segments())
	}
}

// noWrite is a connection that fails the test if anything reaches it.
type noWrite struct {
	net.Conn
	t *testing.T
}

func (n noWrite) Write(b []byte) (int, error) {
	n.t.Errorf("%d byte(s) reached the socket past a refusal", len(b))
	return len(b), nil
}

// TestTheMeterCannotWrapIntoAdmittingAWrite: at the top of uint32, used+need
// would wrap to a small number and pass a write the allowance cannot cover.
func TestTheMeterCannotWrapIntoAdmittingAWrite(t *testing.T) {
	m := &meteredConn{Conn: noWrite{t: t}, allowed: math.MaxUint32, used: math.MaxUint32 - 1}
	// Two segments against one of headroom.
	if _, err := m.Write(make([]byte, enginerate.SegmentPayload+1)); !errors.Is(err, errWireBudget) {
		t.Fatalf("a write past the headroom returned %v, want errWireBudget", err)
	}
	if m.segments() != math.MaxUint32-1 {
		t.Errorf("a refused write moved the charge to %d", m.segments())
	}
}

// TestAnAbsurdTimeoutSaturatesTheAdmissionRatherThanFreeingTheMeter: a
// connection bound held at the maximum must not wrap the probe's sum into a
// small admission whose write allowance then underflows to nearly unlimited.
func TestAnAbsurdTimeoutSaturatesTheAdmissionRatherThanFreeingTheMeter(t *testing.T) {
	p := Probe{Name: "tls-payload", TLS: true, Payload: []byte("HEAD / HTTP/1.0\r\n\r\n")}
	if got := ProbeAdmission(p, math.MaxInt64); got != math.MaxUint32 {
		t.Errorf("ProbeAdmission at the duration maximum = %d, want the saturated %d", got, uint32(math.MaxUint32))
	}
	if got, most := probeWriteAllowance(p, math.MaxInt64), probeWriteSegments(p); got > most {
		t.Errorf("write allowance %d exceeds the %d segments the probe can need: the subtraction wrapped",
			got, most)
	}
}

// TestConcurrentWritersCannotOvershootTheAdmission: the meter is the shared
// accounting for one connection, and racing writers get exactly what was
// admitted between them.
func TestConcurrentWritersCannotOvershootTheAdmission(t *testing.T) {
	s := newSink(t)
	raw := dialSink(t, s.port)
	const admitted, writers = 10, 50
	m := meter(raw, admitted)

	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Write([]byte("x")); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	_ = raw.Close()

	if ok != admitted {
		t.Errorf("%d writes succeeded, want exactly %d", ok, admitted)
	}
	if got := s.received(t); len(got) != admitted {
		t.Errorf("peer received %d byte(s), want %d", len(got), admitted)
	}
}

// TestProbeAdmissionNeverPacesLooserThanTheModel: admission replaced probeCost
// as what is taken before the dial, and must never be the smaller of the two.
func TestProbeAdmissionNeverPacesLooserThanTheModel(t *testing.T) {
	probes := []Probe{
		{Name: "bare"},
		{Name: "payload", Payload: []byte("GET / HTTP/1.0\r\n\r\n")},
		{Name: "tls", TLS: true},
		{Name: "tls-payload", TLS: true, Payload: bytes.Repeat([]byte("x"), maxProbePayload)},
		{Name: "ssh", Kind: probeKindSSHHostKey},
	}
	for _, timeout := range []time.Duration{200 * time.Millisecond, time.Second, 3 * time.Second} {
		for _, p := range probes {
			adm, model := ProbeAdmission(p, timeout), probeCost(p, timeout)
			if adm < model {
				t.Errorf("%s @%v: admission %d < model %d", p.Name, timeout, adm, model)
			}
			if floor := enginerate.ConnectionBound(timeout); adm < floor {
				t.Errorf("%s @%v: admission %d < the bare connection's %d", p.Name, timeout, adm, floor)
			}
		}
	}
}

// TestTheWorstCaseTemplateIsAdmittedAtItsLongestExpansion: the payload is
// admitted at the size it reaches against the longest address, so no target
// can make the write bigger than what was paid for. Driven through runProbe, so
// the write really passes the meter.
func TestTheWorstCaseTemplateIsAdmittedAtItsLongestExpansion(t *testing.T) {
	// As many placeholders as maxProbePayload allows at the longest expansion.
	n := (maxProbePayload - 2) / maxTargetLength
	payload := append(bytes.Repeat([]byte(targetPlaceholder), n), '\r', '\n')
	if substitutedSize(payload) > maxProbePayload {
		t.Fatalf("test payload expands to %d, over the %d the engine accepts",
			substitutedSize(payload), maxProbePayload)
	}
	p := Probe{Name: "template", Payload: payload}

	longest := "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255" // 45 characters
	if need := enginerate.Segments(len(substituteTarget(payload, longest))); need > probeWriteAllowance(p, time.Second) {
		t.Errorf("worst-case expansion needs %d segment(s), the probe is allowed %d",
			need, probeWriteAllowance(p, time.Second))
	}

	s := newSink(t)
	cfg := baseConfig(s.port)
	cfg.ConnectTimeout = time.Second
	out := runProbe(t.Context(), cfg, "127.0.0.1", s.port, p)
	if want := substituteTarget(payload, "127.0.0.1"); !bytes.Equal(s.received(t), want) {
		t.Errorf("the substituted payload did not arrive intact")
	}
	if adm := ProbeAdmission(p, cfg.ConnectTimeout); out.cost > adm {
		t.Errorf("the probe reported %d packets against %d admitted", out.cost, adm)
	}
}

// tlsServerWith serves TLS with a given configuration and answers one read.
func tlsServerWith(t *testing.T, cfg *tls.Config) uint16 {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				if n, _ := c.Read(buf); n > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"))
				}
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// TestTLSHandshakeWritesStayInsideTheirAdmission measures what the client side
// of a real handshake writes, under every shape this engine can meet: TLS 1.3,
// a HelloRetryRequest (a second ClientHello), TLS 1.2, a server asking for a
// client certificate, and TLS 1.0, whose CBC records are split 1/n-1. Each must
// complete, and carry the probe payload, without the meter refusing a write.
func TestTLSHandshakeWritesStayInsideTheirAdmission(t *testing.T) {
	cert := selfSigned(t, nil, 2048)
	cases := map[string]*tls.Config{
		"tls1.3": {Certificates: []tls.Certificate{cert}},
		"tls1.3-hello-retry": {Certificates: []tls.Certificate{cert},
			CurvePreferences: []tls.CurveID{tls.CurveP384}},
		"tls1.2": {Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12},
		"tls1.2-client-cert-requested": {Certificates: []tls.Certificate{cert},
			MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert},
		"tls1.0-cbc": {Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}},
	}
	p := Probe{Name: "https-head", TLS: true,
		Payload: []byte("HEAD / HTTP/1.0\r\nHost: {{target}}\r\nUser-Agent: cvap\r\n\r\n")}
	for name, scfg := range cases {
		t.Run(name, func(t *testing.T) {
			port := tlsServerWith(t, scfg)
			cfg := baseConfig(port)
			cfg.ConnectTimeout = 2 * time.Second
			out := runProbe(t.Context(), cfg, "127.0.0.1", port, p)
			if out.tls == nil {
				t.Fatalf("the handshake did not complete; a refused write would end it here")
			}
			if len(out.response) == 0 {
				t.Errorf("the payload went unanswered; its write may have been refused")
			}
			if adm := ProbeAdmission(p, cfg.ConnectTimeout); out.cost > adm {
				t.Errorf("reported %d packets against %d admitted", out.cost, adm)
			}
		})
	}
}

// TestTheTLSClientFlightIsMeasuredNotAssumed: what each handshake shape really
// writes, held to the constant admitted for it.
//
// MEASURED under a meter with no effective limit. Metered at tlsClientSegments
// itself, the count could never exceed the constant whatever the handshake
// needed — the assertion would be true by construction and a constant set too
// low would surface only as handshakes failing in the field.
func TestTheTLSClientFlightIsMeasuredNotAssumed(t *testing.T) {
	cert := selfSigned(t, nil, 2048)
	shapes := map[string]*tls.Config{
		"tls1.3":             {Certificates: []tls.Certificate{cert}},
		"tls1.3-hello-retry": {Certificates: []tls.Certificate{cert}, CurvePreferences: []tls.CurveID{tls.CurveP384}},
		"tls1.2":             {Certificates: []tls.Certificate{cert}, MaxVersion: tls.VersionTLS12},
		"tls1.2-client-cert-requested": {Certificates: []tls.Certificate{cert},
			MaxVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert},
		"tls1.0-cbc": {Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10,
			MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA}},
	}
	for name, scfg := range shapes {
		t.Run(name, func(t *testing.T) {
			port := tlsServerWith(t, scfg)
			raw := dialSink(t, port)
			defer func() { _ = raw.Close() }()
			m := meter(raw, 1<<20)
			if _, _, err := dialTLS(t.Context(), m, "127.0.0.1", 2*time.Second); err != nil {
				t.Fatalf("handshake: %v", err)
			}
			used := m.segments()
			t.Logf("%s wrote %d segment(s); %d admitted", name, used, tlsClientSegments)
			if used == 0 {
				t.Fatal("the handshake wrote nothing through the meter; it is not being metered")
			}
			if used > tlsClientSegments {
				t.Errorf("%s wrote %d segment(s), more than the %d admitted for a TLS client "+
					"handshake; under the real meter it would be refused", name, used, tlsClientSegments)
			}
		})
	}
}

// TestTheSSHExchangeWritesItsThreeMessages: version line, KEXINIT and
// KEX_ECDH_INIT, each one segment, through the meter.
func TestTheSSHExchangeWritesItsThreeMessages(t *testing.T) {
	srv := newSSHServer(t, &sshServer{})
	raw := dialSink(t, srv.port)
	defer func() { _ = raw.Close() }()
	m := meter(raw, sshClientSegments)
	if _, err := sshHostKey(t.Context(), m, 2*time.Second); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if m.segments() != sshClientSegments {
		t.Errorf("the exchange charged %d segment(s), want %d", m.segments(), sshClientSegments)
	}
}

// TestACancelledDialIsChargedForTheSYNsItSent: a connect cancelled while its
// SYN train is in flight is charged for what the train had sent by then. It was
// charged as a refusal — one SYN — and Settle refunded the rest.
func TestACancelledDialIsChargedForTheSYNsItSent(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(1500*time.Millisecond, cancel)
	// TEST-NET-1: never routed, so the SYN train runs until the cancel.
	_, cost, timedOut, err := dial(ctx, "192.0.2.1", 80, 3*time.Second)
	if err == nil || timedOut {
		t.Fatalf("err=%v timedOut=%v, want a cancellation", err, timedOut)
	}
	// SYNs at 0 and ~1s had left by 1.5s.
	if cost < 2 {
		t.Errorf("a dial cancelled 1.5s into its train was charged %d packet(s); "+
			"two SYNs had left and must not be refunded", cost)
	}
	if cost > PortAdmission(3*time.Second) {
		t.Errorf("charged %d, above the %d the connection was admitted", cost, PortAdmission(3*time.Second))
	}
}

// TestAQuickRefusalIsOneSYN: the elapsed-time bound does not over-charge the
// common case.
func TestAQuickRefusalIsOneSYN(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	_, cost, _, err := dial(t.Context(), "127.0.0.1", closed, time.Second)
	if err == nil {
		t.Fatal("expected a refusal")
	}
	if cost != 1 {
		t.Errorf("a refusal was charged %d packet(s), want 1", cost)
	}
}
