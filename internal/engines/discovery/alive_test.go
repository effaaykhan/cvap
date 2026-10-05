package discovery

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/enginerate"
)

// TestProbeAliveClassifiesEachOutcome drives probeAlive itself, one row per way
// a liveness connect can end, and checks the verdict, the method it names, and
// the packets it reports.
//
// Real sockets, as everywhere in this package. Each failure address was MEASURED
// on Linux before it was written down, not assumed:
//
//	192.0.2.1          i/o timeout                 (TEST-NET-1, never routed)
//	255.255.255.255    connect: network is unreachable
//	fe80::1%<no such>  connect: invalid argument   (fails locally; no DNS)
//
// Only an accepted connection or a refusal is a host. A timeout, a routing
// failure and any other transport error are silence or a local failure, and
// reporting one alive is the false-liveness defect the packet-capture audit
// found: hosts at confidence 1.0 with zero packets on the wire.
func TestProbeAliveClassifiesEachOutcome(t *testing.T) {
	// One second, so the modelled SYN train is two packets rather than one: at
	// any timeout under a second SynCost is 1, and charging a single SYN would
	// pass for charging the train — an undercount, the direction a ceiling must
	// never lean.
	const timeout = time.Second
	synTrain := enginerate.SynCost(timeout)
	if synTrain < 2 {
		t.Fatalf("SynCost(%v) = %d; the timeout rows need a train longer than one SYN "+
			"to tell charging it from charging one", timeout, synTrain)
	}
	open := listener(t, func(c net.Conn) {})
	closed := freePort(t)

	cases := []struct {
		name      string
		address   string
		ports     []uint16
		alive     bool
		method    string
		wantCount uint32
	}{
		{"accepted connection", "127.0.0.1", []uint16{open}, true,
			"tcp-connect:" + strconv.Itoa(int(open)), 1 + enginerate.EstablishedCost},
		{"refusal", "127.0.0.1", []uint16{closed}, true,
			"tcp-refused:" + strconv.Itoa(int(closed)), 1},
		{"timeout", "192.0.2.1", []uint16{80}, false, "no-response", synTrain},
		{"timeout on every port, each charged", "192.0.2.1", []uint16{80, 81}, false,
			"no-response", 2 * synTrain},
		{"network unreachable", "255.255.255.255", []uint16{80}, false, "no-response", 0},
		{"generic transport error", "fe80::1%cvapnosuchif", []uint16{80}, false, "no-response", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withHostDiscoveryPorts(t, tc.ports...)
			cfg := baseConfig()
			cfg.ConnectTimeout = timeout

			var counted uint32
			alive, method := probeAlive(t.Context(), cfg, tc.address,
				enginerate.New(1000, time.Now), func(n uint32) { counted += n })

			if alive != tc.alive {
				t.Errorf("alive = %v (method %q), want %v", alive, method, tc.alive)
			}
			if method != tc.method {
				t.Errorf("method = %q, want %q", method, tc.method)
			}
			if counted != tc.wantCount {
				t.Errorf("reported %d packet(s) sent, want %d", counted, tc.wantCount)
			}
		})
	}
}

// TestProbeAliveStopsAtTheFirstAnswer: a refusal on the first port proves the
// host, and the probe dials nothing further — the next port's listener is never
// reached and its packets are never charged.
func TestProbeAliveStopsAtTheFirstAnswer(t *testing.T) {
	closed := freePort(t)
	open := listener(t, func(c net.Conn) {})
	withHostDiscoveryPorts(t, closed, open)

	var counted uint32
	alive, method := probeAlive(t.Context(), baseConfig(), "127.0.0.1",
		enginerate.New(1000, time.Now), func(n uint32) { counted += n })
	if !alive || method != "tcp-refused:"+strconv.Itoa(int(closed)) {
		t.Errorf("alive=%v method=%q; the first positive answer decides", alive, method)
	}
	if counted != 1 {
		t.Errorf("reported %d packet(s), want 1: the probe must stop at the first answer", counted)
	}
}

// TestProbeAliveStopsOnCancellation: a cancelled job reports nothing alive and
// dials nothing.
func TestProbeAliveStopsOnCancellation(t *testing.T) {
	open := listener(t, func(c net.Conn) {})
	withHostDiscoveryPorts(t, open)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var counted uint32
	alive, method := probeAlive(ctx, baseConfig(), "127.0.0.1",
		enginerate.New(1000, time.Now), func(n uint32) { counted += n })
	if alive || method != "cancelled" || counted != 0 {
		t.Errorf("alive=%v method=%q counted=%d after cancellation", alive, method, counted)
	}
}

func withHostDiscoveryPorts(t *testing.T, ports ...uint16) {
	t.Helper()
	prev := hostDiscoveryPorts
	hostDiscoveryPorts = func() []uint16 { return ports }
	t.Cleanup(func() { hostDiscoveryPorts = prev })
}
