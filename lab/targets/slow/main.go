// A lab target with one connection's worth of capacity in TOTAL.
//
// ADR-024 caps a fragile asset at 10 pps, and nothing had ever exercised that
// guard: every other lab target answers as fast as it is asked.
//
// Two earlier attempts here failed, and both failures are instructive enough to
// keep:
//
//  1. nginx with limit_req. Its rate limiting is above the handshake, so a
//     connect scanner completes the TCP connection, sees the port open, and
//     never notices the 429. It degraded under HTTP load, not under the load a
//     scanner applies.
//  2. socat without fork, one listener per port. Serialisation per PORT does not
//     bite, because a port scanner makes one connection per port — contention
//     only appears when several connections hit the same one.
//
// What an actual fragile device does is run out of capacity across its WHOLE
// stack: a printer with one embedded connection slot does not care which port
// you knocked on. So this listens on several ports and shares a single slot
// between all of them, holding each accepted connection briefly. Connect faster
// than that and connections are refused or time out — which is visibly different
// depending on whether a scanner honours the fragile cap.
package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// holdFor is how long one connection occupies the device's only slot.
//
// 50ms, chosen by MEASURING rather than by picking a round number. It has to sit
// below the interval a capped scan uses and above what a burst leaves: at
// ADR-024's 10 pps with concurrency 1 the connects are 100ms apart, so every one
// finds the slot free; at 500 pps with concurrency 20 they arrive together and
// all but one are dropped.
//
// The first value tried was 400ms, and measuring showed it lost banners at BOTH
// rates — a target that degrades under every load distinguishes nothing.
const holdFor = 50 * time.Millisecond

// inUse is the whole capacity of this "device": one connection, shared across
// every port it listens on.
var inUse atomic.Bool

func main() {
	ports := strings.Split(os.Getenv("PORTS"), ",")
	if len(ports) == 0 || ports[0] == "" {
		ports = []string{"80", "443", "8080", "22", "23", "631"}
	}
	for _, p := range ports {
		go serve(strings.TrimSpace(p))
	}
	select {}
}

func serve(port string) {
	// A backlog of 1 is not settable from Go's net package, so the shared slot
	// below is what produces the refusals; the listener itself is ordinary.
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen %s: %v\n", port, err)
		return
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			if !inUse.CompareAndSwap(false, true) {
				// The device is busy. It does not queue — it drops, which is
				// what running out of connection slots looks like from outside.
				return
			}
			defer inUse.Store(false)
			time.Sleep(holdFor)
			_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nServer: fragile-lab-target\r\n\r\nfragile\n"))
		}()
	}
}
