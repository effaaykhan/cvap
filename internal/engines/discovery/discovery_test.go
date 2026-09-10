package discovery

import (
	"context"
	"encoding/json"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// These drive REAL sockets against listeners this test owns.
//
// Not a mocked dialer, and the reason is on the record: an ICMP path in this
// package was written, reviewed and merged into the working tree before anyone
// ran it, and it turned out `net.ListenPacket("udp4", ...)` does not create the
// socket it claimed to. It returned "unavailable" on every call and silently
// degraded discovery. A test against a fake dialer would have passed.

// listener starts a TCP server on loopback and returns its port.
func listener(t *testing.T, handle func(net.Conn)) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
				handle(c)
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// collect runs the engine and returns the observations by type.
func collect(t *testing.T, cfg Config, targets []Target) map[string][]map[string]any {
	t.Helper()
	out := map[string][]map[string]any{}
	var mu sync.Mutex
	emit := func(o Observation) error {
		var payload map[string]any
		if err := json.Unmarshal(o.Payload, &payload); err != nil {
			t.Errorf("observation payload is not JSON: %v", err)
			return nil
		}
		payload["__task_id"] = o.TaskID
		mu.Lock()
		out[o.Type] = append(out[o.Type], payload)
		mu.Unlock()
		return nil
	}
	if err := Run(t.Context(), cfg, targets, emit, func(uint32) {}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	return out
}

func baseConfig(ports ...uint16) Config {
	return Config{
		RatePPS: 500, ConnectTimeout: 500 * time.Millisecond,
		MaxConcurrentPerTarget: 4, Ports: ports, SafetyMode: "safe",
	}
}

// TestAnOpenPortIsReportedAndAClosedOneIsNot.
//
// Closed ports produce no observation: the default set is ~180 per host, which
// for a /24 is 45,000 rows almost all saying nothing happened, against an ingest
// budget of 5,000 a second. Coverage is recorded once, on the host.
func TestAnOpenPortIsReportedAndAClosedOneIsNot(t *testing.T) {
	open := listener(t, func(c net.Conn) { <-t.Context().Done() })
	closed := freePort(t)

	got := collect(t, baseConfig(open, closed), []Target{
		{TaskID: "task-1", Value: "127.0.0.1"},
	})

	if len(got["port"]) != 1 {
		t.Fatalf("got %d port observations, want 1 (the open one)", len(got["port"]))
	}
	if got["port"][0]["state"] != "open" {
		t.Errorf("state = %v, want open", got["port"][0]["state"])
	}
	if int(got["port"][0]["port"].(float64)) != int(open) {
		t.Errorf("reported port %v, want %d", got["port"][0]["port"], open)
	}
}

// TestCoverageIsRecordedOnTheHost.
//
// Without this, "port 23 is not in the results" means both "we looked and it was
// closed" and "we never looked" — and telling those apart is the difference
// between a scan and a scan that looks complete.
func TestCoverageIsRecordedOnTheHost(t *testing.T) {
	open := listener(t, func(c net.Conn) { <-t.Context().Done() })
	closed := freePort(t)

	got := collect(t, baseConfig(open, closed), []Target{
		{TaskID: "task-1", Value: "127.0.0.1"},
	})

	if len(got["host"]) != 1 {
		t.Fatalf("got %d host observations, want 1", len(got["host"]))
	}
	h := got["host"][0]
	if h["alive"] != true {
		t.Errorf("alive = %v, want true", h["alive"])
	}
	scanned, _ := h["ports_scanned"].([]any)
	if len(scanned) != 2 {
		t.Errorf("ports_scanned has %d entries, want 2 — the closed one must still be "+
			"recorded as covered", len(scanned))
	}
	if int(h["ports_open"].(float64)) != 1 {
		t.Errorf("ports_open = %v, want 1", h["ports_open"])
	}
}

// TestEveryObservationCarriesItsTask.
//
// An observation with no task_id cannot be attributed to the work that produced
// it. The first version of this engine emitted port and banner observations with
// an empty one, which running it made obvious and reading it had not.
func TestEveryObservationCarriesItsTask(t *testing.T) {
	port := listener(t, func(c net.Conn) { _, _ = c.Write([]byte("SSH-2.0-Test\r\n")) })

	got := collect(t, baseConfig(port), []Target{{TaskID: "task-abc", Value: "127.0.0.1"}})

	var seen int
	for typ, obs := range got {
		for _, o := range obs {
			seen++
			if o["__task_id"] != "task-abc" {
				t.Errorf("%s observation carries task_id %q, want task-abc", typ, o["__task_id"])
			}
		}
	}
	if seen == 0 {
		t.Fatal("no observations at all")
	}
}

// TestSafeModeReadsWhatIsVolunteeredAndSendsNothing.
//
// The listener records every byte it receives. Under a safe job that must be
// zero — reading is not sending — and the banner must still be captured.
func TestSafeModeReadsWhatIsVolunteeredAndSendsNothing(t *testing.T) {
	var mu sync.Mutex
	var received []byte

	port := listener(t, func(c net.Conn) {
		_, _ = c.Write([]byte("220 test FTP ready\r\n"))
		buf := make([]byte, 512)
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if n, _ := c.Read(buf); n > 0 {
			mu.Lock()
			received = append(received, buf[:n]...)
			mu.Unlock()
		}
	})

	cfg := baseConfig(port)
	cfg.Probes = nil // a safe job is handed none
	got := collect(t, cfg, []Target{{TaskID: "t", Value: "127.0.0.1"}})

	if len(got["banner"]) != 1 {
		t.Fatalf("got %d banners, want 1 — a volunteered banner is read in safe mode",
			len(got["banner"]))
	}
	if got["banner"][0]["solicited"] != false {
		t.Error("a volunteered banner was marked solicited")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(received) != 0 {
		t.Errorf("the engine sent %d bytes under a safe job: %q. Safe mode reads what a "+
			"service volunteers and sends nothing.", len(received), received)
	}
}

// TestAProbeIsSentOnlyWhenSuppliedAndIsRecordedAsSolicited.
func TestAProbeIsSentOnlyWhenSuppliedAndIsRecordedAsSolicited(t *testing.T) {
	var mu sync.Mutex
	var received []byte

	port := listener(t, func(c net.Conn) {
		buf := make([]byte, 512)
		_ = c.SetReadDeadline(time.Now().Add(time.Second))
		if n, _ := c.Read(buf); n > 0 {
			mu.Lock()
			received = append(received, buf[:n]...)
			mu.Unlock()
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"))
		}
	})

	cfg := baseConfig(port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{
		Name: "http-head", Payload: []byte("HEAD / HTTP/1.1\r\nHost: {{target}}\r\n\r\n"),
		ReadBytes: 1024,
	}}
	got := collect(t, cfg, []Target{{TaskID: "t", Value: "127.0.0.1"}})

	mu.Lock()
	sent := string(received)
	mu.Unlock()
	if !strings.Contains(sent, "HEAD /") {
		t.Fatalf("the probe was not sent; server received %q", sent)
	}
	// The placeholder is substituted with the AUTHORISED target and nothing
	// else: an engine composing its own address would be constructing targets.
	if !strings.Contains(sent, "Host: 127.0.0.1") {
		t.Errorf("the target placeholder was not substituted: %q", sent)
	}
	if strings.Contains(sent, "{{target}}") {
		t.Errorf("the placeholder travelled literally: %q", sent)
	}

	if len(got["banner"]) != 1 {
		t.Fatalf("got %d banners, want 1", len(got["banner"]))
	}
	b := got["banner"][0]
	if b["solicited"] != true || b["probe"] != "http-head" {
		t.Errorf("banner provenance is solicited=%v probe=%v; the pipeline needs both to "+
			"weigh the confidence", b["solicited"], b["probe"])
	}
	if b["safety_mode"] != "intrusive" {
		t.Errorf("safety_mode = %v, want intrusive", b["safety_mode"])
	}
}

// TestABannerIsBoundedAndSanitised.
//
// An engine parses hostile input by design: a banner comes from a host that may
// be adversarial, and it lands in a jsonb column an operator UI renders.
func TestABannerIsBoundedAndSanitised(t *testing.T) {
	port := listener(t, func(c net.Conn) {
		// Far more than the cap, with control characters in it.
		_, _ = c.Write([]byte("\x00\x01\x02BEGIN"))
		big := make([]byte, maxBannerBytes*4)
		for i := range big {
			big[i] = 'A'
		}
		_, _ = c.Write(big)
	})

	got := collect(t, baseConfig(port), []Target{{TaskID: "t", Value: "127.0.0.1"}})
	if len(got["banner"]) != 1 {
		t.Fatalf("got %d banners, want 1", len(got["banner"]))
	}
	data, _ := got["banner"][0]["data"].(string)
	// base64 in JSON; the decoded length is what matters.
	if len(data) == 0 {
		t.Fatal("empty banner")
	}
	raw := decodeBase64(t, data)
	if len(raw) > maxBannerBytes {
		t.Errorf("read %d bytes from a hostile host, cap is %d", len(raw), maxBannerBytes)
	}
	for _, c := range raw {
		if c < 0x20 && c != ' ' {
			t.Errorf("a control byte %#x survived into the payload", c)
			break
		}
	}
}

// TestADeadHostIsReportedWithItsMethodAndLowerConfidence.
//
// TCP connect cannot tell a filtered host from an absent one, so a negative is
// evidence rather than fact and must not claim otherwise.
func TestADeadHostIsReportedWithItsMethodAndLowerConfidence(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1: reserved, never routed, guaranteed silent.
	cfg := baseConfig(freePort(t))
	cfg.ConnectTimeout = 150 * time.Millisecond

	var host Observation
	emit := func(o Observation) error {
		if o.Type == "host" {
			host = o
		}
		return nil
	}
	if err := Run(t.Context(), cfg, []Target{{TaskID: "t", Value: "192.0.2.1"}},
		emit, func(uint32) {}); err != nil {
		t.Fatal(err)
	}

	if host.ObservationID == "" {
		t.Fatal("no host observation for an unreachable target")
	}
	if host.Confidence >= 1.0 {
		t.Errorf("confidence %v for a negative; connect scanning cannot distinguish a "+
			"filtered host from an absent one, so this must not be reported as fact",
			host.Confidence)
	}
	var p map[string]any
	if err := json.Unmarshal(host.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p["alive"] != false || p["method"] == "" {
		t.Errorf("alive=%v method=%v; a negative must name what was tried", p["alive"], p["method"])
	}
}

// TestNoRateBudgetIsRefused. Zero is not a rate, and an engine that treated it
// as unlimited would be deciding its own budget.
func TestNoRateBudgetIsRefused(t *testing.T) {
	cfg := baseConfig(80)
	cfg.RatePPS = 0
	err := Run(t.Context(), cfg, []Target{{TaskID: "t", Value: "127.0.0.1"}},
		func(Observation) error { return nil }, func(uint32) {})
	if err == nil {
		t.Error("a job with no rate budget was accepted")
	}
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return p
}

func decodeBase64(t *testing.T, s string) []byte {
	t.Helper()
	var out []byte
	if err := json.Unmarshal([]byte(`"`+s+`"`), &out); err != nil {
		t.Fatalf("decode banner: %v", err)
	}
	return out
}

// TestRefusalIsDistinguishedFromEveryOtherFailure.
//
// ============================================================================
// A packet-capture audit measured three hosts reported alive at confidence 1.0
// with ZERO outbound packets.
// ============================================================================
//
// The classifier was "not a timeout, therefore alive", which folded
// ECONNREFUSED together with ENETUNREACH, EHOSTUNREACH and a DNS failure. Core
// derives assets from observations, so a sweep of a mostly-unroutable range
// would fabricate an asset per address at full confidence.
//
// Real errors, not constructed ones: isRefused compares syscall text because
// `syscall` is not on this engine's import allowlist, and a test built from
// fabricated errors would prove nothing about what the platform actually
// returns.
func TestRefusalIsDistinguishedFromEveryOtherFailure(t *testing.T) {
	// A real refusal: nothing listening on a port that was just released.
	closed := freePort(t)
	_, refusedErr := net.DialTimeout("tcp",
		net.JoinHostPort("127.0.0.1", strconv.Itoa(int(closed))), time.Second)
	if refusedErr == nil {
		t.Fatal("expected a refusal from a closed loopback port")
	}
	if !isRefused(refusedErr) {
		t.Errorf("a real refusal was not recognised: %v (%T). Hosts that exist would be "+
			"reported as absent.", refusedErr, refusedErr)
	}

	// A real routing failure. Which address produces one is platform-specific,
	// so it was found by MEASURING rather than assumed: 0.0.0.0 and 127.x give a
	// genuine refusal via loopback (and reporting those alive is correct),
	// 240.0.0.1 and TEST-NET time out, and the broadcast address is what the
	// kernel refuses to route.
	_, unreachErr := net.DialTimeout("tcp", "255.255.255.255:80", 2*time.Second)
	if unreachErr == nil {
		t.Fatal("expected a routing failure for the broadcast address")
	}
	if isRefused(unreachErr) {
		t.Errorf("a routing failure was classified as a refusal: %v. Nothing left the "+
			"machine, so there is no evidence of a host.", unreachErr)
	}

	// A timeout is not a refusal either.
	_, timeoutErr := net.DialTimeout("tcp", "192.0.2.1:80", 200*time.Millisecond)
	if timeoutErr != nil && isRefused(timeoutErr) {
		t.Errorf("a timeout was classified as a refusal: %v", timeoutErr)
	}
	if isRefused(nil) {
		t.Error("a nil error was classified as a refusal")
	}
}

// TestAnUnroutableTargetIsNotReportedAliveAndCostsNoBudget.
//
// The audit's exact case: three targets, zero outbound packets, three hosts
// reported alive with a `sent` count of nine packets that never existed.
func TestAnUnroutableTargetIsNotReportedAliveAndCostsNoBudget(t *testing.T) {
	cfg := baseConfig(freePort(t))
	cfg.ConnectTimeout = 300 * time.Millisecond

	var host Observation
	var sentTotal uint32
	err := Run(t.Context(), cfg, []Target{{TaskID: "t", Value: "255.255.255.255"}},
		func(o Observation) error {
			if o.Type == "host" {
				host = o
			}
			return nil
		},
		func(n uint32) { sentTotal += n })
	if err != nil {
		t.Fatal(err)
	}

	var p map[string]any
	if e := json.Unmarshal(host.Payload, &p); e != nil {
		t.Fatal(e)
	}
	if p["alive"] == true {
		t.Errorf("an unroutable address was reported alive (method=%v). Core derives assets "+
			"from these; at scale that is one fabricated asset per unroutable address.",
			p["method"])
	}
	if sentTotal != 0 {
		t.Errorf("the engine reported %d packet(s) sent for a target the kernel would not "+
			"route to. Nothing left the machine, and the runtime reclaims rate allocation "+
			"from this number.", sentTotal)
	}
}

// The banner read must honour its budget, not a hardcoded 1s cap — a greeting that
// arrives after 1s but within the budget MUST be captured. This is the ADR-083
// regression: exim's SMTP 220 arrives ~4s in (client reverse-DNS), and the old 1s
// cap dropped it non-deterministically, flipping release resolution between vote
// tiers. Uses net.Pipe with a delayed write; the delay (1.2s) is past the old cap.
func TestReadBannerCapturesGreetingAfterOldOneSecondCap(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		time.Sleep(1200 * time.Millisecond) // past the old 1s cap, within the 2s budget
		_, _ = server.Write([]byte("220 test ESMTP Exim 4.99.1"))
	}()
	got := readBanner(context.Background(), client, 2*time.Second, maxBannerBytes)
	if !strings.Contains(string(got), "Exim") {
		t.Fatalf("a greeting at 1.2s within a 2s budget must be captured (ADR-083); got %q", got)
	}
}

// A genuinely silent port yields nil after the budget, and does not hang past it.
func TestReadBannerSilentPortGivesUpAtBudget(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	start := time.Now()
	got := readBanner(context.Background(), client, 150*time.Millisecond, maxBannerBytes)
	if got != nil {
		t.Fatalf("a silent conn must yield nil, got %q", got)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("readBanner waited %v, should give up near the 150ms budget", elapsed)
	}
}
