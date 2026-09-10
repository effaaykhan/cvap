package fingerprint

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These drive REAL sockets against listeners this test owns.
//
// The reason is on the record in the discovery engine's tests: an ICMP path in
// that package was written, reviewed and merged before anyone ran it, and
// net.ListenPacket did not create the socket it claimed to. A test against a
// fake dialer would have passed. Matching is the half of this engine that a unit
// test can check in isolation; whether the bytes actually arrive is not.

// server starts a TCP listener and records everything the client sent to it.
//
// The received count is what proves safe mode: an assertion that the engine
// produced no probe observation would also pass if the probe were sent and the
// response ignored.
type server struct {
	port     uint16
	received atomic.Int64
}

func serve(t *testing.T, handle func(c net.Conn, first []byte)) *server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &server{port: uint16(ln.Addr().(*net.TCPAddr).Port)}
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
				n, _ := c.Read(buf)
				if n > 0 {
					s.received.Add(int64(n))
				}
				handle(c, buf[:n])
			}()
		}
	}()
	return s
}

func collect(t *testing.T, cfg Config, units []Target) []servicePayload {
	t.Helper()
	var (
		mu  sync.Mutex
		out []servicePayload
	)
	emit := func(o Observation) error {
		var p servicePayload
		if err := json.Unmarshal(o.Payload, &p); err != nil {
			t.Errorf("observation payload is not JSON: %v", err)
			return nil
		}
		mu.Lock()
		out = append(out, p)
		mu.Unlock()
		return nil
	}
	if err := Run(t.Context(), cfg, units, emit, func(uint32) {}); err != nil {
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

func target() []Target { return []Target{{TaskID: "t1", Value: "127.0.0.1"}} }

// TestABannerIdentifiesAServiceWithoutSendingAnything.
//
// The safe-mode deliverable in one test: a service that volunteers is fully
// identified — protocol, product and version — with zero bytes leaving this
// process. `received` is the assertion that matters; a check on the observation
// alone would pass just as well if a probe had been sent and its answer thrown
// away.
func TestABannerIdentifiesAServiceWithoutSendingAnything(t *testing.T) {
	// Written before any read, so the banner is genuinely volunteered.
	s := serveGreeting(t, "SSH-2.0-OpenSSH_10.3\r\n")

	cfg := baseConfig(s.port)
	cfg.BannerMatches = []Match{{
		Pattern: `^SSH-2\.0-OpenSSH_(?P<version>[0-9][\w.]*)`,
		Service: "ssh", Product: "OpenSSH", Confidence: 0.95,
	}}

	got := collect(t, cfg, target())
	if len(got) != 1 {
		t.Fatalf("want one service observation, got %d", len(got))
	}
	p := got[0]
	if p.Service != "ssh" || p.Product != "OpenSSH" || p.Version != "10.3" {
		t.Errorf("identification: service=%q product=%q version=%q", p.Service, p.Product, p.Version)
	}
	if p.Method != "banner" {
		t.Errorf("method = %q, want banner", p.Method)
	}
	if p.Solicited {
		t.Error("solicited is true for a banner nobody asked for")
	}
	if p.Softmatch {
		t.Error("a match that named a product is not a softmatch")
	}
	if n := s.received.Load(); n != 0 {
		t.Errorf("%d bytes were sent to identify a service that announced itself", n)
	}
}

// serveGreeting is a listener that writes first and then reads.
func serveGreeting(t *testing.T, banner string) *server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := &server{port: uint16(ln.Addr().(*net.TCPAddr).Port)}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte(banner))
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				if n > 0 {
					s.received.Add(int64(n))
				}
			}()
		}
	}()
	return s
}

// TestSafeModeCannotSendAProbeBecauseItHasNone.
//
// The enforcement is the EMPTY probe list, not the mode string. This asserts the
// engine given no probes sends nothing at a service that volunteers nothing —
// where a probe would be the only way to learn anything, so the temptation to
// send one is at its highest.
func TestSafeModeCannotSendAProbeBecauseItHasNone(t *testing.T) {
	s := serve(t, func(c net.Conn, first []byte) {
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.27.5\r\n\r\n"))
	})

	cfg := baseConfig(s.port)
	cfg.SafetyMode = "safe"
	cfg.BannerMatches = []Match{{Pattern: `Server: nginx`, Service: "http", Product: "nginx", Confidence: 0.9}}
	// No probes: this is what job.budget hands a safe job.

	got := collect(t, cfg, target())
	if n := s.received.Load(); n != 0 {
		t.Fatalf("%d bytes sent under a safe job", n)
	}
	if len(got) != 1 {
		t.Fatalf("want one observation for the open port, got %d", len(got))
	}
	if got[0].Service != "" {
		t.Errorf("service %q was identified without sending anything to a server that speaks first",
			got[0].Service)
	}
	if got[0].Method != "none" {
		t.Errorf("method = %q, want none — the port was open and nothing was learned", got[0].Method)
	}
}

// TestASoftmatchIsAnAnswerNotAFailure.
//
// "This is HTTP, product unknown" has to be representable, because a great deal
// of real software is configured not to name itself. The failure this guards
// against is reporting nothing at all for such a service, which loses the port's
// identity entirely.
func TestASoftmatchIsAnAnswerNotAFailure(t *testing.T) {
	s := serve(t, func(c net.Conn, _ []byte) {
		// No Server header at all.
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})

	cfg := baseConfig(s.port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{
		Name: "http-head", Ports: []uint16{s.port}, Payload: []byte("HEAD / HTTP/1.0\r\n\r\n"),
		Matches: []Match{{Pattern: `^HTTP/1\.[01] \d{3}`, Service: "http", Soft: true, Confidence: 0.7}},
	}}

	got := collect(t, cfg, target())
	if len(got) != 1 {
		t.Fatalf("want one observation, got %d", len(got))
	}
	p := got[0]
	if p.Service != "http" {
		t.Errorf("service = %q, want http", p.Service)
	}
	if !p.Softmatch {
		t.Error("softmatch is false for a match that named no product")
	}
	if p.Product != "" {
		t.Errorf("product = %q, want empty for a softmatch", p.Product)
	}
	if !p.Solicited {
		t.Error("solicited is false for an answer we asked for")
	}
}

// TestASoftMatchDoesNotEndTheChainButAHardOneDoes.
//
// The whole point of the response-shape probe: `server_tokens off` yields a soft
// "it speaks HTTP" from the cheap probe, and the product is only recoverable
// from a later, rarer one. Stopping the chain at the first match of any kind
// would make every shape rule unreachable — which is a feature that exists in
// the corpus and never runs.
func TestASoftMatchDoesNotEndTheChainButAHardOneDoes(t *testing.T) {
	var sawBadVersion atomic.Bool
	s := serve(t, func(c net.Conn, first []byte) {
		if strings.Contains(string(first), "HTTP/9.9") {
			sawBadVersion.Store(true)
			_, _ = c.Write([]byte("HTTP/1.1 505 x\r\n\r\n<hr><center>nginx</center>"))
			return
		}
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})

	cfg := baseConfig(s.port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{
		{
			Name: "http-head", Ports: []uint16{s.port}, Rarity: 1,
			Payload: []byte("HEAD / HTTP/1.0\r\n\r\n"),
			Matches: []Match{{Pattern: `^HTTP/1\.[01] \d{3}`, Service: "http", Soft: true, Confidence: 0.7}},
		},
		{
			Name: "http-badversion", Ports: []uint16{s.port}, Rarity: 5,
			Payload: []byte("GET / HTTP/9.9\r\n\r\n"),
			Matches: []Match{{Pattern: `<hr><center>nginx</center>`, Service: "http", Product: "nginx", Confidence: 0.6}},
		},
	}

	got := collect(t, cfg, target())
	if !sawBadVersion.Load() {
		t.Fatal("the shape probe was never sent: a soft match ended the chain")
	}
	if len(got) != 1 {
		t.Fatalf("want one observation, got %d", len(got))
	}
	if got[0].Product != "nginx" {
		t.Errorf("product = %q, want nginx recovered from the response shape", got[0].Product)
	}
	if got[0].Softmatch {
		t.Error("the final answer named a product and is still marked soft")
	}
	if got[0].Probe != "http-badversion" {
		t.Errorf("probe = %q, want the shape probe credited", got[0].Probe)
	}
}

// TestTheChainIsCappedSoOnePortCannotCostThirtyProbes.
//
// A thirty-probe chain against one port costs thirty times what finding the port
// cost, and against a fragile host at 10 pps that is minutes on one port. The
// cap is the bound; rarity ordering decides which probes are inside it.
func TestTheChainIsCappedSoOnePortCannotCostThirtyProbes(t *testing.T) {
	var connections atomic.Int64
	s := serve(t, func(c net.Conn, _ []byte) {
		connections.Add(1)
		_, _ = c.Write([]byte("nothing any rule recognises"))
	})

	cfg := baseConfig(s.port)
	cfg.SafetyMode = "intrusive"
	cfg.MaxProbesPerPort = 3
	for i := range 20 {
		cfg.Probes = append(cfg.Probes, Probe{
			Name: string(rune('a'+i)) + "-probe", Ports: []uint16{s.port}, Rarity: i,
			Payload: []byte("x"),
			Matches: []Match{{Pattern: `never matches this`, Service: "x", Confidence: 0.5}},
		})
	}

	collect(t, cfg, target())
	// One connection for the banner read, then at most the cap.
	if got := connections.Load(); got > 1+3 {
		t.Errorf("%d connections for one port; the cap of 3 probes was not applied", got)
	}
}

// TestTheChainTriesAPortSpecificProbeBeforeAGenericOne.
//
// Ordering is a budget decision. A probe that names this port is far likelier to
// match than a generic one, so trying it first is what makes "stop on a hard
// match" save packets rather than merely reorder them.
func TestTheChainTriesAPortSpecificProbeBeforeAGenericOne(t *testing.T) {
	probes := []Probe{
		{Name: "generic-late", Rarity: 1},
		{Name: "specific", Ports: []uint16{443}, Rarity: 9},
		{Name: "generic-early", Rarity: 0},
	}
	chain := chainFor(probes, 443, 8)
	if len(chain) != 3 {
		t.Fatalf("chain length %d, want 3", len(chain))
	}
	if chain[0].Name != "specific" {
		t.Errorf("first probe is %q; a probe naming the port must precede a generic one "+
			"even at a worse rarity", chain[0].Name)
	}
	if chain[1].Name != "generic-early" || chain[2].Name != "generic-late" {
		t.Errorf("generic probes are out of rarity order: %q then %q", chain[1].Name, chain[2].Name)
	}
}

// TestAPortSpecificRuleDoesNotFireOnAnotherPort.
//
// `220 ` opens both SMTP and FTP and no pattern separates them, so the generic
// rule for each carries the ports it applies to. Without the scope, an FTP rule
// would claim every mail server.
func TestAPortSpecificRuleDoesNotFireOnAnotherPort(t *testing.T) {
	rules := compileMatches([]Match{
		{Pattern: `^220[ -]`, Service: "ftp", Soft: true, Ports: []uint16{21}, Confidence: 0.7},
		{Pattern: `^220[ -][^\r\n]*ESMTP`, Service: "smtp", Soft: true, Confidence: 0.7},
	})
	greeting := []byte("220 mail.example.test ESMTP Postfix\r\n")

	if r, ok := evaluate(rules, greeting, 25); !ok || r.Service != "smtp" {
		t.Errorf("on port 25: got %+v, want smtp", r)
	}
	if r, ok := evaluate(rules, greeting, 21); !ok || r.Service != "ftp" {
		t.Errorf("on port 21: got %+v, want the port-scoped ftp rule", r)
	}
}

// TestBinaryProtocolsMatchRawBytesNotSanitisedOnes.
//
// ============================================================================
// This is the one that fails if matching ever runs after sanitise().
// ============================================================================
//
// A MySQL handshake is a length-prefixed binary packet whose payload is full of
// control bytes and NULs. sanitise replaces every one of them, so a rule
// matching `\x00\x0a` against a sanitised banner matches the replacement
// characters instead of the protocol — a rule that silently never fires.
func TestBinaryProtocolsMatchRawBytesNotSanitisedOnes(t *testing.T) {
	handshake := append([]byte{0x4a, 0x00, 0x00, 0x00, 0x0a}, []byte("8.0.36-0ubuntu0.22.04.1\x00")...)
	rules := compileMatches([]Match{{
		Pattern: `(?s)^...\x00\x0a(?P<version>[0-9][^\x00]*)\x00`,
		Service: "mysql", Product: "MySQL", Confidence: 0.95,
	}})

	r, ok := evaluate(rules, handshake, 3306)
	if !ok {
		t.Fatal("the MySQL handshake did not match; binary rules need raw bytes")
	}
	if r.Version != "8.0.36-0ubuntu0.22.04.1" {
		t.Errorf("version = %q", r.Version)
	}

	if _, ok := evaluate(rules, sanitise(handshake), 3306); ok {
		t.Error("the rule matched SANITISED bytes too, so this test would not catch " +
			"matching in the wrong order")
	}
}

// TestAHighByteInAPatternMatchesThatByte.
//
// Telnet opens with IAC (0xff). Go regexps run over UTF-8, so a pattern written
// as `\xff` compiles to the rune U+00FF and encodes as two bytes — it would
// never match the one byte a Telnet server actually sends. latin1 is what makes
// the obvious pattern mean the obvious thing.
func TestAHighByteInAPatternMatchesThatByte(t *testing.T) {
	rules := compileMatches([]Match{{
		Pattern: `^\xff[\xfb-\xfe]`, Service: "telnet", Soft: true, Confidence: 0.7,
	}})
	if _, ok := evaluate(rules, []byte{0xff, 0xfd, 0x18}, 23); !ok {
		t.Fatal("IAC DO did not match; high bytes in a pattern are not reaching the wire bytes")
	}
	if _, ok := evaluate(rules, []byte("ÿý"), 23); ok {
		t.Error("the UTF-8 ENCODING of U+00FF matched, which means the mapping is not 1:1")
	}
}

// TestACapturedProductBeatsAnEmptyRuleField.
//
// The generic `Server: (?P<product>...)/(?P<version>...)` rule is what makes a
// server nobody wrote a rule for still identifiable. Its Product field is empty,
// so softness has to be decided by the RESOLVED product rather than by what the
// rule declared — otherwise every such match would be reported as "protocol
// known, product unknown" while holding the product.
func TestACapturedProductBeatsAnEmptyRuleField(t *testing.T) {
	rules := compileMatches([]Match{{
		Pattern: `\r\nServer: (?P<product>[^\r\n/]+)/(?P<version>[^\r\n ]+)`,
		Service: "http", Confidence: 0.95,
	}})
	r, ok := evaluate(rules, []byte("HTTP/1.1 200 OK\r\nServer: Caddy/2.7.6\r\n\r\n"), 80)
	if !ok {
		t.Fatal("no match")
	}
	if r.Product != "Caddy" || r.Version != "2.7.6" {
		t.Errorf("product=%q version=%q", r.Product, r.Version)
	}
	if r.Soft {
		t.Error("softmatch is true while the result holds a product")
	}
}

// TestAnUncompilablePatternIsDroppedRatherThanEvaluated.
//
// A rule whose regexp will not compile is a rule that matches nothing, silently.
// Dropping it at compile time is what makes the count of live rules honest.
func TestAnUncompilablePatternIsDroppedRatherThanEvaluated(t *testing.T) {
	rules := compileMatches([]Match{
		{Pattern: `([unclosed`, Service: "broken", Confidence: 0.9},
		{Pattern: `^ok`, Service: "fine", Confidence: 0.9},
	})
	if len(rules) != 1 || rules[0].Service != "fine" {
		t.Fatalf("compileMatches kept %d rules, want only the compilable one", len(rules))
	}
}

// TestANameIsRefusedBecauseNothingWouldCheckTheAnswer.
//
// The same refusal the discovery engine makes. internal/scope compares hostname
// rules by string equality, so an allowed name pointing at an excluded address
// reaches a host both enforcement sites refused — measured end to end against
// the discovery engine, and a second engine that can dial is a second way there.
func TestANameIsRefusedBecauseNothingWouldCheckTheAnswer(t *testing.T) {
	cfg := baseConfig(80)
	got := collect(t, cfg, []Target{{TaskID: "t1", Value: "localhost"}})
	if len(got) != 1 {
		t.Fatalf("want one refusal observation, got %d", len(got))
	}
	if got[0].Method != "refused" {
		t.Errorf("method = %q, want refused", got[0].Method)
	}
}

// TestNoRateBudgetIsRefused.
//
// Zero is not a rate. The runtime allocates one, and an engine that treated a
// missing allocation as "unlimited" would be the failure the allocation model
// exists to prevent.
func TestNoRateBudgetIsRefused(t *testing.T) {
	cfg := baseConfig(80)
	cfg.RatePPS = 0
	err := Run(t.Context(), cfg, target(), func(Observation) error { return nil }, func(uint32) {})
	if err == nil {
		t.Fatal("a job with no rate budget ran")
	}
}

// TestTheEngineClampsBeneathWhateverItWasHanded.
//
// ADR-024's ceilings are duplicated here as well as in the runtime, so a runtime
// bug cannot hand this engine a number the ADR forbids. Cheap, and the
// difference between one enforcement site and two.
func TestTheEngineClampsBeneathWhateverItWasHanded(t *testing.T) {
	s := serveGreeting(t, "SSH-2.0-x\r\n")
	cfg := baseConfig(s.port)
	cfg.RatePPS = 100000
	cfg.MaxConcurrentPerTarget = 5000
	cfg.ConnectTimeout = time.Minute
	cfg.MaxProbesPerPort = 500

	// Run mutates its own copy; assert through behaviour that the job completes
	// promptly rather than waiting a minute on the connect timeout.
	done := make(chan struct{})
	go func() {
		defer close(done)
		collect(t, cfg, target())
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the job did not finish; a connect timeout above the platform ceiling was honoured")
	}
}

// TestSolicitedIsTrueBecauseWeSentSomethingNotBecauseARuleMatched.
//
// The field answers an operator's "did we touch this host", and that answer does
// not depend on whether what came back was recognisable. It was set only inside
// the matched branch, so a probed host that said nothing useful was reported as
// unsolicited — a safety audit measured it on three lab hosts.
func TestSolicitedIsTrueBecauseWeSentSomethingNotBecauseARuleMatched(t *testing.T) {
	s := serve(t, func(c net.Conn, _ []byte) {
		_, _ = c.Write([]byte("bytes no rule in this test recognises"))
	})

	cfg := baseConfig(s.port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{
		Name: "poke", Ports: []uint16{s.port}, Payload: []byte("x"),
		Matches: []Match{{Pattern: `never matches`, Service: "x", Confidence: 0.9}},
	}}

	got := collect(t, cfg, target())
	if len(got) != 1 {
		t.Fatalf("want one observation, got %d", len(got))
	}
	if !got[0].Solicited {
		t.Error("solicited is false for a host this engine sent a payload to")
	}
	if n := s.received.Load(); n == 0 {
		t.Fatal("nothing was actually sent, so this test asserts nothing")
	}
}

// TestTheEngineWithholdsWhatTheRuntimeWouldHaveWithheld.
//
// ============================================================================
// A SECOND site for the three controls that decide whether a payload leaves.
// ============================================================================
//
// A safety audit drove a hand-written job into this process's stdin — bypassing
// the runtime entirely — marked safe and fragile and carrying a probe for port
// 9100, and captured `@PJL INFO ID` arriving there. On a real 9100 those bytes
// are a print job.
//
// This is not a scope check: scope asks WHICH HOST, needs data this engine must
// never hold, and stays at Core and the runtime (ADR-027). These ask WHAT MAY BE
// SENT, and they are answered from constants compiled into this binary that no
// wire field can move — the same shape as the rate ceiling the engine already
// duplicates.
func TestTheEngineWithholdsWhatTheRuntimeWouldHaveWithheld(t *testing.T) {
	probe := Probe{
		Name: "printer", Ports: []uint16{9100}, Payload: []byte("@PJL INFO ID\r\n"),
		Matches: []Match{{Pattern: `x`, Service: "printer", Confidence: 0.9}},
	}
	ordinary := Probe{
		Name: "fine", Ports: []uint16{8080}, Payload: []byte("x"),
		Matches: []Match{{Pattern: `x`, Service: "http", Confidence: 0.9}},
	}
	everywhere := Probe{
		Name: "everywhere", Payload: []byte("\r\n"),
		Matches: []Match{{Pattern: `x`, Service: "x", Confidence: 0.9}},
	}
	huge := Probe{
		Name: "grows", Ports: []uint16{8080},
		Payload: []byte(strings.Repeat(targetPlaceholder, 51)),
		Matches: []Match{{Pattern: `x`, Service: "x", Confidence: 0.9}},
	}

	all := []Probe{probe, ordinary, everywhere, huge}

	if got := withheldProbes(Config{SafetyMode: "safe", Probes: all}); len(got) != 0 {
		t.Errorf("a job that is not intrusive kept %d probe(s)", len(got))
	}
	kept := withheldProbes(Config{SafetyMode: "intrusive", Probes: all})
	if len(kept) != 1 || kept[0].Name != "fine" {
		t.Fatalf("kept %+v, want only the ordinary probe", names(kept))
	}
}

func names(ps []Probe) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

// TestAFragileTargetIsSentNoProbeByThisEngineEither.
//
// ADR-024 control 3: fragile suppresses aggressive checks AND caps rate. The
// runtime withholds probes for a whole job containing a fragile target; this is
// the per-target form. It exists because `grep Fragile` in this package returned
// a struct field and no reader — the same defect a packet-capture audit found in
// the discovery engine, repeated here.
func TestAFragileTargetIsSentNoProbeByThisEngineEither(t *testing.T) {
	s := serve(t, func(c net.Conn, _ []byte) {})

	cfg := baseConfig(s.port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{
		Name: "poke", Ports: []uint16{s.port}, Payload: []byte("x"),
		Matches: []Match{{Pattern: `x`, Service: "x", Confidence: 0.9}},
	}}

	collect(t, cfg, []Target{{TaskID: "t1", Value: "127.0.0.1", Fragile: true}})
	if n := s.received.Load(); n != 0 {
		t.Errorf("%d bytes sent to a target marked fragile", n)
	}
}

// bannerWait must give a delayed-greeting port (SMTP) longer than the connect
// ceiling, so exim's ~4s reverse-DNS-delayed 220 is captured and its release vote
// not dropped (ADR-083). A client-speaks-first port stays short; an ordinary
// server-first port stays at the connect-capped one second.
func TestBannerWaitAllowsDelayedGreeters(t *testing.T) {
	ctx := context.Background()
	const connect = 3 * time.Second

	if w := bannerWait(ctx, 25, connect); w != maxBannerWait {
		t.Errorf("SMTP(25) wait = %v, want maxBannerWait %v (above the connect cap)", w, maxBannerWait)
	}
	if w := bannerWait(ctx, 443, connect); w != 250*time.Millisecond {
		t.Errorf("HTTPS(443) wait = %v, want 250ms (client speaks first)", w)
	}
	if w := bannerWait(ctx, 9999, connect); w != time.Second {
		t.Errorf("ordinary server-first port wait = %v, want 1s", w)
	}
}
