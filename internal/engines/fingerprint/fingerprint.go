// Package fingerprint is the engine that says WHAT is listening on a port.
//
// Discovery answers "there is something on 443". This answers "it is nginx
// 1.27.5 behind a certificate that expires on Thursday" — or, when that is all
// anyone can honestly say, "it speaks HTTP and will not name itself".
//
// # Two ways to learn, and only one of them is free
//
// Some services announce themselves the moment a connection opens. Reading that
// costs nothing beyond the connection and provokes nothing, so it happens in
// EVERY mode including safe — the bytes had already arrived by the time a rule
// looked at them.
//
// The rest say nothing until spoken to. HTTP, TLS, SMB, RDP and the databases
// all wait for the client, so identifying them means sending something, and
// sending something is what ADR-021 calls intrusive. The runtime enforces that
// by handing a safe job an EMPTY probe list, so there is no branch in this
// package that a bug could route around. The honest cost, stated rather than
// discovered: under a safe job an open 443 is an open port with nothing
// attached.
//
// # It holds no corpus, no scope and no probes of its own
//
// Every pattern and every payload arrives on the wire, already filtered by a
// static safety policy this process cannot see and cannot widen. Targets arrive
// resolved and pre-authorised; this package constructs none.
//
// # crypto/tls, and why an exception was worth asking for
//
// A verifying dial fails on exactly the certificates worth reporting — expired,
// self-signed, wrong hostname — and returns an error where the evidence should
// be. So this engine inspects without trusting, in one constructor whose name
// says so, and a mutation asserts that a plain verified dial fails these tests.
// See tls.go, and ADR-048 for what the exception buys and what bounds it.
package fingerprint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/engines/enginerate"
)

// Target is one resolved, pre-authorised unit of work.
type Target struct {
	TaskID  string
	Value   string
	Fragile bool
}

// Probe is a payload the runtime has authorised this job to send.
type Probe struct {
	Name      string
	Ports     []uint16
	Payload   []byte
	ReadBytes uint32
	TLS       bool
	Rarity    int
	Matches   []Match
}

// Config is the job's whole allowance.
type Config struct {
	// RatePPS is this engine's SLICE of the runtime's budget, already reduced
	// for a fragile target. A ceiling, never a starting point.
	RatePPS float64

	ConnectTimeout         time.Duration
	MaxConcurrentPerTarget int

	// Ports to examine. Empty takes ServicePorts.
	Ports []uint16

	// SafetyMode travels for PROVENANCE and decides nothing here. What decides
	// is whether Probes is empty.
	SafetyMode string

	// Probes is empty under a safe job. That emptiness is the enforcement.
	Probes []Probe

	// BannerMatches run against what a service volunteered, in every mode.
	BannerMatches []Match

	// MaxProbesPerPort caps the fallback chain. Zero takes the engine's own
	// default rather than meaning unlimited.
	MaxProbesPerPort int
}

// Observation is what the engine emits.
type Observation struct {
	ObservationID string
	TaskID        string
	Type          string
	Payload       []byte
	Confidence    float32
	ObservedAt    time.Time
}

// Emit is how an engine reports. Returning an error stops the scan.
type Emit func(Observation) error

// Sent reports packets actually sent, so the runtime can reclaim unused rate
// allocation (ADR-027).
type Sent func(uint32)

// Platform ceilings, held here as well as in the runtime.
//
// ADR-024 argues that duplicating a control is deliberate. A ceiling that
// arrives over the same channel as the value it bounds is not a ceiling, so
// these are compiled in.
const (
	platformMaxRatePerTarget       = 50
	platformMaxConcurrentPerTarget = 20
	platformMaxConnectTimeout      = 3 * time.Second
	platformMaxProbesPerPort       = 8

	// maxResponseBytes bounds one read from a host that may be adversarial.
	maxResponseBytes = 16 << 10
)

// Run identifies services on every target.
//
// Sequential across targets, concurrent within one — ADR-024's ceilings are per
// TARGET, and scanning several hosts at once would need a per-host bucket each
// while the aggregate slice is shared.
func Run(ctx context.Context, cfg Config, targets []Target, emit Emit, sent Sent) error {
	ports := cfg.Ports
	if len(ports) == 0 {
		ports = ServicePorts()
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 3 * time.Second
	}
	if cfg.MaxConcurrentPerTarget <= 0 {
		cfg.MaxConcurrentPerTarget = 1
	}
	if cfg.MaxProbesPerPort <= 0 {
		cfg.MaxProbesPerPort = platformMaxProbesPerPort
	}
	if cfg.RatePPS <= 0 {
		return errors.New("fingerprint: no rate budget; the runtime allocates one and zero is not a rate")
	}

	if cfg.RatePPS > platformMaxRatePerTarget {
		cfg.RatePPS = platformMaxRatePerTarget
	}
	if cfg.MaxConcurrentPerTarget > platformMaxConcurrentPerTarget {
		cfg.MaxConcurrentPerTarget = platformMaxConcurrentPerTarget
	}
	if cfg.ConnectTimeout > platformMaxConnectTimeout {
		cfg.ConnectTimeout = platformMaxConnectTimeout
	}
	if cfg.MaxProbesPerPort > platformMaxProbesPerPort {
		cfg.MaxProbesPerPort = platformMaxProbesPerPort
	}

	// ================================================================
	// A SECOND site for the three controls that decide whether a payload
	// leaves at all.
	// ================================================================
	//
	// The engine already compiles in ADR-024's rate, concurrency, timeout and
	// chain ceilings on the argument that "a ceiling that arrives over the same
	// channel as the value it bounds is not a ceiling". A safety audit pointed
	// out that the three controls with the largest blast radius — safe mode, the
	// fragile flag, and the non-inert port denylist — arrived over exactly that
	// channel and were duplicated nowhere, while enginewire.Probe's own comment
	// claimed a probe was "subject to every rule": true at the runtime, false
	// here. Driving a hand-written job into this process's stdin put `@PJL INFO
	// ID` on port 9100 under a job marked safe and fragile.
	//
	// This is NOT a scope check, and the distinction is the one ADR-027 draws.
	// Scope is a question about WHICH HOST, it needs data this engine must never
	// hold, and it stays at Core and the runtime. These are questions about WHAT
	// MAY BE SENT, answered from constants compiled into this binary that no
	// wire field can move — the same shape as the rate ceiling above.
	cfg.Probes = withheldProbes(cfg)

	// Compiled once per job rather than once per response. A regexp compiled
	// inside the port loop would be recompiled ports × probes times against a
	// corpus that does not change.
	cfg.BannerMatches = compileMatches(cfg.BannerMatches)
	for i := range cfg.Probes {
		cfg.Probes[i].Matches = compileMatches(cfg.Probes[i].Matches)
	}

	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}

		// ================================================================
		// An ADDRESS, or nothing. This engine does not resolve names.
		// ================================================================
		//
		// The same refusal the discovery engine makes, for the same measured
		// reason: net.Dialer resolves a hostname and connects to whatever comes
		// back, and nothing checks that answer against scope. internal/scope
		// matches hostname rules by string equality, so an allowed name pointing
		// at an excluded address reaches a host both enforcement sites refused.
		//
		// Repeated here rather than shared, because a second engine that could
		// dial is a second way to reach that bypass, and a check that lives in
		// one engine protects one engine.
		if net.ParseIP(t.Value) == nil {
			if err := emit(observation(t.TaskID, "service", servicePayload{
				Address: t.Value, Method: "refused", SafetyMode: cfg.SafetyMode,
				Detail: "not an IP address; this engine resolves no names because nothing " +
					"would check the answer",
			}, 0)); err != nil {
				return err
			}
			continue
		}

		// ADR-024 control 3: a fragile target suppresses aggressive checks AND
		// caps rate. The runtime withholds probes for a whole job containing one;
		// this is the per-target form of the same rule, and it is here because
		// `grep Fragile` in this package used to return a struct field and no
		// reader — the exact defect a packet-capture audit found in the
		// discovery engine, repeated.
		targetCfg := cfg
		if t.Fragile {
			targetCfg.Probes = nil
			targetCfg.MaxConcurrentPerTarget = 1
		}

		if err := identifyTarget(ctx, targetCfg, t, ports, emit, sent); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			return err
		}
	}
	return ctx.Err()
}

func identifyTarget(ctx context.Context, cfg Config, t Target, ports []uint16, emit Emit, sent Sent) error {
	limiter := enginerate.New(cfg.RatePPS, nil)

	var (
		wg      sync.WaitGroup
		sem     = make(chan struct{}, cfg.MaxConcurrentPerTarget)
		mu      sync.Mutex
		packets uint32
		emitErr error
	)
	count := func(n uint32) {
		mu.Lock()
		packets += n
		mu.Unlock()
	}

	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		// Taken BEFORE the goroutine starts, so the rate governs how fast work
		// is created rather than how fast it finishes. Taking them inside would
		// let MaxConcurrentPerTarget goroutines start at once and then queue on
		// the bucket, which is a burst at the host followed by a wait.
		prepaid := enginerate.SynCost(cfg.ConnectTimeout)
		if err := limiter.TakeN(ctx, prepaid); err != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port uint16) {
			defer wg.Done()
			defer func() { <-sem }()

			obs, timedOut := identifyPort(ctx, cfg, limiter, t, port, prepaid, count)
			if timedOut {
				limiter.BackOff()
			}
			mu.Lock()
			for _, o := range obs {
				if emitErr == nil {
					emitErr = emit(o)
				}
			}
			mu.Unlock()
		}(port)
	}
	wg.Wait()
	sent(packets)

	if emitErr != nil {
		return emitErr
	}
	return ctx.Err()
}

// identifyPort is one port: connect, listen, then ask if allowed to.
func identifyPort(ctx context.Context, cfg Config, limiter *enginerate.Bucket, t Target, port uint16, prepaid uint32, count func(uint32)) (obs []Observation, timedOut bool) {
	address := t.Value
	conn, cost, timedOut, err := dial(ctx, address, port, cfg.ConnectTimeout)
	count(cost)
	// Reconcile against what was taken before the dial. Without this the bucket
	// paces on SYNs and everything after the handshake — the ACK and FIN pair, a
	// handshake, a payload — is free; measured at 2.24x the ceiling.
	if err := limiter.Settle(ctx, prepaid, cost); err != nil {
		return nil, timedOut
	}
	if err != nil {
		// A closed or filtered port produces no service observation. Discovery
		// owns the record of which ports were tried; duplicating it here would
		// be two sources of truth for coverage.
		return nil, timedOut
	}

	best := servicePayload{
		Address: address, Port: port, Protocol: "tcp",
		SafetyMode: cfg.SafetyMode,
	}
	var (
		bestConf float32
		haveBest bool
	)

	// ------------------------------------------------------------------
	// What it volunteered. Free, and it happens in every mode.
	// ------------------------------------------------------------------
	raw := readResponse(ctx, conn, bannerWait(ctx, port, cfg.ConnectTimeout), maxResponseBytes)
	_ = conn.Close()

	if len(raw) > 0 {
		best.Evidence = string(sanitise(raw))
		best.Method = "banner"
		best.Solicited = false
		if r, ok := evaluate(cfg.BannerMatches, raw, port); ok {
			applyResult(&best, r)
			bestConf, haveBest = r.Confidence, true
			if !r.Soft {
				// Named itself, with a product. Nothing a probe could add is
				// worth the packets.
				return []Observation{observation(t.TaskID, "service", best, bestConf)}, false
			}
		}
	}

	// ------------------------------------------------------------------
	// What it will only say when asked. Empty under a safe job.
	// ------------------------------------------------------------------
	for _, p := range chainFor(cfg.Probes, port, cfg.MaxProbesPerPort) {
		if ctx.Err() != nil {
			break
		}
		// ================================================================
		// Solicited is true because we SENT something, not because a rule
		// matched.
		// ================================================================
		//
		// It used to be set only inside the branch where a match succeeded, so a
		// host that was probed and said nothing recognisable was reported as
		// unsolicited — measured on three lab hosts, including one that had just
		// completed a TLS handshake and one that had been sent a bare newline.
		// The field answers an operator's "did we touch this host", and the
		// answer does not depend on whether the answer was useful.
		best.Solicited = true
		// ================================================================
		// The WHOLE probe's budget, before the connection is opened.
		// ================================================================
		//
		// Charging each phase as it happens was the second attempt and it made
		// things worse in a way only a capture showed: a connection waiting on
		// tokens for its handshake sits idle, and an idle connection produces
		// retransmits and teardown packets nobody charged for. At a 10 pps
		// fragile budget that was 87 packets on the wire against 76 charged.
		//
		// Acquiring first means the socket opens only when the whole exchange
		// can be paid for, so no connection is ever held open by the rate
		// limiter itself.
		probePrepaid := probeCost(p, cfg.ConnectTimeout)
		if err := limiter.TakeN(ctx, probePrepaid); err != nil {
			break
		}
		r, tlsInfo, resp, cost, ok := runProbe(ctx, cfg, address, port, p)
		count(cost)
		if err := limiter.Settle(ctx, probePrepaid, cost); err != nil {
			break
		}
		if tlsInfo != nil {
			// Recorded even when no rule matched. A certificate is evidence in
			// its own right — week 6's rules read it directly — and losing it
			// because the application layer stayed quiet would throw away the
			// expensive half of the handshake.
			best.TLS = tlsInfo
			if best.Method == "" {
				best.Method = "tls"
			}
		}
		if len(resp) > 0 && best.Evidence == "" {
			best.Evidence = string(sanitise(resp))
		}
		if !ok {
			continue
		}
		if haveBest && !better(r, best.Softmatch, bestConf) {
			continue
		}
		applyResult(&best, r)
		bestConf, haveBest = r.Confidence, true
		best.Probe = p.Name
		best.Method = "probe"
		if p.TLS {
			best.Method = "tls-probe"
		}
		if !r.Soft {
			// ============================================================
			// A HARD match stops the chain. A SOFT one does not.
			// ============================================================
			//
			// The product name is precisely what the later, rarer probes exist
			// to recover: `server_tokens off` yields a soft "it speaks HTTP",
			// and the response-shape probe after it recovers "nginx" from an
			// error page. Stopping at the first soft match would make those
			// probes unreachable and the whole response-shape idea decorative.
			//
			// What bounds the cost is the CAP and the rarity ordering, not
			// early exit on any match at all: at most MaxProbesPerPort probes
			// reach one port, cheapest and most likely first, and a softmatch
			// is a reportable terminal answer when the cap runs out.
			break
		}
	}

	if best.Service == "" && best.TLS == nil && best.Evidence == "" {
		// Open, and nothing to say about it. Emitted anyway: "we looked and
		// found nothing" is coverage, and it is a different fact from "we never
		// looked". Confidence 1.0 — the port being open is certain even though
		// the service is unknown.
		best.Method = "none"
		return []Observation{observation(t.TaskID, "service", best, 1.0)}, false
	}
	if bestConf == 0 {
		// Evidence without a match: bytes were recorded and no rule fired.
		bestConf = 0.5
	}
	return []Observation{observation(t.TaskID, "service", best, bestConf)}, false
}

// better reports whether a new result should displace the one held.
//
// ============================================================================
// A PRODUCT beats a softmatch, even at lower confidence. Found by a test.
// ============================================================================
//
// The first version compared confidence alone, and the response-shape case
// exposed it: `server_tokens off` yields a soft "it speaks HTTP" at 0.70 from
// the cheap probe, and the shape rule that recovers "nginx" from an error page
// carries 0.60 — deliberately, because shape evidence is weaker than a
// self-description. Ranked on confidence, the vaguer answer won and the shape
// probe's whole reason to exist was thrown away after being paid for in packets.
//
// The two numbers are not on one scale. Confidence ranks how much to believe an
// answer of a given KIND; soft against hard is a difference in kind, and knowing
// the product is strictly more than not knowing it. So: hard beats soft
// outright, and confidence decides between two answers of the same kind.
func better(r Result, heldSoft bool, heldConf float32) bool {
	if r.Soft != heldSoft {
		return heldSoft
	}
	return r.Confidence > heldConf
}

// runProbe sends one probe on its own connection.
//
// Its OWN connection, not the one the banner was read from. A service that has
// already sent a greeting is in a protocol state, and a second unrelated payload
// on the same connection produces a response neither probe can be said to have
// caused — which makes the provenance in the observation a fiction.
func runProbe(ctx context.Context, cfg Config, address string, port uint16, p Probe) (r Result, tlsInfo *tlsPayload, resp []byte, cost uint32, ok bool) {
	conn, cost, _, err := dial(ctx, address, port, cfg.ConnectTimeout)
	if err != nil {
		return Result{}, nil, nil, cost, false
	}
	defer func() { _ = conn.Close() }()

	rw := conn
	if p.TLS {
		tc, info, err := dialTLS(ctx, conn, address, cfg.ConnectTimeout)
		cost += TLSHandshakeCost
		if err != nil {
			// Not TLS, or a handshake this client cannot complete. Either is a
			// finding-shaped fact and neither is an error worth abandoning the
			// chain for.
			return Result{}, nil, nil, cost, false
		}
		rw, tlsInfo = tc, info
	}

	if len(p.Payload) > 0 {
		payload := substituteTarget(p.Payload, address)
		if err := rw.SetWriteDeadline(time.Now().Add(cfg.ConnectTimeout)); err != nil {
			return Result{}, tlsInfo, nil, cost, false
		}
		if _, err := rw.Write(payload); err != nil {
			return Result{}, tlsInfo, nil, cost, false
		}
		cost++
	}

	limit := int(p.ReadBytes)
	if limit <= 0 || limit > maxResponseBytes {
		limit = maxResponseBytes
	}
	resp = readResponse(ctx, rw, cfg.ConnectTimeout, limit)
	if len(resp) == 0 {
		return Result{}, tlsInfo, nil, cost, false
	}

	// The probe's own rules first, then the banner rules — a probe response is
	// often a greeting the banner rules already know how to read, which is what
	// makes the `newline` probe useful without carrying any rules of its own.
	if r, ok := evaluate(p.Matches, resp, port); ok {
		return r, tlsInfo, resp, cost, true
	}
	if r, ok := evaluate(cfg.BannerMatches, resp, port); ok {
		return r, tlsInfo, resp, cost, true
	}
	return Result{}, tlsInfo, resp, cost, false
}

// withheldProbes applies the engine's own copy of the three send-side controls.
//
// Silent rather than reported, and deliberately so: this is a SECOND site, and
// the runtime already reports what it withheld. Anything dropped here means the
// runtime and this engine disagree, which cannot happen through the normal path
// — so the value of dropping it is that the packet does not leave, not that
// somebody is told twice.
func withheldProbes(cfg Config) []Probe {
	if cfg.SafetyMode != safetyIntrusive {
		// Not a branch that decides safe mode — the runtime already handed a
		// safe job an empty list, and that emptiness is the enforcement. This is
		// the belt to that pair of braces, for a job that reached this process
		// some other way.
		return nil
	}
	kept := make([]Probe, 0, len(cfg.Probes))
	for _, p := range cfg.Probes {
		if len(p.Ports) == 0 || anyNonInert(p.Ports) {
			continue
		}
		if substitutedSize(p.Payload) > maxProbePayload {
			continue
		}
		kept = append(kept, p)
	}
	return kept
}

// nonInertPorts mirrors the runtime's denylist (internal/scanpoint/corpus.go).
//
// Duplicated rather than imported, because internal/scanpoint is not on the
// engine import allowlist and putting it there would give an engine the
// runtime's whole surface. The two lists are asserted equal by
// TestTheEngineDenylistMatchesTheRuntimes, which reads both source files — a
// divergence here would be a second site that quietly permits what the first
// refuses.
var nonInertPorts = map[uint16]bool{
	515: true, 631: true, 9100: true,
	102: true, 502: true, 20000: true, 44818: true, 47808: true,
}

func anyNonInert(ports []uint16) bool {
	for _, p := range ports {
		if nonInertPorts[p] {
			return true
		}
	}
	return false
}

// maxProbePayload and maxTargetLength mirror the runtime's bounds, for the same
// reason nonInertPorts does.
const (
	maxProbePayload = 512
	maxTargetLength = 46
	safetyIntrusive = "intrusive"
)

// substitutedSize is the worst case after placeholders are replaced.
//
// The runtime checks this too. It is checked again here because substitution
// happens in THIS process, after every bound in that one: a 510-byte probe of 51
// placeholders was captured putting 867 bytes on the wire against a v4-mapped
// address, and ~1989 against a full IPv6 target.
func substitutedSize(payload []byte) int {
	n := bytes.Count(payload, []byte(targetPlaceholder))
	return len(payload) + n*(maxTargetLength-len(targetPlaceholder))
}

// probeCost is what one probe is expected to cost in packets, charged up front.
//
// The larger of the SYN train — what a filtered host costs, where the connection
// never opens — and the full exchange for a host that answers: the handshake
// pair, the TLS flight when there is one, and the payload's own packet. Settle
// reconciles it afterwards, so guessing high here costs a moment of pacing and
// never costs the ceiling.
func probeCost(p Probe, timeout time.Duration) uint32 {
	full := uint32(1 + enginerate.EstablishedCost)
	if p.TLS {
		full += TLSHandshakeCost
	}
	if len(p.Payload) > 0 {
		full++
	}
	if syn := enginerate.SynCost(timeout); syn > full {
		return syn
	}
	return full
}

// chainFor orders the probes that apply to one port, and caps them.
//
// ============================================================================
// Ordering is a BUDGET decision, not a tidiness one.
// ============================================================================
//
// A thirty-probe chain against one port costs thirty times what finding the port
// cost, and against a fragile host at 10 pps that is minutes on a single port.
// So: a probe that NAMES this port before a generic one, then by rarity, then by
// name so the order is stable across runs and two scans of the same host produce
// the same evidence.
func chainFor(probes []Probe, port uint16, cap int) []Probe {
	var out []Probe
	for _, p := range probes {
		if appliesTo(p.Ports, port) {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := len(out[i].Ports) > 0, len(out[j].Ports) > 0
		if si != sj {
			return si
		}
		if out[i].Rarity != out[j].Rarity {
			return out[i].Rarity < out[j].Rarity
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > cap {
		out = out[:cap]
	}
	return out
}

// dial opens a TCP connection and reports what it cost in packets.
func dial(ctx context.Context, address string, port uint16, timeout time.Duration) (net.Conn, uint32, bool, error) {
	dialer := net.Dialer{Timeout: timeout}
	hostPort := net.JoinHostPort(address, strconv.Itoa(int(port)))
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			// The SYN train happened in full.
			return nil, enginerate.SynCost(timeout), true, err
		}
		// Refused: one SYN out, a RST back.
		return nil, 1, false, err
	}
	// SYN, then the ACK completing the handshake and the FIN pair closing it.
	return conn, 1 + enginerate.EstablishedCost, false, nil
}

// bannerWait is how long to wait for something a service may never send.
//
// ============================================================================
// Service-aware, because a fixed one-second wait on every open port was a
// second per port spent listening for a greeting HTTP does not have.
// ============================================================================
//
// This is the deferred cost recorded against the discovery engine: safe mode
// held every open port for a full second waiting for a banner that, on an HTTP
// port, never arrives. The fix belongs here because only a fingerprint engine
// knows which protocols speak first.
//
// The trade is real and one-directional: a service that volunteers a banner
// LATER than the short wait, on a port where nothing normally volunteers, is
// missed. Under an intrusive job the probe chain covers that case. Under a safe
// job it is a genuine loss, and the short wait is still right — a second per
// silent port, across a /24 with ten open ports each, is forty minutes of a scan
// spent listening to nothing.
func bannerWait(ctx context.Context, port uint16, connectTimeout time.Duration) time.Duration {
	wait := time.Second
	if clientSpeaksFirst(port) {
		wait = 250 * time.Millisecond
	}
	if wait > connectTimeout {
		wait = connectTimeout
	}
	if dl, ok := ctx.Deadline(); ok {
		if left := time.Until(dl); left < wait {
			wait = left
		}
	}
	return wait
}

// readResponse reads what is available, bounded in bytes and in time.
//
// Returns RAW bytes. Sanitising before matching would be a defect rather than a
// precaution: `sanitise` replaces every control byte, and MySQL's handshake and
// Telnet's option negotiation are made of them — every binary rule would match
// the replacement characters instead of the protocol. Sanitising happens once,
// on the evidence excerpt that travels to a log and a JSON payload.
func readResponse(ctx context.Context, conn net.Conn, timeout time.Duration, limit int) []byte {
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		timeout = time.Until(dl)
	}
	if timeout <= 0 {
		return nil
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil
	}
	buf := make([]byte, limit)
	n, err := conn.Read(buf)
	if n <= 0 || (err != nil && n == 0) {
		return nil
	}
	return buf[:n]
}

// sanitise strips what must never reach a log or a JSON payload unescaped.
func sanitise(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		switch {
		case c == '\r' || c == '\n' || c == '\t':
			out[i] = ' '
		case c < 0x20 || c == 0x7f:
			out[i] = '.'
		default:
			out[i] = c
		}
	}
	return bytes.TrimSpace(out)
}

// substituteTarget replaces the placeholder with the authorised target.
//
// The engine composes no address of its own: the only value that can appear here
// is the one the runtime already authorised (ADR-027).
func substituteTarget(payload []byte, address string) []byte {
	return []byte(strings.ReplaceAll(string(payload), targetPlaceholder, address))
}

// targetPlaceholder mirrors scanpoint.ProbeTargetPlaceholder, which this package
// cannot import. probes_test.go in internal/scanpoint asserts the two agree.
const targetPlaceholder = "{{target}}"

func applyResult(p *servicePayload, r Result) {
	p.Service = r.Service
	p.Product = r.Product
	p.Version = r.Version
	p.Info = r.Info
	p.Softmatch = r.Soft
	p.Pattern = r.Pattern
	if r.OSHint != "" {
		p.OS = &osHint{Hint: r.OSHint, Source: "service banner"}
	}
}

func observation(taskID, kind string, payload any, confidence float32) Observation {
	b, err := json.Marshal(payload)
	if err != nil {
		b = []byte(fmt.Sprintf("{%q:%q}", "marshal_error", err.Error()))
	}
	return Observation{
		ObservationID: uuid.NewString(),
		TaskID:        taskID,
		Type:          kind,
		Payload:       b,
		Confidence:    confidence,
		ObservedAt:    time.Now().UTC(),
	}
}
