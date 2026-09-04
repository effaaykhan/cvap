// Package discovery is the engine that finds hosts and open ports.
//
// # It is the first engine that can put a packet on a wire
//
// Everything else in internal/engines is inert by construction: the
// internal/enginepolicy allowlist permits only packages that parse, format,
// measure time or generate an id, and its exceptions map was empty. This package
// holds the first entry — `net` — granted deliberately, in a diff a reviewer
// sees, with ADR-047 explaining why this engine may send packets and how
// ADR-024's ceilings bind it.
//
// What that means in practice: everything below is written on the assumption
// that a mistake here reaches somebody's network.
//
// # What it does and does not do
//
// TCP connect scanning only. SYN, ARP and ICMP all need a socket the standard
// library will not create — raw for the first two, an unprivileged ICMP datagram
// socket for the third, which Go has no stdlib path to. Each would widen the
// engine import allowlist past the single `net` that ADR-047 argues for, and SYN
// and ARP additionally need CAP_NET_RAW, which changes how a scan point is
// DEPLOYED and not merely what it can do.
//
// The cost is real and accepted rather than unnoticed: connect completes the
// handshake, so it is louder and slower against a filtered host than SYN would
// be, and a fully filtered host is indistinguishable from an absent one.
//
// # It holds no scope data, and no probes of its own
//
// Targets arrive resolved and pre-authorised; this package constructs none and
// carries no allowlist, no exclusions and no CIDR arithmetic (ADR-024, ADR-027).
// Anything it wanted to touch that it was not given goes back to the runtime.
//
// Probes are HANDED to it by the runtime and are empty unless the job is
// intrusive (ADR-021). There is no probe corpus here, so "safe mode" is not a
// branch in this package that a bug could route around — under a safe job there
// is simply nothing to send, and what remains is a connect and a bounded read of
// whatever the service volunteers.
package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Target is one resolved, pre-authorised unit of work.
//
// Its own type rather than internal/enginewire's, because that package is not on
// the engine allowlist — the process shell translates. The duplication is the
// boundary doing its job: this package cannot reach the wire types, so it cannot
// grow a dependency on anything they might later carry.
type Target struct {
	TaskID  string
	Value   string
	Fragile bool
}

// Probe is a payload the runtime has authorised this job to send.
type Probe struct {
	Name      string
	Ports     []uint32
	Payload   []byte
	ReadBytes uint32
}

// Config is the job's whole allowance.
type Config struct {
	// RatePPS is this engine's SLICE of the runtime's budget, already reduced
	// for a fragile target. A ceiling, never a starting point.
	RatePPS float64

	ConnectTimeout         time.Duration
	MaxConcurrentPerTarget int

	// Ports to scan. Empty takes DefaultPorts.
	Ports []uint16

	// SafetyMode travels for PROVENANCE and decides nothing here. What decides
	// is whether Probes is empty.
	SafetyMode string
	Probes     []Probe
}

// Observation is what the engine emits. The runtime turns these into wire
// messages; this package has no idea a wire exists (ADR-006).
type Observation struct {
	ObservationID string
	TaskID        string
	Type          string
	Payload       []byte
	Confidence    float32
	ObservedAt    time.Time
}

// Emit is how an engine reports. Returning an error stops the scan — the runtime
// uses this for backpressure, so an engine that ignored it would buffer without
// bound.
type Emit func(Observation) error

// Sent reports packets actually sent, so the runtime can reclaim unused rate
// allocation (ADR-027).
type Sent func(uint32)

// Run scans every target.
//
// Sequential across targets, concurrent within one. That is not a performance
// choice: ADR-024's ceilings are per TARGET, and scanning several hosts at once
// would need a per-host bucket each while the aggregate slice is shared — which
// is the shared-mutable-rate-state arrangement ADR-027 rejects between
// processes and is no better inside one. One target at a time makes "50 pps at
// this host" true by construction.
func Run(ctx context.Context, cfg Config, targets []Target, emit Emit, sent Sent) error {
	ports := cfg.Ports
	if len(ports) == 0 {
		ports = DefaultPorts()
	}
	if cfg.ConnectTimeout <= 0 {
		cfg.ConnectTimeout = 3 * time.Second
	}
	if cfg.MaxConcurrentPerTarget <= 0 {
		cfg.MaxConcurrentPerTarget = 1
	}
	if cfg.RatePPS <= 0 {
		return errors.New("discovery: no rate budget; the runtime allocates one and zero is not a rate")
	}

	// A ceiling of this engine's own, beneath whatever it was allocated.
	//
	// ADR-024 argues that duplicating a control is deliberate, and until now the
	// single clamp in the runtime's job.budget and the single authorise in
	// enginehost were the only things between a Core value and the wire. These
	// cost one comparison each and mean a runtime bug cannot hand this engine a
	// number the ADR forbids.
	//
	// The platform figures are hard-coded rather than read from configuration
	// for the same reason the runtime hard-codes the fragile cap: a ceiling that
	// arrives over the same channel as the value it bounds is not a ceiling.
	if cfg.RatePPS > platformMaxRatePerTarget {
		cfg.RatePPS = platformMaxRatePerTarget
	}
	if cfg.MaxConcurrentPerTarget > platformMaxConcurrentPerTarget {
		cfg.MaxConcurrentPerTarget = platformMaxConcurrentPerTarget
	}
	if cfg.ConnectTimeout > platformMaxConnectTimeout {
		cfg.ConnectTimeout = platformMaxConnectTimeout
	}

	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			return err
		}

		// ================================================================
		// An ADDRESS, or nothing. This engine does not resolve names.
		// ================================================================
		//
		// net.Dialer resolves a hostname and connects to whatever comes back,
		// and NOBODY checks that answer. internal/scope matches hostname rules
		// by string equality and says so outright — "a hostname rule does not
		// cover the address that name resolves to, in either direction" — which
		// was a documented consequence while nothing in this repository could
		// dial. This engine made it a send path.
		//
		// A packet-capture audit drove it end to end: allow `printer.corp.example`,
		// exclude `10.10.0.20`, point the name at the excluded host, and ten
		// packets arrived at an address both enforcement sites had refused. The
		// resolver traffic is a second problem — two UDP/53 queries per connect,
		// to a resolver nobody authorised, naming every target.
		//
		// Refused here as well as at planning, because ADR-024's two sites exist
		// precisely so that neither has to be the only one. It costs one parse.
		if net.ParseIP(t.Value) == nil {
			if err := emit(observation(t.TaskID, "host", hostPayload{
				Address: t.Value, Alive: false, Method: "refused",
				Detail: "not an IP address; this engine resolves no names because nothing " +
					"would check the answer",
				SafetyMode: cfg.SafetyMode,
			}, 0)); err != nil {
				return err
			}
			continue
		}

		if err := scanTarget(ctx, cfg, t, ports, emit, sent); err != nil {
			// A per-target failure does not abandon the rest. A host that
			// refuses every connection is a normal outcome, and treating it as
			// fatal would make one unreachable address hide every other host in
			// the job.
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if err := emit(observation(t.TaskID, "host", hostPayload{
				Address: t.Value, Alive: false, Method: "error", Detail: truncate(err.Error(), 256),
				SafetyMode: cfg.SafetyMode,
			}, 0.5)); err != nil {
				return err
			}
		}
	}
	return nil
}

// hostPayload is a `host` observation: was anything there, and how do we know.
//
// Method is load-bearing rather than decoration. "Answered a TCP connect on 443"
// and "answered an ICMP echo" are different evidence, and a host reported alive
// with no method is a claim the pipeline cannot weigh.
type hostPayload struct {
	Address    string `json:"address"`
	Alive      bool   `json:"alive"`
	Method     string `json:"method"`
	Detail     string `json:"detail,omitempty"`
	SafetyMode string `json:"safety_mode"`

	// PortsScanned is what was actually tried, and it is here because only OPEN
	// ports produce their own observation.
	//
	// ========================================================================
	// Coverage has to be recorded somewhere, or "no open ports" is ambiguous.
	// ========================================================================
	//
	// The first version emitted a row per closed port, which for the default set
	// is ~180 per host — 45,000 for a /24, almost all of them saying nothing
	// happened, against an ingest budget of 5,000 observations a second and a
	// 90-day retention. Dropping them silently would have been worse than the
	// volume: "port 23 is not in the results" would then mean both "we looked
	// and it was closed" and "we never looked", and telling those apart is the
	// difference between a scan and a scan that looks complete.
	//
	// So the ports tried are recorded ONCE per host, and a port observation
	// means the port answered.
	PortsScanned []uint16 `json:"ports_scanned,omitempty"`
	PortsOpen    int      `json:"ports_open"`
}

// portPayload is a `port` observation, emitted for OPEN ports only.
//
// State is present and always "open" rather than being dropped, because the
// pipeline reads a type and a payload and a field that is always one value is
// cheaper than a schema that changes when closed ports start being reported
// again.
//
// It is never "filtered". Connect scanning cannot distinguish a filtered port
// from a slow one — both time out — so reporting filtered would be an inference
// dressed as an observation. A timeout produces no port observation at all, and
// the host's PortsScanned list is what says it was tried.
type portPayload struct {
	Address    string `json:"address"`
	Port       uint16 `json:"port"`
	Protocol   string `json:"protocol"`
	State      string `json:"state"`
	SafetyMode string `json:"safety_mode"`
}

// bannerPayload is a `banner` observation.
//
// Solicited says whether a probe was sent to get this. A banner a service
// volunteered and one drawn out by a payload are different confidence, and
// ADR-021 makes the difference operationally meaningful — most deployments run
// safe mode, so the pipeline must be able to tell what it is looking at.
type bannerPayload struct {
	Address    string `json:"address"`
	Port       uint16 `json:"port"`
	Data       []byte `json:"data"`
	Solicited  bool   `json:"solicited"`
	Probe      string `json:"probe,omitempty"`
	SafetyMode string `json:"safety_mode"`
}

// maxBannerBytes bounds an unsolicited read.
//
// An engine parses hostile input by design: a banner comes from a host that may
// be adversarial, and an unbounded read is a denial of service against your own
// fleet. A probe may name a smaller bound; none may name a larger one.
const maxBannerBytes = 8 << 10

func scanTarget(ctx context.Context, cfg Config, t Target, ports []uint16, emit Emit, sent Sent) error {
	limiter := newBucket(cfg.RatePPS, nil)
	var packets uint32
	var mu sync.Mutex
	count := func(n uint32) {
		mu.Lock()
		packets += n
		mu.Unlock()
	}

	alive, method := probeAlive(ctx, cfg, t.Value, limiter, count)
	if !alive {
		// Emitted before the early return, and it carries no PortsScanned
		// because none were.
		if err := emit(observation(t.TaskID, "host", hostPayload{
			Address: t.Value, Alive: false, Method: method, SafetyMode: cfg.SafetyMode,
		}, confidenceFor(false))); err != nil {
			return err
		}
		sent(packets)
		return ctx.Err()
	}

	sem := make(chan struct{}, cfg.MaxConcurrentPerTarget)
	var wg sync.WaitGroup
	var emitMu sync.Mutex
	var emitErr error
	var open int
	// scanned is what was actually TRIED, which is not the same as the
	// configured list once a cancellation cuts the loop short. Reporting the
	// configured list would claim coverage the scan did not have.
	scanned := make([]uint16, 0, len(ports))

	for _, port := range ports {
		if ctx.Err() != nil {
			break
		}
		// The token is taken BEFORE the goroutine starts, so the rate governs
		// how fast work is created rather than how fast it finishes. Taking it
		// inside would let MaxConcurrentPerTarget goroutines all start at once
		// and then queue on the bucket, which is a burst at the host followed by
		// a wait — the shape that tips a fragile device over.
		if err := limiter.take(ctx); err != nil {
			break
		}
		scanned = append(scanned, port)
		wg.Add(1)
		sem <- struct{}{}
		go func(port uint16) {
			defer wg.Done()
			defer func() { <-sem }()

			obs, timedOut := scanPort(ctx, cfg, t.TaskID, t.Value, port)
			count(1)
			if timedOut {
				// Timeouts, not refusals, are what a struggling host looks
				// like: a closed port answers immediately with a RST.
				limiter.backOff()
			}
			emitMu.Lock()
			if len(obs) > 0 {
				open++
			}
			for _, o := range obs {
				if emitErr == nil {
					emitErr = emit(o)
				}
			}
			emitMu.Unlock()
		}(port)
	}
	wg.Wait()
	sent(packets)

	// The host observation comes LAST for a live host, because it carries the
	// coverage record and that is not known until the scan finishes. A
	// cancellation partway through therefore leaves the ports that were reached
	// reported and no host row claiming more — which is the right direction:
	// missing evidence rather than overstated coverage.
	if err := emit(observation(t.TaskID, "host", hostPayload{
		Address: t.Value, Alive: true, Method: method, SafetyMode: cfg.SafetyMode,
		PortsScanned: scanned, PortsOpen: open,
	}, 1.0)); err != nil {
		return err
	}

	if emitErr != nil {
		return emitErr
	}
	return ctx.Err()
}

// scanPort connects, reads what is volunteered, and sends any authorised probe.
//
// Returns whether the attempt TIMED OUT, which is the signal back-off keys on —
// a refused connection is a closed port and says nothing about the host's
// health, while a timeout is what a host struggling to answer looks like.
func scanPort(ctx context.Context, cfg Config, taskID, address string, port uint16) ([]Observation, bool) {
	dialer := net.Dialer{Timeout: cfg.ConnectTimeout}
	hostPort := net.JoinHostPort(address, strconv.Itoa(int(port)))

	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		var ne net.Error
		timedOut := errors.As(err, &ne) && ne.Timeout()
		if timedOut {
			// Not reported as a port observation at all. A timeout is the
			// absence of an answer, and recording it as "closed" would be an
			// inference; recording it as "filtered" would be a stronger one that
			// connect scanning cannot support.
			return nil, true
		}
		// A refused connection is a CLOSED port and produces no observation.
		// The host's PortsScanned list records that it was tried; a row per
		// closed port is ~180 per host and says nothing happened.
		return nil, false
	}
	defer func() { _ = conn.Close() }()

	out := []Observation{observation(taskID, "port", portPayload{
		Address: address, Port: port, Protocol: "tcp", State: "open",
		SafetyMode: cfg.SafetyMode,
	}, 1.0)}

	// What the service volunteers, in both modes. Reading is not sending.
	if b := readBanner(ctx, conn, cfg.ConnectTimeout, maxBannerBytes); len(b) > 0 {
		out = append(out, observation(taskID, "banner", bannerPayload{
			Address: address, Port: port, Data: b, Solicited: false,
			SafetyMode: cfg.SafetyMode,
		}, 0.9))
	}

	// And whatever the runtime authorised, which is nothing under a safe job.
	for _, p := range cfg.Probes {
		if !probeApplies(p, port) {
			continue
		}
		payload := substituteTarget(p.Payload, address)
		if _, err := conn.Write(payload); err != nil {
			continue
		}
		limit := int(p.ReadBytes)
		if limit <= 0 || limit > maxBannerBytes {
			limit = maxBannerBytes
		}
		if b := readBanner(ctx, conn, cfg.ConnectTimeout, limit); len(b) > 0 {
			out = append(out, observation(taskID, "banner", bannerPayload{
				Address: address, Port: port, Data: b, Solicited: true, Probe: p.Name,
				SafetyMode: cfg.SafetyMode,
			}, 0.95))
		}
		// One probe per connection. A second would be sent to a service that has
		// already answered something else, and disentangling which payload
		// produced which bytes is not something the pipeline should have to do.
		break
	}
	return out, false
}

// readBanner reads what is available, bounded in both bytes and time.
func readBanner(ctx context.Context, conn net.Conn, timeout time.Duration, limit int) []byte {
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		timeout = time.Until(dl)
	}
	if timeout <= 0 {
		return nil
	}
	// A short read deadline rather than the full connect timeout: a service that
	// volunteers a banner does so immediately, and waiting the whole timeout on
	// every silent port would make a scan take ports × timeout.
	if timeout > time.Second {
		timeout = time.Second
	}
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil
	}
	buf := make([]byte, limit)
	n, err := conn.Read(buf)
	if n <= 0 || (err != nil && n == 0) {
		return nil
	}
	return sanitise(buf[:n])
}

// sanitise strips what must never reach a log or a JSON payload unescaped.
//
// The bytes come from a host that may be adversarial and they travel through the
// runtime's structured logger and into a jsonb column an operator UI renders.
// Control characters are replaced rather than dropped so the length still
// reflects what was received.
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
// is the one the runtime already authorised, which is what keeps target
// construction out of the engine (ADR-027).
func substituteTarget(payload []byte, address string) []byte {
	return []byte(strings.ReplaceAll(string(payload), "{{target}}", address))
}

func probeApplies(p Probe, port uint16) bool {
	if len(p.Ports) == 0 {
		return true
	}
	for _, want := range p.Ports {
		if uint32(port) == want {
			return true
		}
	}
	return false
}

func confidenceFor(alive bool) float32 {
	if alive {
		return 1.0
	}
	// Not zero. "Nothing answered" is evidence, just weaker than an answer: a
	// fully filtered host looks identical to an absent one over TCP connect.
	return 0.6
}

func observation(taskID, typ string, payload any, confidence float32) Observation {
	b, err := json.Marshal(payload)
	if err != nil {
		b = []byte(fmt.Sprintf("{%q:%q}", "marshal_error", err.Error()))
	}
	return Observation{
		ObservationID: uuid.NewString(),
		TaskID:        taskID,
		Type:          typ,
		Payload:       b,
		Confidence:    confidence,
		ObservedAt:    time.Now().UTC(),
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// The ADR-024 platform ceilings this engine will not exceed whatever it is
// handed. Duplicates of the runtime's, deliberately: two sites, per ADR-024.
const (
	platformMaxRatePerTarget       = 50
	platformMaxConcurrentPerTarget = 20
	platformMaxConnectTimeout      = 3 * time.Second
)
