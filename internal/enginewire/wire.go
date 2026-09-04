// Package enginewire is the job contract between the scan point runtime and an
// engine process (ADR-027).
//
// Newline-delimited JSON over the engine's stdin and stdout, bidirectional.
// Deliberately not gRPC: an engine must not be able to speak the dispatch
// protocol or open a socket, and a contract carried on two pipes it did not
// create is the cheapest way to make that structural rather than a rule. stderr
// is free text and the runtime logs it.
//
// # Why the engine can ask, and cannot decide
//
// ADR-027 puts scope enforcement at exactly two sites, Core and the RUNTIME,
// never in an engine. Engines receive resolved, pre-authorised targets and
// construct none — but a real engine discovers things mid-scan: a redirect, a
// DNS answer, a referenced host. The ADR says those "go back to the runtime for
// authorisation before the engine may touch it", which needs a request and a
// reply, which is why this contract is bidirectional rather than a job in and
// observations out.
//
// So an engine may ASK (Authorise) and the runtime ANSWERS (Authorised). The
// engine holds no allowlist, no exclusions and no CIDR arithmetic, and cannot
// reach a verdict on its own even if it wanted to. The no-op engine never asks —
// it discovers nothing — but the shape has to exist before an engine that does,
// or the first one to need it will be tempted to carry its own copy of the rules.
//
// # Streaming, not a final report
//
// Observations arrive one line at a time so the runtime holds whatever was
// produced before a SIGKILL. ADR-026 is unambiguous that results are never
// discarded, and an engine that reported only at the end would lose everything a
// killed job had gathered — which is exactly the record ADR-012's operator
// escalation is about.
package enginewire

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// MaxLine bounds one JSON message.
//
// An engine parses hostile input by design — a banner from an attacker-
// controlled host is untrusted — and an unbounded line here turns that into
// memory pressure in the runtime, which is the process holding credentials and
// every other job. bufio.Scanner's default 64 KiB is too small for an
// observation payload; 4 MiB matches the wire chunk cap.
const MaxLine = 4 << 20

// Kind values. Strings rather than an enum because this contract crosses a
// process boundary between independently-built binaries, and a numeric value
// whose meaning shifts between versions is the failure ADR-022 describes.
// Probe kinds. Strings for the reason the message kinds are: this contract
// crosses a process boundary between independently-built binaries.
const (
	// ProbeKindPayload sends bytes and reads a bounded reply. The default, and
	// the only kind ADR-048's payload bound applies to.
	ProbeKindPayload = ""

	// ProbeKindSSHHostKey performs an SSH key exchange far enough to receive the
	// host key and then ABANDONS it (ADR-049).
	//
	// It exists because ADR-007's `ssh_hostkey` is the only identity key most
	// Linux hosts can offer — every strong key needs an agent or cloud metadata
	// — and without it asset resolution cannot merge a host across a DHCP change.
	//
	// The abandonment is structural rather than promised: the engine implements
	// no message past the key-exchange reply, so there is no authentication path
	// to decline to take.
	ProbeKindSSHHostKey = "ssh_hostkey"
)

const (
	// Runtime to engine.
	KindJob        = "job"
	KindAuthorised = "authorised"

	// Engine to runtime.
	KindObservation = "observation"
	KindAuthorise   = "authorise"
	KindSent        = "sent"
	KindDone        = "done"
)

// Target is one resolved, pre-authorised unit of work.
//
// There is deliberately no allowlist or exclusion field. An engine that could
// evaluate scope would be a third enforcement site, and ADR-024's "both paths"
// assertion depends on there being exactly two.
type Target struct {
	TaskID  string `json:"task_id"`
	Value   string `json:"value"`
	Fragile bool   `json:"fragile"`
}

// ToEngine is a message the runtime sends.
type ToEngine struct {
	Kind string `json:"kind"`

	// KindJob.
	JobID   string   `json:"job_id,omitempty"`
	Targets []Target `json:"targets,omitempty"`

	// RateBudgetPPS is this engine's SLICE of the runtime's budget, not the
	// platform ceiling (ADR-027). Engines do not read the ceiling and do not
	// coordinate with each other; the aggregate is bounded by what the runtime
	// hands out, by construction rather than by cooperation.
	RateBudgetPPS uint32 `json:"rate_budget_pps,omitempty"`

	// ConnectTimeoutMS and MaxConcurrentPerTarget travel for the same reason:
	// a ceiling that does not reach the component sending packets is
	// decorative (ADR-024).
	ConnectTimeoutMS       uint32 `json:"connect_timeout_ms,omitempty"`
	MaxConcurrentPerTarget uint32 `json:"max_concurrent_per_target,omitempty"`

	// SafetyMode is the EFFECTIVE mode, already reduced by Core (ADR-021).
	//
	// It travels for PROVENANCE, not for enforcement. An observation made by
	// reading what a service volunteered and one made by soliciting a response
	// are different confidence levels, and the finding pipeline has to be able
	// to tell them apart — so the engine stamps this on what it emits.
	//
	// What it does NOT do is decide whether a probe may be sent. See Probes.
	SafetyMode string `json:"safety_mode,omitempty"`

	// Probes are the payloads this engine may send to solicit a response.
	//
	// ========================================================================
	// EMPTY IN SAFE MODE, and that is the enforcement — not a flag the engine
	// is trusted to honour.
	// ========================================================================
	//
	// Same shape as RateBudgetPPS: the engine cannot exceed a budget it was
	// never given, and it cannot send a probe it was never handed. An engine
	// holds no probe corpus of its own, so "safe mode" is not a branch inside
	// the engine that a bug or a rule could route around — there is simply
	// nothing to send.
	//
	// The runtime asserts the invariant on the way out (see engineHost.start):
	// a job whose safety_mode is not intrusive carries no probes, and a job
	// that somehow carries probes under a safe mode is refused rather than
	// trimmed.
	Probes []Probe `json:"probes,omitempty"`

	// BannerMatches are evaluated against what a service VOLUNTEERS on connect,
	// and travel in every mode including safe.
	//
	// Reading is not sending, so identifying SSH from the banner it announced
	// costs nothing and provokes nothing — which is why the safe/intrusive line
	// is drawn at Probes and not here. A pack that shipped no banner matches
	// would make safe mode identify nothing at all.
	BannerMatches []Match `json:"banner_matches,omitempty"`

	// Ports the fingerprint engine should examine.
	//
	// Supplied by the RUNTIME, not chosen by the engine, for the same reason
	// targets are: a port list an engine composed is a scan nobody authorised.
	// Empty takes the engine's own service-port default — which is a rescan, and
	// the honest cost of Core not yet planning a fingerprint job from discovery's
	// observations. See ADR-048.
	Ports []uint32 `json:"ports,omitempty"`

	// MaxProbesPerPort caps the fallback chain.
	//
	// Zero means the engine's own default rather than "unlimited": a corpus that
	// forgot the field must not authorise an unbounded chain, which is the same
	// reading clampCeiling takes for an absent rate.
	MaxProbesPerPort uint32 `json:"max_probes_per_port,omitempty"`

	// KindAuthorised: the runtime's answer to a KindAuthorise request.
	Target    string `json:"target,omitempty"`
	Permitted bool   `json:"permitted,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// Match is one rule for recognising a service in bytes a host returned.
//
// Content, not code: these arrive in a signed fingerprint pack (ADR-019) and the
// runtime hands over whatever survives its static safety policy. The engine
// evaluates them and constructs none.
type Match struct {
	// Pattern is a Go regexp evaluated against the response. Named capture
	// groups `version`, `product` and `info` are lifted into the observation
	// when present, which is how one rule covers every version of a service.
	Pattern string `json:"pattern"`

	// Service is the protocol — ssh, http, smtp. Always set on a match, because
	// naming the protocol is the part that is almost always knowable.
	Service string `json:"service"`

	// Product is the software, when the rule can tell. Empty is a SOFTMATCH:
	// see Soft.
	Product string `json:"product,omitempty"`

	// Ports scopes the rule, empty meaning any port.
	//
	// Needed because some greetings are genuinely ambiguous: `220 ` opens both
	// SMTP and FTP and no pattern separates them, so the generic rule for each
	// carries the ports it applies to and the port prior does the disambiguating
	// that the bytes cannot. A rule that names a product needs no scope.
	Ports []uint32 `json:"ports,omitempty"`

	// Soft marks a rule that identifies the protocol and not the product.
	//
	// ========================================================================
	// "This is HTTP, product unknown" is a correct answer, not a failed one.
	// ========================================================================
	//
	// A great deal of real software is configured not to name itself —
	// `server_tokens off` is the default advice for nginx — and a matcher with
	// no representation for "protocol known, product not" has two bad options:
	// report nothing, which loses the port's identity, or guess, which is worse.
	// A soft match ends the probe chain: continuing to spend packets after the
	// protocol is settled buys only the product name.
	Soft bool `json:"soft,omitempty"`

	// Confidence the rule carries when it fires, 0..1. A version string lifted
	// from a banner is near-certain; a response-shape match is not, and the
	// difference has to survive into the observation because ADR-014 makes
	// confidence decide how a finding is presented.
	Confidence float32 `json:"confidence"`

	// OSHint is a distribution or platform the banner suggests — an OpenSSH
	// suffix naming Ubuntu, say.
	//
	// NEVER treated as OS detection. See the observation payload: it is
	// recorded with an explicit non-authoritative flag, because ADR-014 makes
	// OS attribution decide which vendor advisory feed a host is matched
	// against, and a wrong feed at high confidence poisons the knowledge plane.
	OSHint string `json:"os_hint,omitempty"`
}

// Probe is one payload the engine may send to solicit a response.
//
// The engine does not choose these and does not carry a corpus. It sends what
// it was given, to the ports it was told, and reads a bounded reply.
type Probe struct {
	// Name identifies the probe in an observation's provenance, so a service
	// identified by soliciting it can be traced to what was sent.
	Name string `json:"name"`

	// Ports this probe applies to. Empty means every open port, which is what a
	// generic probe wants.
	Ports []uint32 `json:"ports,omitempty"`

	// Payload is sent verbatim. Bytes rather than a string because a probe for
	// a binary protocol is not text.
	Payload []byte `json:"payload"`

	// ReadBytes bounds the reply. Zero takes the engine's default; an engine
	// parses hostile input by design, and an unbounded read from a scan target
	// is a denial of service against your own fleet.
	ReadBytes uint32 `json:"read_bytes,omitempty"`

	// Matches are evaluated against this probe's response, in order, first hit
	// wins.
	Matches []Match `json:"matches,omitempty"`

	// Kind is what this probe IS. Empty means a payload probe.
	//
	// ========================================================================
	// A key exchange is not a payload, and pretending otherwise stretched a
	// bound written about bytes over a conversation (ADR-049).
	// ========================================================================
	//
	// ADR-048's policy — a payload bound, a non-inert port denylist, nothing in
	// safe mode, nothing at a fragile target — was written when every probe was
	// a byte string. Three of those four apply to any kind. The payload bound
	// applies only to a payload, so the kind has to be explicit rather than
	// inferred from which fields happen to be set.
	//
	// A kind this build does not recognise is REFUSED by the runtime's static
	// policy, not ignored: a pack from the future naming a kind we cannot bound
	// is a probe whose behaviour is unknown, and the safe reading of unknown is
	// no.
	Kind string `json:"kind,omitempty"`

	// TLS wraps the connection in a TLS handshake before Payload is sent.
	//
	// A separate flag rather than a payload, because a handshake is a
	// CONVERSATION and no fixed byte string performs one. It is also what makes
	// certificate inspection reachable at all: the engine cannot describe a
	// certificate it never negotiated.
	//
	// The handshake itself is a probe — bytes the engine sends first — so it is
	// subject to every rule an ordinary probe is: intrusive mode only, never at
	// a fragile target, never to a port on the non-inert denylist.
	TLS bool `json:"tls,omitempty"`

	// Note that TLS is a TRANSPORT MODIFIER and Kind is the exchange: an HTTPS
	// probe is a payload probe with TLS set. They are separate fields because
	// they answer different questions.
	//
	// Rarity orders the probe chain: lower is tried first. A probe naming this
	// port is tried before a generic one regardless, so this orders within
	// those groups.
	//
	// Ordering matters because the budget counts packets: a thirty-probe chain
	// against one port costs thirty times what finding the port cost, and
	// against a fragile host at 10 pps that is minutes per port.
	Rarity int `json:"rarity,omitempty"`
}

// Observation is what an engine produces. The runtime turns these into wire
// messages; the engine has no idea a wire exists (ADR-006).
type Observation struct {
	ObservationID string    `json:"observation_id"`
	TaskID        string    `json:"task_id"`
	Type          string    `json:"type"`
	Payload       []byte    `json:"payload"`
	Confidence    float32   `json:"confidence"`
	ObservedAt    time.Time `json:"observed_at"`
}

// FromEngine is a message an engine sends.
type FromEngine struct {
	Kind string `json:"kind"`

	// KindObservation.
	Observation *Observation `json:"observation,omitempty"`

	// KindAuthorise: may I touch this? The engine does not proceed until the
	// runtime answers, and a refusal is final.
	Target string `json:"target,omitempty"`

	// KindSent: packets actually sent since the last report, so the runtime can
	// reclaim unused rate allocation (ADR-027).
	Count uint32 `json:"count,omitempty"`

	// KindDone: the engine finished cleanly. Absent when it was killed, which
	// is how the runtime tells a clean end from a truncated one.
	Detail string `json:"detail,omitempty"`
}

// Writer emits one message per line.
type Writer struct {
	enc *json.Encoder
	w   io.Writer
}

func NewWriter(w io.Writer) *Writer {
	enc := json.NewEncoder(w)
	return &Writer{enc: enc, w: w}
}

// WriteTo sends a runtime-to-engine message.
func (w *Writer) WriteTo(m ToEngine) error { return w.enc.Encode(m) }

// WriteFrom sends an engine-to-runtime message.
func (w *Writer) WriteFrom(m FromEngine) error { return w.enc.Encode(m) }

// Reader reads one message per line, bounded.
type Reader struct {
	sc *bufio.Scanner
}

func NewReader(r io.Reader) *Reader {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), MaxLine)
	return &Reader{sc: sc}
}

// ReadTo reads a runtime-to-engine message. io.EOF ends the stream.
func (r *Reader) ReadTo() (ToEngine, error) {
	var m ToEngine
	err := r.next(&m)
	return m, err
}

// ReadFrom reads an engine-to-runtime message. io.EOF ends the stream.
func (r *Reader) ReadFrom() (FromEngine, error) {
	var m FromEngine
	err := r.next(&m)
	return m, err
}

func (r *Reader) next(v any) error {
	if !r.sc.Scan() {
		if err := r.sc.Err(); err != nil {
			return fmt.Errorf("enginewire: read: %w", err)
		}
		return io.EOF
	}
	if err := json.Unmarshal(r.sc.Bytes(), v); err != nil {
		return fmt.Errorf("enginewire: malformed message: %w", err)
	}
	return nil
}
