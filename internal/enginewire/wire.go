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

	// KindAuthorised: the runtime's answer to a KindAuthorise request.
	Target    string `json:"target,omitempty"`
	Permitted bool   `json:"permitted,omitempty"`
	Reason    string `json:"reason,omitempty"`
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
