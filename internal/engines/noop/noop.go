// Package noop is an engine that emits synthetic observations and touches
// nothing.
//
// It exists to prove the dispatch/ingest loop end to end — a scan point
// enrolls, receives a job, produces observations, submits them — without any
// code that could put a packet on a wire. Discovery is a later session.
//
// # It cannot scan, structurally
//
// This package imports context, time and uuid. No net, no net/http, no os/exec,
// no syscall. That is not a convention: internal/engines/import_policy_test.go
// walks the import graph of every package under internal/engines and fails on
// any of them, with an allowlist that is empty today.
//
// The distinction matters because week 8's `make safety` asserts that no packet
// leaves scope. This asserts something different and cheaper: that there is no
// code here that could send one.
//
// # What an engine is and is not
//
// Engines emit observations only (ADR-006). They hold no scope data — no
// allowlist, no exclusions, no CIDR arithmetic — because scope enforcement lives
// at exactly two sites, Core at planning and the scan point runtime on the send
// path, and never in an engine (ADR-024, ADR-027). An engine receives resolved,
// pre-authorised targets and constructs none.
//
// They never receive raw credential material either: the runtime establishes the
// authenticated session and passes a handle (ADR-020). This engine takes no
// credentials at all, which is the easiest way to hold that property.
package noop

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Target is one resolved, pre-authorised unit of work.
//
// The engine does not decide whether it may touch this — the runtime already
// did. There is deliberately no field here for an allowlist or an exclusion set:
// an engine that could evaluate scope would be a third enforcement site, and
// ADR-024's "both paths" assertion depends on there being exactly two.
type Target struct {
	TaskID uuid.UUID
	Value  string

	// Fragile caps rate regardless of policy (ADR-024). Carried so the runtime
	// can allocate a smaller slice; the engine does not read it as permission.
	Fragile bool
}

// Observation is what an engine produces. It is the runtime's job to turn these
// into wire messages; the engine has no idea a wire exists.
type Observation struct {
	ObservationID uuid.UUID
	TaskID        uuid.UUID
	Type          string
	Payload       []byte
	Confidence    float32
	ObservedAt    time.Time
}

// Engine is the no-op engine.
type Engine struct{}

// Name is what the scan point declares as a capability. It is a ceiling, never a
// grant: declaring it can only narrow what Core dispatches.
func (Engine) Name() string { return "discovery" }

// Version is reported alongside the capability so Core never dispatches a rule
// format this build cannot execute (ADR-022).
func (Engine) Version() string { return "0.0.0-noop" }

// Run produces one observation per target and touches nothing.
//
// The payload states plainly that nothing was probed. A synthetic observation
// that looked like a real one would eventually be believed by a correlation
// pass, and an inventory built from fabricated evidence is worse than an empty
// one.
func (Engine) Run(ctx context.Context, targets []Target) ([]Observation, error) {
	out := make([]Observation, 0, len(targets))
	for _, t := range targets {
		if err := ctx.Err(); err != nil {
			// Honour cancellation within seconds so the kill switch works
			// (ADR-024, ADR-027). Returning what was produced so far is
			// deliberate: results are never discarded (ADR-026).
			return out, err
		}

		payload, err := json.Marshal(map[string]any{
			"engine":  "noop",
			"probed":  false,
			"target":  t.Value,
			"fragile": t.Fragile,
			"note":    "synthetic observation; no packet was sent",
		})
		if err != nil {
			return out, err
		}

		out = append(out, Observation{
			ObservationID: uuid.New(),
			TaskID:        t.TaskID,
			Type:          "host",
			Payload:       payload,
			// Low, and deliberately. Confidence is first-class (cvap-invariants)
			// and a synthetic observation has earned none of it.
			Confidence: 0.0,
			ObservedAt: time.Now().UTC(),
		})
	}
	return out, nil
}
