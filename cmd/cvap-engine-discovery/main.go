// Command cvap-engine-discovery is the discovery engine, hosted as a separate
// process by the scan point runtime (ADR-027).
//
// A thin I/O shell around internal/engines/discovery. The engine LOGIC stays in
// that package, which is the one place in this repository granted `net` by the
// internal/enginepolicy allowlist — deliberately, in a diff a reviewer sees, with
// ADR-047 explaining why this engine may send packets and how ADR-024's ceilings
// bind it.
//
// # Why the shell is still separate from the logic
//
// The same reason it is for the no-op engine, and it matters more here. This
// binary needs os.Stdin and os.Stdout; a package that may import `os` is a
// package that could import `os/exec`. Keeping the pipes out here means the
// logic package's exception is exactly one import — `net` — rather than a
// widening that a later engine inherits for anything.
//
// SIGTERM is not handled, for the reason the no-op engine states at length: it
// would need os/signal and syscall, and syscall is the raw-socket path. The
// default disposition terminates the process, which is what the runtime asked
// for, and the kill switch works whether or not the engine cooperates.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/discovery"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

var version = "dev"

func main() {
	if err := run(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "cvap-engine-discovery: %v\n", err)
		os.Exit(1)
	}
}

func capabilities() string {
	return `[{"engine":"discovery","engine_version":"` + version +
		`","rule_format_version":"1","enabled":true}]`
}

func run() error {
	for _, a := range os.Args[1:] {
		if a == "-capabilities" || a == "--capabilities" {
			_, err := fmt.Fprintln(os.Stdout, capabilities())
			return err
		}
	}

	ctx := context.Background()
	in := enginewire.NewReader(os.Stdin)
	out := enginewire.NewWriter(os.Stdout)

	msg, err := in.ReadTo()
	if err != nil {
		return fmt.Errorf("reading the job: %w", err)
	}
	if msg.Kind != enginewire.KindJob {
		return fmt.Errorf("first message was %q, want %q", msg.Kind, enginewire.KindJob)
	}

	targets := make([]discovery.Target, 0, len(msg.Targets))
	for _, t := range msg.Targets {
		targets = append(targets, discovery.Target{
			TaskID: t.TaskID, Value: t.Value, Fragile: t.Fragile,
		})
	}

	// Probes are whatever the runtime handed over, and nothing else.
	//
	// There is no corpus in this binary or in the logic package: under a safe
	// job this slice is empty and the engine has nothing to send. That is the
	// enforcement, not the SafetyMode string, which travels only so an
	// observation can record how it was made (ADR-021).
	probes := make([]discovery.Probe, 0, len(msg.Probes))
	for _, p := range msg.Probes {
		probes = append(probes, discovery.Probe{
			Name: p.Name, Ports: p.Ports, Payload: p.Payload, ReadBytes: p.ReadBytes,
		})
	}

	cfg := discovery.Config{
		RatePPS:                float64(msg.RateBudgetPPS),
		ConnectTimeout:         time.Duration(msg.ConnectTimeoutMS) * time.Millisecond,
		MaxConcurrentPerTarget: int(msg.MaxConcurrentPerTarget),
		Ports:                  parsePorts(os.Getenv("CVAP_ENGINE_DISCOVERY_PORTS")),
		SafetyMode:             msg.SafetyMode,
		Probes:                 probes,
	}

	// Streamed a line at a time rather than reported at the end, so a SIGKILL
	// loses only what had not been written. Results are never discarded
	// (ADR-026), and a killed job's partial record is what an operator reads to
	// find out what was touched.
	emit := func(o discovery.Observation) error {
		return out.WriteFrom(enginewire.FromEngine{
			Kind:        enginewire.KindObservation,
			Observation: toObservation(o),
		})
	}

	var total uint32
	sent := func(n uint32) {
		total += n
		// Reported as the scan proceeds rather than only at the end, so the
		// runtime can reclaim unused allocation while the job is still running
		// (ADR-027). An engine that reported once at the end would hold its
		// whole slice against the budget for the life of the job.
		_ = out.WriteFrom(enginewire.FromEngine{Kind: enginewire.KindSent, Count: n})
	}

	runErr := discovery.Run(ctx, cfg, targets, emit, sent)
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	if errors.Is(runErr, context.Canceled) {
		// Cancelled. Everything produced so far has been written; exit 0
		// because a clean stop on request is not a failure. The runtime tells
		// this from a crash by the absence of the done message.
		return nil
	}

	return out.WriteFrom(enginewire.FromEngine{
		Kind: enginewire.KindDone,
		Detail: "discovery " + version + ": " + strconv.FormatUint(uint64(total), 10) +
			" packets sent",
	})
}

// parsePorts reads an operator override.
//
// Comma-separated decimal. A malformed entry is SKIPPED rather than failing the
// job: the list is a scan parameter, not a safety control, and refusing to scan
// because one entry was mistyped trades a smaller scan for no scan. Anything
// outside a port's range is not a port.
func parsePorts(v string) []uint16 {
	if v == "" {
		return nil
	}
	var out []uint16
	for _, f := range splitComma(v) {
		n, err := strconv.ParseUint(f, 10, 16)
		if err != nil || n == 0 {
			continue
		}
		out = append(out, uint16(n))
	}
	return out
}

func splitComma(v string) []string {
	var out []string
	cur := ""
	for _, r := range v {
		if r == ',' || r == ' ' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}

// toObservation translates the engine's observation onto the wire.
//
// Named and separate so translate_test.go can assert, by reflection, that no
// field is dropped. That is the RETURN path, and it is the more expensive
// direction to get wrong: a field lost on the way out costs coverage, while a
// field lost on the way back discards evidence already paid for in packets.
func toObservation(o discovery.Observation) *enginewire.Observation {
	return &enginewire.Observation{
		ObservationID: o.ObservationID,
		TaskID:        o.TaskID,
		Type:          o.Type,
		Payload:       o.Payload,
		Confidence:    o.Confidence,
		ObservedAt:    o.ObservedAt,
	}
}
