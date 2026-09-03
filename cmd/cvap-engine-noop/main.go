// Command cvap-engine-noop is the no-op engine, hosted as a separate process by
// the scan point runtime (ADR-027).
//
// A thin I/O shell around internal/engines/noop and nothing else. The engine
// LOGIC stays in that package, which imports context, encoding/json, time and
// uuid — no net, no os/exec, no syscall — and internal/enginepolicy walks its
// import graph and fails the build on any of them. Putting the pipes here rather
// than there is what keeps that guard meaningful: this binary needs os.Stdin,
// and a package that may import os is a package that could import net.
//
// # Why a process at all
//
// ADR-027 decides that engines ARE separate processes, and the reasons only
// become real when one exists: the kill switch is SIGTERM then SIGKILL rather
// than a context cancellation an engine may ignore; a crashed engine takes down
// no part of the runtime and leaks no credential because it never held one; and
// the rate budget is allocated across processes rather than shared through
// mutable state.
//
// # perTargetDelay
//
// Set only by `-ldflags -X main.perTargetDelay=...` in the end-to-end test,
// which needs a job that lasts long enough to sever its lease mid-flight.
// Deliberately not an environment variable: a knob that slows scanning must not
// be reachable in a production build, and a build flag cannot be set by anything
// running the shipped binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/noop"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

var (
	version = "dev"

	// perTargetDelay is a duration string, empty in every normal build.
	perTargetDelay = ""
)

func main() {
	if err := run(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "cvap-engine-noop: %v\n", err)
		os.Exit(1)
	}
}

// capabilitiesJSON is what `cvap-engine-noop -capabilities` prints.
//
// ADR-027: engines declare capabilities and versions, and the scan point reports
// them on connect so Core never dispatches work an engine cannot execute. The
// runtime asks the binary rather than being configured with the answer, because
// engines are replaced independently of the runtime — a configured answer would
// be right until the day someone upgraded one of them.
//
// os.Args rather than the flag package, to keep `flag` off the engine import
// exception list for one string comparison.
func capabilities() string {
	return `[{"engine":"` + noop.Engine{}.Name() +
		`","engine_version":"` + noop.Engine{}.Version() +
		`","rule_format_version":"1","enabled":true}]`
}

func run() error {
	for _, a := range os.Args[1:] {
		if a == "-capabilities" || a == "--capabilities" {
			_, err := fmt.Fprintln(os.Stdout, capabilities())
			return err
		}
	}

	// SIGTERM is NOT handled, and that is a decision rather than an omission.
	//
	// Handling it would need os/signal and syscall, and the engine import guard
	// forbids both for a reason that still applies to this binary: syscall is
	// the raw-socket path, and an exception granted for signal handling is one a
	// later engine inherits for anything. The default disposition terminates the
	// process, which is exactly what the runtime asked for.
	//
	// Nothing is lost by it. Observations are streamed a line at a time, so
	// SIGTERM discards at most the one in flight, and ADR-027 calls clean
	// shutdown "the engine's chance to finish a partial observation, not a
	// veto" — a courtesy, not the mechanism. The mechanism is SIGTERM then
	// SIGKILL, and it works whether or not the engine cooperates, which is the
	// property that makes the kill switch a control.
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

	delay, err := parseDelay()
	if err != nil {
		return err
	}

	// Observations are streamed one line at a time rather than reported at the
	// end, so a SIGKILL loses only what had not been written. Results are never
	// discarded (ADR-026), and a killed job's partial record is what an operator
	// reads to find out what was touched.
	engine := noop.Engine{}
	for _, t := range msg.Targets {
		if ctx.Err() != nil {
			// Cancelled. Everything produced so far has already been written,
			// so there is nothing to flush; exit 0 because a clean stop on
			// request is not a failure. The runtime distinguishes this from a
			// crash by the absence of the done message.
			return nil
		}
		if delay > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(delay):
			}
		}

		obs, err := engine.Run(ctx, []noop.Target{{
			TaskID:  mustParseTask(t.TaskID),
			Value:   t.Value,
			Fragile: t.Fragile,
		}})
		for _, o := range obs {
			if werr := out.WriteFrom(enginewire.FromEngine{
				Kind: enginewire.KindObservation,
				Observation: &enginewire.Observation{
					ObservationID: o.ObservationID.String(),
					TaskID:        o.TaskID.String(),
					Type:          o.Type,
					Payload:       o.Payload,
					Confidence:    o.Confidence,
					ObservedAt:    o.ObservedAt,
				},
			}); werr != nil {
				return werr
			}
		}
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}

	// Nothing was sent, and saying so is not a formality: the runtime reclaims
	// unused rate allocation from this number, and an engine that reported
	// nothing would have its slice held against the budget for the life of the
	// job (ADR-027).
	if err := out.WriteFrom(enginewire.FromEngine{Kind: enginewire.KindSent, Count: 0}); err != nil {
		return err
	}
	return out.WriteFrom(enginewire.FromEngine{
		Kind:   enginewire.KindDone,
		Detail: "noop " + version + ": no packet was sent",
	})
}

func parseDelay() (time.Duration, error) {
	if perTargetDelay == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(perTargetDelay)
	if err != nil {
		return 0, fmt.Errorf("perTargetDelay %q: %w", perTargetDelay, err)
	}
	return d, nil
}
