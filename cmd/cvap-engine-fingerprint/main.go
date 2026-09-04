// Command cvap-engine-fingerprint is the service identification engine, hosted
// as a separate process by the scan point runtime (ADR-027).
//
// A thin I/O shell around internal/engines/fingerprint. The engine LOGIC stays
// in that package, which is the one granted `net` and the four crypto imports by
// the internal/enginepolicy allowlist — deliberately, in a diff a reviewer sees,
// with ADR-048 explaining why this engine may speak TLS and what bounds it.
//
// # Why the shell is still separate from the logic
//
// This binary needs os.Stdin and os.Stdout; a package that may import `os` is a
// package that could import `os/exec`. Keeping the pipes out here holds the
// logic package's exception to what it actually needs.
//
// SIGTERM is not handled, for the reason the other engines state: it would need
// os/signal and syscall, and syscall is the raw-socket path. The default
// disposition terminates the process, which is what the runtime asked for.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/fingerprint"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

var version = "dev"

func main() {
	if err := run(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintf(os.Stderr, "cvap-engine-fingerprint: %v\n", err)
		os.Exit(1)
	}
}

func capabilities() string {
	return `[{"engine":"fingerprint","engine_version":"` + version +
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

	units := make([]fingerprint.Target, 0, len(msg.Targets))
	for _, t := range msg.Targets {
		units = append(units, fingerprint.Target{
			TaskID: t.TaskID, Value: t.Value, Fragile: t.Fragile,
		})
	}

	// Probes are whatever the runtime handed over, and nothing else.
	//
	// There is no corpus in this binary or in the logic package: under a safe
	// job this slice is empty and the engine has nothing to send. That is the
	// enforcement, not the SafetyMode string, which travels only so an
	// observation can record how it was made (ADR-021).
	probes := make([]fingerprint.Probe, 0, len(msg.Probes))
	for _, p := range msg.Probes {
		probes = append(probes, fingerprint.Probe{
			Name:      p.Name,
			Ports:     toPorts(p.Ports),
			Payload:   p.Payload,
			ReadBytes: p.ReadBytes,
			TLS:       p.TLS,
			Rarity:    p.Rarity,
			Matches:   toMatches(p.Matches),
		})
	}

	cfg := fingerprint.Config{
		RatePPS:                float64(msg.RateBudgetPPS),
		ConnectTimeout:         time.Duration(msg.ConnectTimeoutMS) * time.Millisecond,
		MaxConcurrentPerTarget: int(msg.MaxConcurrentPerTarget),
		Ports:                  toPorts(msg.Ports),
		SafetyMode:             msg.SafetyMode,
		Probes:                 probes,

		// Banner rules travel in EVERY mode, including safe. Reading is not
		// sending: the bytes have already arrived by the time a rule looks at
		// them, so withholding these would cost identification and buy nothing.
		BannerMatches:    toMatches(msg.BannerMatches),
		MaxProbesPerPort: int(msg.MaxProbesPerPort),
	}

	emit := func(o fingerprint.Observation) error {
		return out.WriteFrom(enginewire.FromEngine{
			Kind: enginewire.KindObservation,
			Observation: &enginewire.Observation{
				ObservationID: o.ObservationID,
				TaskID:        o.TaskID,
				Type:          o.Type,
				Payload:       o.Payload,
				Confidence:    o.Confidence,
				ObservedAt:    o.ObservedAt,
			},
		})
	}

	var total uint32
	sent := func(n uint32) {
		total += n
		// Reported as the scan proceeds rather than only at the end, so the
		// runtime can reclaim unused allocation while the job is still running
		// (ADR-027).
		_ = out.WriteFrom(enginewire.FromEngine{Kind: enginewire.KindSent, Count: n})
	}

	runErr := fingerprint.Run(ctx, cfg, units, emit, sent)
	if runErr != nil && !errors.Is(runErr, context.Canceled) {
		return runErr
	}
	if errors.Is(runErr, context.Canceled) {
		// Cancelled. Everything produced so far has been written; exit 0 because
		// a clean stop on request is not a failure. The runtime tells this from
		// a crash by the absence of the done message.
		return nil
	}

	return out.WriteFrom(enginewire.FromEngine{
		Kind: enginewire.KindDone,
		Detail: "fingerprint " + version + ": " + strconv.FormatUint(uint64(total), 10) +
			" packets sent",
	})
}

// toPorts narrows the wire's uint32 ports to the uint16 a port actually is.
//
// Anything outside the range is DROPPED rather than truncated. Truncating would
// turn 65536 into 0 and 65590 into 54, which is a payload sent somewhere nobody
// asked for — the one failure mode a scanner must not have.
func toPorts(in []uint32) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, p := range in {
		if p == 0 || p > 65535 {
			continue
		}
		out = append(out, uint16(p))
	}
	return out
}

func toMatches(in []enginewire.Match) []fingerprint.Match {
	out := make([]fingerprint.Match, 0, len(in))
	for _, m := range in {
		out = append(out, fingerprint.Match{
			Pattern:    m.Pattern,
			Service:    m.Service,
			Product:    m.Product,
			Soft:       m.Soft,
			Confidence: m.Confidence,
			OSHint:     m.OSHint,
			Ports:      toPorts(m.Ports),
		})
	}
	return out
}
