// Command runtimedrive runs one job through the REAL scan-point send-path scope
// check and the real engine binary, for the §6.3 form of make safety.
//
// ============================================================================
// It exercises engineHost.authorise — ADR-024's second enforcement site — which
// the narrow safety gate never instantiates because it drives the engine
// directly.
// ============================================================================
//
// Usage: runtimedrive <engine-binary-path>  <job.json on stdin
//
// It prints a scanpoint.SafetyResult as JSON on stdout for diagnostics. The
// gate's actual assertion is the packet capture around this process: authorised
// targets receive packets, excluded and out-of-scope ones receive none. The
// binary spawns the engine exactly as the runtime does, so the capture sees the
// real engine's egress after the real scope check has run.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/effaaykhan/cvap/internal/scanpoint"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "runtimedrive:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: runtimedrive <engine-binary-path>  <job.json on stdin")
	}
	binary := os.Args[1]

	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("reading job: %w", err)
	}
	var j scanpoint.SafetyJob
	if err := json.Unmarshal(raw, &j); err != nil {
		return fmt.Errorf("job is not valid JSON: %w", err)
	}

	// Engine stderr already goes to the process's stderr through the host; keep
	// our own logging there too so stdout carries only the JSON result.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	res, err := scanpoint.SafetyDrive(context.Background(), log, binary, j)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(res)
}
