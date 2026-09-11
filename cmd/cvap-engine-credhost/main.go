// Command cvap-engine-credhost is the credentialed-host scan engine (ADR-086/087/088).
// A thin I/O shell: it reads the job on stdin, receives the runtime's signing-agent
// socket as file descriptor 3 (never key material), and streams `package`
// observations on stdout. The engine logic — the SSH read and inventory parse — is in
// internal/engines/credhost so only that package carries the net/ssh exception.
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/effaaykhan/cvap/internal/engines/credhost"
	"github.com/effaaykhan/cvap/internal/enginewire"
)

// agentFD is the fixed extra file descriptor the runtime passes the agent socket on
// (fd 0/1/2 are stdio; the first ExtraFiles entry is fd 3).
const agentFD = 3

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "cvap-engine-credhost:", err)
		os.Exit(1)
	}
}

// capabilities is what the runtime's EngineSet reads to learn this binary hosts the
// "host" engine. The shape mirrors the other engines' — a JSON array of Capability.
func capabilities() string {
	return `[{"engine":"host","engine_version":"` + version +
		`","rule_format_version":"1","enabled":true}]`
}

func run() error {
	for _, a := range os.Args[1:] {
		if a == "-capabilities" || a == "--capabilities" {
			_, err := fmt.Fprintln(os.Stdout, capabilities())
			return err
		}
	}

	in := enginewire.NewReader(os.Stdin)
	out := enginewire.NewWriter(os.Stdout)

	msg, err := in.ReadTo()
	if err != nil {
		return fmt.Errorf("reading job: %w", err)
	}
	if msg.Kind != enginewire.KindJob {
		return fmt.Errorf("first message is %q, want a job", msg.Kind)
	}

	targets := make([]credhost.Target, 0, len(msg.Targets))
	for _, t := range msg.Targets {
		targets = append(targets, credhost.Target{TaskID: t.TaskID, Value: t.Value})
	}

	// The runtime's signing agent arrives as fd 3 — signatures, never the key.
	agentFile := os.NewFile(uintptr(agentFD), "credagent")
	if agentFile == nil {
		return fmt.Errorf("no agent socket on fd %d", agentFD)
	}
	agentConn, err := net.FileConn(agentFile)
	_ = agentFile.Close()
	if err != nil {
		return fmt.Errorf("agent socket: %w", err)
	}
	defer agentConn.Close()

	timeout := 30 * time.Second
	if msg.ConnectTimeoutMS > 0 {
		timeout = time.Duration(msg.ConnectTimeoutMS) * time.Millisecond
	}
	cfg := credhost.Config{
		Targets:    targets,
		User:       msg.CredUser,
		KnownHosts: msg.KnownHosts,
		Timeout:    timeout,
	}

	emit := func(o credhost.Observation) error {
		return out.WriteFrom(enginewire.FromEngine{
			Kind: enginewire.KindObservation,
			Observation: &enginewire.Observation{
				ObservationID: o.ObservationID, TaskID: o.TaskID, Type: o.Type,
				Payload: o.Payload, Confidence: o.Confidence, ObservedAt: o.ObservedAt,
			},
		})
	}

	ctx := context.Background()
	if err := credhost.Run(ctx, cfg, agentConn, emit); err != nil {
		return err
	}
	return out.WriteFrom(enginewire.FromEngine{Kind: enginewire.KindDone, Detail: "credentialed inventory read"})
}
