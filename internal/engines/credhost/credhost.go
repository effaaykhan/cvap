// Package credhost is the credentialed-host engine: it authenticates to a Linux
// target over SSH and reads its exact package inventory and release, emitting one
// `package` observation the correlator matches without revision blindness (ADR-078)
// and uses to supersede inferred findings (ADR-077/087/088).
//
// # It never holds the credential
//
// The runtime holds the SSH key and serves signing over a socket handed to this
// engine as an extra file descriptor (ADR-027/047/086). This engine authenticates
// with signatures from that agent and never sees key material — the same guarantee
// the validation instrument proved, now on the fleet path. It also holds no scope
// data: targets arrive resolved and pre-authorised, and it verifies the host key
// against the known-hosts the runtime supplies (no in-engine TOFU).
//
// It reads inventory only — two read-only commands (dpkg-query / rpm -qa, and
// /etc/os-release) via internal/credscan — no write to the target, no exploit
// (non-negotiable #9). Emits observations only, never assets or findings.
package credhost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/effaaykhan/cvap/internal/credscan"
)

// Target is one resolved, pre-authorised host. Its own type so the engine cannot
// grow a dependency on the wire types (same boundary discovery draws).
type Target struct {
	TaskID string
	Value  string
}

// Config is the job's whole allowance for this engine.
type Config struct {
	Targets    []Target
	User       string
	KnownHosts string // host-key lines the runtime supplies; verified in-memory
	Port       int
	Timeout    time.Duration
}

// Observation is what the engine emits (mirrors the discovery/fingerprint shape).
type Observation struct {
	ObservationID string
	TaskID        string
	Type          string
	Payload       []byte
	Confidence    float32
	ObservedAt    time.Time
}

// Emit reports one observation. A returning error stops the run (backpressure).
type Emit func(Observation) error

// packagePayload is the wire shape correlate.packagePayload reads — exact release
// (os-release) plus the exact installed inventory. The field tags MUST match.
type packagePayload struct {
	Address       string             `json:"address"`
	Release       string             `json:"release"`
	ReleaseSource string             `json:"release_source"`
	Family        string             `json:"family,omitempty"` // os-release ID: ground-truth family (ADR-089)
	Installed     []installedPackage `json:"installed,omitempty"`
}

type installedPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Run authenticates to each target over the runtime's signing agent and emits one
// `package` observation per target. agentConn is the runtime end of the agent socket
// (the extra FD); the key stays in the runtime.
func Run(ctx context.Context, cfg Config, agentConn net.Conn, emit Emit) error {
	if agentConn == nil {
		return errors.New("credhost: no agent socket (the runtime must pass the signing FD)")
	}
	auth := ssh.PublicKeysCallback(agent.NewClient(agentConn).Signers)
	hkcb, err := hostKeyCallback(cfg.KnownHosts)
	if err != nil {
		return fmt.Errorf("credhost: %w", err)
	}
	port := cfg.Port
	if port == 0 {
		port = 22
	}
	for _, t := range cfg.Targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, err := credscan.ReadHost(ctx, credscan.SSHConfig{
			Addr:            net.JoinHostPort(t.Value, fmt.Sprint(port)),
			User:            cfg.User,
			Auth:            auth,
			HostKeyCallback: hkcb,
			Timeout:         cfg.Timeout,
		})
		if err != nil {
			return fmt.Errorf("credhost: reading %s: %w", t.Value, err)
		}
		payload := packagePayload{
			Address:       t.Value,
			Release:       read.Release.ReleaseKey(),
			ReleaseSource: "os-release",
			Family:        read.Release.ID, // ground-truth distro family, read on the host (ADR-089)
			Installed:     make([]installedPackage, len(read.Packages)),
		}
		for i, p := range read.Packages {
			payload.Installed[i] = installedPackage{Name: p.Source, Version: p.Version}
		}
		blob, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		if err := emit(Observation{
			ObservationID: uuid.NewString(),
			TaskID:        t.TaskID,
			Type:          "package",
			Payload:       blob,
			Confidence:    1.0,
			ObservedAt:    time.Now().UTC(),
		}); err != nil {
			return err
		}
	}
	return nil
}

// hostKeyCallback builds an in-memory host-key verifier from known-hosts lines
// ("host keytype base64"). No file and no os import (engine invariant: nothing on
// disk) — the presented key is matched by marshaled bytes against the supplied keys.
func hostKeyCallback(known string) (ssh.HostKeyCallback, error) {
	var keys [][]byte
	for _, line := range strings.Split(known, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(f[1] + " " + f[2]))
		if err != nil {
			continue
		}
		keys = append(keys, pub.Marshal())
	}
	if len(keys) == 0 {
		return nil, errors.New("no usable host keys supplied; refusing to connect without verification")
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		km := key.Marshal()
		for _, k := range keys {
			if bytes.Equal(k, km) {
				return nil
			}
		}
		return errors.New("host key mismatch")
	}, nil
}
