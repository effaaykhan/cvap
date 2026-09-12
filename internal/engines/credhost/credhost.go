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
	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/sshalgo"
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
	// Port is never set by any job today, so sshalgo.DefaultPort is what this
	// engine dials AND what Core scopes the observed trust root to (ADR-094).
	// Setting it without teaching dispatch to compose known_hosts for the same
	// port makes verification fail closed against the wrong service's key.
	Port    int
	Timeout time.Duration
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
		port = sshalgo.DefaultPort
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	for _, t := range cfg.Targets {
		if err := ctx.Err(); err != nil {
			return err
		}
		// A deadline on the READ, not only the connect: a target that accepts
		// the connection and stalls would otherwise hold the session, the
		// engine and the job open — and with them the credential — for as
		// long as it liked. The instrument bounds it the same way.
		readCtx, cancel := context.WithTimeout(ctx, timeout+30*time.Second)
		read, err := credscan.ReadHost(readCtx, credscan.SSHConfig{
			Addr:            net.JoinHostPort(t.Value, fmt.Sprint(port)),
			User:            cfg.User,
			Auth:            auth,
			HostKeyCallback: hkcb,
			Timeout:         timeout,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("credhost: reading %s: %w", t.Value, err)
		}
		// The composed release key (ID-major for rpm distros) is what Core pins;
		// bound it here as the engine's site of the ADR-095 grammar, so a host
		// whose fields pass individually but compose past the bound is refused
		// at the read rather than silently dropped at Core.
		if rel := read.Release.ReleaseKey(); !domain.ReleaseTokenValid(rel) || !domain.ReleaseTokenValid(read.Release.ID) {
			return fmt.Errorf("credhost: reading %s: os-release names a release outside the attribution grammar", t.Value)
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

// hostTrust is what one line of trust material says about one host: the keys
// (marshaled public-key bytes) and SHA256 fingerprints it may present.
type hostTrust struct {
	keys   [][]byte
	prints map[string]bool
}

// hostKeyCallback builds an in-memory host-key verifier from the trust material the
// runtime supplies. No file and no os import (engine invariant: nothing on disk).
//
// Two shapes of key field are accepted, because CVAP has two sources of a host's key:
//   - Full known-hosts lines ("host keytype base64") — an operator-pinned trust root
//     on the credential profile. Matched by marshaled public-key bytes.
//   - SHA256 fingerprints ("host SHA256:...") — what discovery already captured for
//     the host (asset_identity_keys). A fingerprint cannot be turned back into a key,
//     so it is matched by computing the presented key's own SHA256 fingerprint. This
//     is a standard, secure SSH trust mechanism, and it lets the fleet path verify
//     against exactly what CVAP observed rather than requiring a re-capture.
//
// EVERY line is bound to the host(s) in its first field, and the callback checks
// the key against the trust for the host it actually dialled. The first version
// pooled every key in the job's material and accepted any of them for any target,
// so the key observed for one host verified a connection to another — with 32
// targets per job that was a 32-key any-of set, and with a fleet-wide operator pin
// it was the fleet (scan-safety audit, ADR-091). A line with no host field binds to
// nothing and is ignored; hashed (|1|...) hosts cannot be matched and are ignored.
func hostKeyCallback(known string) (ssh.HostKeyCallback, error) {
	byHost := map[string]*hostTrust{}
	usable := 0
	for _, line := range strings.Split(known, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "SHA256:") || strings.HasPrefix(f[0], "|") {
			continue // no host to bind to
		}
		var keyBytes []byte
		var print string
		switch {
		case strings.HasPrefix(f[1], "SHA256:"):
			print = f[1]
		case len(f) >= 3:
			pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(f[1] + " " + f[2]))
			if err != nil {
				continue
			}
			keyBytes = pub.Marshal()
		default:
			continue
		}
		for _, h := range strings.Split(f[0], ",") {
			h = normaliseKnownHost(h)
			if h == "" {
				continue
			}
			t := byHost[h]
			if t == nil {
				t = &hostTrust{prints: map[string]bool{}}
				byHost[h] = t
			}
			if print != "" {
				t.prints[print] = true
			} else {
				t.keys = append(t.keys, keyBytes)
			}
			usable++
		}
	}
	if usable == 0 {
		return nil, errors.New("no usable host keys supplied; refusing to connect without verification")
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		// hostname is the address the engine dialled (host:port); the trust is
		// looked up under the host alone and under host:port, nothing wider.
		t := byHost[normaliseKnownHost(hostname)]
		if t == nil {
			return fmt.Errorf("no trust material for host %q", hostname)
		}
		if t.prints[ssh.FingerprintSHA256(key)] {
			return nil
		}
		km := key.Marshal()
		for _, k := range t.keys {
			if bytes.Equal(k, km) {
				return nil
			}
		}
		return errors.New("host key mismatch")
	}, nil
}

// normaliseKnownHost reduces the known_hosts host-field forms to one string:
// "host", "[host]:port" and "host:22" (the default port is the bare host).
func normaliseKnownHost(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(h, "[") {
		if i := strings.LastIndex(h, "]:"); i > 0 {
			host, port := h[1:i], h[i+2:]
			if port == "22" {
				return host
			}
			return host + ":" + port
		}
	}
	if host, port, err := net.SplitHostPort(h); err == nil {
		if port == "22" {
			return host
		}
		return host + ":" + port
	}
	return h
}
