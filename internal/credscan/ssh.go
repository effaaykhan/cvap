package credscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// The one host-dependent part of the instrument: an authenticated read of a Linux
// host over SSH. Everything else in this package is pure and fixture-tested; this
// runs the two read-only commands and hands their output to the parsers.
//
// This file holds NO credential material. The credential is the runtime's
// (ADR-027/076); the command reveals it only to build cfg.Auth and zeroises it
// after. The ssh library copies key/password bytes into its own buffers on the way
// out — the ADR-038 caveat that a zeroise is one layer, not a guarantee that no copy
// survives — which is why the credential lives only for the job and never touches
// disk (ADR-020).

// HostRead is one authenticated read of a host: the installed inventory and the
// exact release, and nothing else. No impact (non-negotiable #9) — both commands
// are reads, no write, no shell, no data extraction beyond inventory.
type HostRead struct {
	Packages []Package
	Release  OSRelease
}

// SSHConfig is what one authenticated read needs. Auth is built by the command from
// the runtime-held credential; HostKeyCallback is REQUIRED — there is deliberately
// no insecure path, because presenting a credential to an unverified host is the
// credential handed to whoever answered.
type SSHConfig struct {
	Addr            string // host:port
	User            string
	Auth            ssh.AuthMethod
	HostKeyCallback ssh.HostKeyCallback
	Timeout         time.Duration
}

// osReleaseCommand reads the exact release. cat of a world-readable file — a read,
// no impact (non-negotiable #9).
const osReleaseCommand = "cat /etc/os-release"

// ReadHost dials the host, authenticates with the supplied method, runs the two
// read-only commands and parses their output. It refuses to connect without host-key
// verification. It does not construct, hold, or zeroise the credential — that is the
// command's job (ADR-027/076); this only presents the auth method it was handed.
func ReadHost(ctx context.Context, cfg SSHConfig) (HostRead, error) {
	if cfg.HostKeyCallback == nil {
		return HostRead{}, errors.New("credscan: refusing to connect without host-key verification")
	}
	if cfg.Auth == nil {
		return HostRead{}, errors.New("credscan: no auth method")
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}

	clientCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{cfg.Auth},
		HostKeyCallback: cfg.HostKeyCallback,
		Timeout:         timeout,
	}

	// Dial honouring the context: net.Dialer via a small helper so a cancelled ctx
	// stops a hung connect rather than waiting out the timeout.
	conn, err := dialContext(ctx, cfg.Addr, clientCfg)
	if err != nil {
		return HostRead{}, fmt.Errorf("credscan: connect %s: %w", cfg.Addr, err)
	}
	defer conn.Close()

	// Release first — it decides which package manager to read (dpkg vs rpm).
	osOut, err := run(ctx, conn, osReleaseCommand)
	if err != nil {
		return HostRead{}, fmt.Errorf("credscan: reading /etc/os-release: %w", err)
	}
	rel, err := ParseOsRelease(osOut)
	if err != nil {
		return HostRead{}, fmt.Errorf("credscan: %w", err)
	}

	var pkgs []Package
	if rel.IsRPMFamily() {
		out, rerr := run(ctx, conn, RpmQaCommand)
		if rerr != nil {
			return HostRead{}, fmt.Errorf("credscan: reading rpm inventory: %w", rerr)
		}
		if pkgs, err = ParseRpmQa(out); err != nil {
			return HostRead{}, fmt.Errorf("credscan: %w", err)
		}
	} else {
		out, derr := run(ctx, conn, DpkgQueryCommand)
		if derr != nil {
			return HostRead{}, fmt.Errorf("credscan: reading package inventory: %w", derr)
		}
		if pkgs, err = ParseDpkgQuery(out); err != nil {
			return HostRead{}, fmt.Errorf("credscan: %w", err)
		}
	}
	return HostRead{Packages: pkgs, Release: rel}, nil
}

// dialContext connects and completes the SSH handshake, cancellable by ctx.
func dialContext(ctx context.Context, addr string, cfg *ssh.ClientConfig) (*ssh.Client, error) {
	d := net.Dialer{Timeout: cfg.Timeout}
	tcp, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	// If the context is cancelled during the handshake, close the socket so the
	// handshake goroutine unblocks.
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = tcp.Close()
		case <-done:
		}
	}()
	c, chans, reqs, err := ssh.NewClientConn(tcp, addr, cfg)
	close(done)
	if err != nil {
		_ = tcp.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

// Output caps. This instrument authenticates INTO a host the platform assumes may
// be compromised, so the read is bounded on both size and time: a hostile in-scope
// host does not get to OOM or hang the operator process (an unbounded read from a
// scan target is a DoS on your own fleet). A real dpkg inventory is well under 8 MiB.
const (
	maxStdout = 8 << 20  // 8 MiB
	maxStderr = 64 << 10 // 64 KiB
)

// cappedBuffer refuses (does not truncate) once it would exceed cap: a truncated
// inventory is silent under-reporting, and this instrument exists to be measured
// against — a half-read must fail loudly.
type cappedBuffer struct {
	buf bytes.Buffer
	cap int
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.cap {
		return 0, fmt.Errorf("output exceeded %d bytes", w.cap)
	}
	return w.buf.Write(p)
}

// run executes one command over its own session (SSH sessions are single-command)
// and returns stdout. A non-zero exit or stderr is surfaced, not swallowed — a
// half-read inventory must fail loudly, never be measured against. Output is size-
// capped, and the session is closed when ctx is done so the timeout bounds the read
// phase (ssh.Session.Run takes no context of its own).
func run(ctx context.Context, conn *ssh.Client, cmd string) (string, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	stdout := &cappedBuffer{cap: maxStdout}
	stderr := &cappedBuffer{cap: maxStderr}
	sess.Stdout = stdout
	sess.Stderr = stderr

	done := make(chan error, 1)
	go func() { done <- sess.Run(cmd) }()
	select {
	case <-ctx.Done():
		_ = sess.Close() // unblock Run so its goroutine does not leak
		return "", ctx.Err()
	case err := <-done:
		if err != nil {
			return "", fmt.Errorf("%q: %w (stderr: %s)", cmd, err, bytes.TrimSpace(stderr.buf.Bytes()))
		}
		return stdout.buf.String(), nil
	}
}
