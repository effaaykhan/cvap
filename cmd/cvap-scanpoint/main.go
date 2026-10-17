// Command cvap-scanpoint runs the CVAP Scan Point runtime.
//
// Outbound only: it dials Core and never listens (ADR-005). On first run it
// exchanges an enrollment token for a client certificate, and from then on it
// holds a dispatch stream, hosts engine processes, and submits results to
// Ingest over a separate connection.
//
// What it writes to disk is enumerated in internal/scanpoint/identity.go and is
// only ever the private key, the certificate, the CA chain and an identity file.
// Credential material from a CredentialGrant is memory-only and zeroised on
// completion, lease loss or abort (ADR-020).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/logging"
	"github.com/effaaykhan/cvap/internal/scanpoint"
)

var (
	version         = "dev"
	protocolVersion = "v1"
)

func main() {
	// First, before the runtime has done anything else on our behalf: a process
	// that can never gain a privilege (ADR-110 P3). This may re-exec the binary
	// once; the re-exec'd process returns here at once. See EnsureNoNewPrivs.
	if err := scanpoint.EnsureNoNewPrivs(); err != nil {
		fmt.Fprintln(os.Stderr, "cvap-scanpoint: refusing to start (ADR-110 P3):", err)
		os.Exit(1)
	}
	log := logging.New(os.Stdout, logging.Options{Level: levelFromEnv()})

	if err := run(log); err != nil {
		log.Error("scan point stopped", slog.Any("error", err))
		os.Exit(1)
	}
}

func levelFromEnv() slog.Level {
	switch os.Getenv("LOG_LEVEL") {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func run(log *slog.Logger) error {
	// SIGTERM stops the runtime. Jobs in flight self-abort through the same
	// path lease loss uses — zeroise, mark incomplete, submit — because a scan
	// point shutting down has exactly the same obligation as one that lost its
	// lease: results are never discarded (ADR-026).
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	cfg, err := scanpoint.ConfigFromEnv(version, protocolVersion)
	if err != nil {
		return err
	}
	// Before anything touches the network: the kernel packet ceiling (ADR-110)
	// holds only for a process with no capability and no way to gain one. The
	// deployment is told to run it that way; this checks that it was. (The "no
	// way to gain one" half, no_new_privs, was made true in main before the
	// runtime did anything else.)
	if err := scanpoint.CheckUnprivileged("/proc/self/status"); err != nil {
		return fmt.Errorf("cvap-scanpoint: refusing to start (ADR-110 P3): %w", err)
	}
	log.Info("scan point runtime starting",
		slog.String("version", version),
		slog.String("protocol_version", protocolVersion),
		slog.String("data_dir", cfg.DataDir))

	id, err := identity(ctx, log, cfg)
	if err != nil {
		return err
	}

	// Core is never a scan target (ADR-110): the kernel packet ceiling exempts
	// traffic to Core, so a scan of it would run outside the ceiling. The set is
	// what this scan point enrolled against, resolved now; a scan point that
	// cannot build it refuses to start rather than run with a refusal that
	// matches nothing.
	core, err := scanpoint.CoreEndpoints(ctx, cfg, id)
	if err != nil {
		return fmt.Errorf("cvap-scanpoint: Core endpoints (ADR-110): %w", err)
	}
	log.Info("Core endpoints are never scan targets", slog.Any("addresses", core.Addrs()),
		slog.String("network_policy_exempts", cfg.PolicyCoreEndpoints))

	mtls, err := scanpoint.MutualTLS(cfg.DataDir, cfg.CABundlePath)
	if err != nil {
		return err
	}

	// Two connections, not one. ADR-005 separates dispatch from ingest so that
	// a multi-megabyte result upload cannot head-of-line block job assignment,
	// and Core returns their endpoints separately so they can move apart.
	dispatchConn, err := scanpoint.Dial(ctx, id.DispatchAddr, mtls)
	if err != nil {
		return err
	}
	defer func() { _ = dispatchConn.Close() }()

	submitter := scanpoint.NewSubmitter(log, func(ctx context.Context) (scanpointv1.IngestClient, func() error, error) {
		cc, err := scanpoint.Dial(ctx, id.IngestAddr, mtls)
		if err != nil {
			return nil, nil, err
		}
		return scanpointv1.NewIngestClient(cc), cc.Close, nil
	})
	go submitter.Run(ctx)

	engines, err := scanpoint.NewEngineSet(ctx, cfg.EngineBinaries)
	if err != nil {
		return err
	}
	for _, c := range engines.Capabilities() {
		log.Info("engine capability declared",
			slog.String("engine", c.GetEngine()),
			slog.String("engine_version", c.GetEngineVersion()))
	}

	rt := scanpoint.NewRuntime(cfg, log, id, engines, submitter, core)
	go rotateLoop(ctx, log, cfg, id)

	client := scanpointv1.NewDispatchClient(dispatchConn)
	rt.Run(ctx, func(ctx context.Context) (scanpointv1.Dispatch_ConnectClient, func() error, error) {
		stream, err := client.Connect(ctx)
		if err != nil {
			return nil, nil, err
		}
		return stream, func() error { return nil }, nil
	})

	// rt.Run has already self-aborted every job in flight: stopped the engines,
	// zeroised, and enqueued what they gathered. What is left is to let the
	// submitter get those to Core.
	//
	// The submitter runs on ctx, which is already cancelled here, so it is
	// given a fresh one — otherwise the shutdown path would enqueue results and
	// then exit before a single byte left the process, which is the same
	// discard ADR-026 forbids, wearing a different hat.
	drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	go submitter.Run(drainCtx)

	deadline := time.After(10 * time.Second)
	for {
		if n, _ := submitter.Buffered(); n == 0 {
			log.Info("result buffer drained; exiting")
			return nil
		}
		select {
		case <-deadline:
			n, bytes := submitter.Buffered()
			// Named rather than silent. Unsubmitted results are re-derivable
			// from a re-run — which is what reassign_safe governs — but an
			// operator should know this scan point exited holding some.
			log.Error("exiting with results still buffered",
				slog.Int("submissions", n), slog.Uint64("bytes", bytes))
			return nil
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// identity loads a previous enrollment or performs a first one.
func identity(ctx context.Context, log *slog.Logger, cfg scanpoint.Config) (*scanpoint.Identity, error) {
	id, err := scanpoint.LoadIdentity(cfg.DataDir)
	if err == nil {
		log.Info("loaded identity",
			slog.String("scan_point_id", id.ScanPointID),
			slog.Time("certificate_expires", id.NotAfter))
		return id, nil
	}
	if !isNoIdentity(err) {
		return nil, err
	}

	enrollTLS, err := scanpoint.EnrollTLS(cfg.CABundlePath)
	if err != nil {
		return nil, err
	}
	cc, err := scanpoint.Dial(ctx, cfg.EnrollEndpoint, enrollTLS)
	if err != nil {
		return nil, err
	}
	defer func() { _ = cc.Close() }()

	return scanpoint.Enroll(ctx, log, cfg, scanpointv1.NewEnrollmentClient(cc))
}

func isNoIdentity(err error) bool { return errors.Is(err, scanpoint.ErrNoIdentity) }

// rotateLoop replaces the certificate at 60 days of a 90-day lifetime.
//
// On a timer against not_after_unix rather than by parsing the certificate:
// EnrollResponse carries that field so a scheduling decision does not become an
// X.509 dependency (enrollment.proto). Rotation runs over the mTLS listener,
// authenticated by the certificate being replaced.
func rotateLoop(ctx context.Context, log *slog.Logger, cfg scanpoint.Config, id *scanpoint.Identity) {
	t := time.NewTicker(scanpoint.RotateCheckInt)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if !scanpoint.ShouldRotate(id.NotAfter, time.Now()) {
			continue
		}
		mtls, err := scanpoint.MutualTLS(cfg.DataDir, cfg.CABundlePath)
		if err != nil {
			log.Error("rotation: client certificate unavailable", slog.Any("error", err))
			continue
		}
		cc, err := scanpoint.Dial(ctx, id.DispatchAddr, mtls)
		if err != nil {
			log.Error("rotation: could not reach Core", slog.Any("error", err))
			continue
		}
		next, err := scanpoint.Rotate(ctx, log, cfg, id, scanpointv1.NewEnrollmentClient(cc))
		_ = cc.Close()
		if err != nil {
			// Not fatal, and retried on the next tick. There are thirty days
			// between the rotation point and expiry precisely so a transient
			// failure is not an outage.
			log.Error("rotation failed; will retry", slog.Any("error", err))
			continue
		}
		*id = *next
	}
}
