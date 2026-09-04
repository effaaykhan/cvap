package scanpoint

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config is everything the runtime needs that is not derived from enrollment.
//
// Endpoints for dispatch, ingest and rule packs are deliberately NOT here: Core
// returns them in EnrollResponse, so moving ingest onto its own hosts is a
// Core-side change rather than a configuration push to a fleet running
// months-old builds. Only the enrollment endpoint is configured, because it is
// the one a scan point needs before it has anything.
type Config struct {
	// EnrollEndpoint is host:port of Core's enrollment listener. Server TLS
	// only — a scan point has no certificate until this call returns one.
	EnrollEndpoint string

	// CABundlePath is the trust anchor, and ADR-018's whole point: it is
	// CONFIGURATION, not an assumption baked into the binary. The same build
	// enrolls against our SaaS CA and against a customer's on-prem Core.
	CABundlePath string

	// TokenPath holds the enrollment token, read once on first run.
	//
	// A file rather than an environment variable. A token is a bearer
	// credential for a fleet identity (ADR-018), and an environment variable
	// sits in /proc/<pid>/environ for the whole life of the process, gets
	// inherited by every child — including engine processes, which must never
	// see it — and lands in any crash report that dumps the environment. A file
	// is read once, zeroised, and never inherited.
	TokenPath string

	// DataDir holds the private key, the certificate and the CA chain. Created
	// 0700 if absent. Nothing else is ever written here — see identity.go for
	// the full list of what touches disk and why.
	DataDir string

	// EngineBinaries are the engine processes this runtime may host (ADR-027).
	//
	// A LIST of paths, not a map from engine kind to path, and the difference is
	// which side is the authority. Each binary already reports what it is
	// through `-capabilities`, and Core is told the same answer at enrolment —
	// so an operator-supplied mapping would be a second statement of the same
	// fact, free to disagree with the first. A runtime that believed the
	// operator's label over the binary's own would dispatch discovery work to
	// whatever was configured under that name.
	//
	// The runtime asks each binary and refuses to start if two claim the same
	// engine kind, because "which one did that scan run on" must have an answer.
	EngineBinaries []string

	Hostname        string
	AgentVersion    string
	ProtocolVersion string
}

// Every variable below appears as a LITERAL in the os.Getenv call that reads it,
// not as a named constant. .github/scripts/check_env_example.py matches literals
// — it asserts env.example documents exactly what the code reads, in both
// directions — and a constant would make the key invisible to it and to anyone
// grepping for which code reads a setting. The small duplication buys a gate
// that cannot silently stop covering a variable.

// ConfigFromEnv reads configuration and validates it.
func ConfigFromEnv(agentVersion, protocolVersion string) (Config, error) {
	c := Config{
		EnrollEndpoint:  os.Getenv("CVAP_SP_ENROLL_ENDPOINT"),
		CABundlePath:    os.Getenv("CVAP_SP_CA_BUNDLE"),
		TokenPath:       os.Getenv("CVAP_SP_ENROLLMENT_TOKEN_FILE"),
		DataDir:         os.Getenv("CVAP_SP_DATA_DIR"),
		EngineBinaries:  splitBinaries(os.Getenv("CVAP_SP_ENGINE_BINARIES")),
		Hostname:        os.Getenv("CVAP_SP_HOSTNAME"),
		AgentVersion:    agentVersion,
		ProtocolVersion: protocolVersion,
	}
	if c.Hostname == "" {
		h, err := os.Hostname()
		if err != nil {
			// Operator display only (EnrollRequest.hostname is self-asserted
			// and authenticates nothing), so a failure here is cosmetic.
			h = "unknown"
		}
		c.Hostname = h
	}
	return c, c.validate()
}

func (c Config) validate() error {
	var missing []string
	for _, f := range []struct{ name, value string }{
		{"CVAP_SP_ENROLL_ENDPOINT", c.EnrollEndpoint},
		{"CVAP_SP_CA_BUNDLE", c.CABundlePath},
		{"CVAP_SP_DATA_DIR", c.DataDir},
		{"CVAP_SP_ENGINE_BINARIES", strings.Join(c.EngineBinaries, ",")},
	} {
		if f.value == "" {
			missing = append(missing, f.name)
		}
	}
	if len(missing) > 0 {
		// Named, at startup, rather than an empty string failing later in
		// whatever first reads it — the failure mode check_env_example.py was
		// written against.
		return fmt.Errorf("scanpoint: missing configuration: %v", missing)
	}
	if !filepath.IsAbs(c.DataDir) {
		return errors.New("scanpoint: CVAP_SP_DATA_DIR must be an absolute path")
	}
	return nil
}

// ADR-024's platform ceilings, held HERE as well as in Core.
//
// The scan point is the second enforcement site, and it was one only for scope:
// job.budget() forwarded whatever Core sent, so a Core that said
// max_rate_per_target = 100000 got 100000. ADR-024 rejected single-site
// enforcement for rate exactly as it did for targets — a scan point runs a build
// Core does not control, and Core may have a planning bug — and internal/
// scanpoint/CLAUDE.md already claimed the runtime "never allocates more in
// aggregate than the platform ceiling".
//
// ADR-024 is the authority for the numbers; these are the scan point's copy, and
// the duplication is the same deliberate duplication the scope check has. A
// policy may LOWER them and may never raise them, so the runtime takes the
// minimum of what Core sent and what it knows.
const (
	// PlatformMaxRatePPS is ADR-024's per-SCAN-POINT ceiling, and until the
	// allocator existed it was read by nothing: every job built its own bucket
	// at the per-target rate with no shared budget, so a scan point's total was
	// linear in how many jobs it happened to hold.
	PlatformMaxRatePPS = 1000

	PlatformMaxRatePerTarget       = 50
	PlatformFragileRatePPS         = 10
	PlatformMaxConcurrentPerTarget = 20
	PlatformConnectTimeoutMS       = 3000
)

// Timings. The lease and heartbeat numbers are execution-plan §5's, and Core
// holds the same values — these are the scan point's half of the same contract.
const (
	// HeartbeatInterval matches Core's 30s; Core times out at 90s.
	HeartbeatInterval = 30 * time.Second

	// LeaseRenewInterval is 20s against a 60s TTL, so two renewals may fail
	// before the lease is actually gone.
	LeaseRenewInterval = 20 * time.Second

	// LeaseSafetyMargin is how long before the stated expiry the runtime gives
	// up and self-aborts.
	//
	// Not zero, and this is the point of it: the deadline that matters is
	// CORE's, and Core is entitled to reassign the job the instant the lease
	// expires by its clock. A runtime that scanned until its own clock reached
	// the same instant would still be sending packets while a second scan point
	// started the same work. The margin covers clock skew and the round trip,
	// and it errs toward stopping early — which costs one requeue and never
	// costs duplicate execution.
	LeaseSafetyMargin = 5 * time.Second

	// EngineStopGrace is SIGTERM-to-SIGKILL. Core's CancelJob carries its own
	// grace_ms and that wins when present; this is the default for a stop Core
	// did not initiate, such as lease loss.
	EngineStopGrace = 5 * time.Second

	// ReconnectMin and ReconnectMax bound the backoff.
	//
	// Capped at 60s rather than growing without limit: a scan point that has
	// been unreachable for an hour must still reconnect within a minute of the
	// network coming back, or an operator watching a fleet recover sees a long
	// tail with no explanation. Jittered, because a Core restart disconnects
	// every scan point at once and an unjittered backoff reconnects them all in
	// the same instant.
	ReconnectMin = 1 * time.Second
	ReconnectMax = 60 * time.Second

	// CertRotateAt is when to rotate: certificates live 90 days and rotate at
	// 60 (execution-plan §5). Checked on a timer rather than by parsing the
	// certificate, because EnrollResponse.not_after_unix exists precisely so a
	// scheduling decision does not become an X.509 dependency.
	CertRotateAt   = 60 * 24 * time.Hour
	CertLifetime   = 90 * 24 * time.Hour
	RotateCheckInt = 1 * time.Hour
)

// splitBinaries parses the comma-separated engine list.
//
// Empty entries are dropped rather than becoming an empty path that fails later
// as "no such file"; a trailing comma is a typo, not a request to host nothing.
func splitBinaries(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
