package scanpoint

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
)

// trustAnchor loads the configured CA bundle.
//
// ADR-018: the trust anchor is CONFIGURATION, not an assumption baked into the
// binary. The same build enrols against our SaaS CA and against a customer's
// on-prem Core, and there is no fallback to the system pool — a scan point that
// silently trusted a public CA would accept any certificate that CA had issued
// for the endpoint's name, which is the whole property the private anchor buys.
func trustAnchor(path string) (*x509.CertPool, error) {
	// #nosec G304 -- the path is operator configuration (CVAP_SP_CA_BUNDLE) and
	// is the ADR-018 trust anchor, which is deliberately not baked into the
	// binary. It arrives from the environment before any network connection
	// exists, and there is no root to scope it to.
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scanpoint: read CA bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("scanpoint: CA bundle contains no certificates")
	}
	return pool, nil
}

// EnrollTLS is server-authenticated TLS with no client certificate.
//
// Enrollment is the one call a scan point makes before it has an identity, so it
// cannot present one. Core serves it on a separate listener for exactly this
// reason — the dispatch and ingest listener requires and verifies a client
// certificate, and mixing the two would mean relaxing that requirement for every
// service on the port.
func EnrollTLS(caPath string) (*tls.Config, error) {
	pool, err := trustAnchor(caPath)
	if err != nil {
		return nil, err
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

// MutualTLS is the posture for dispatch, ingest and rotation.
//
// TLS 1.3 minimum (architecture-v2 §15). The client certificate is the scan
// point's identity everywhere in Core: it resolves the tenant, it is the audit
// log's actor, and revoking it is what makes revocation immediate (ADR-018).
func MutualTLS(dataDir, caPath string) (*tls.Config, error) {
	pool, err := trustAnchor(caPath)
	if err != nil {
		return nil, err
	}
	// Load once here so a broken pair fails at startup with a clear message
	// rather than at the first handshake.
	if _, err := loadKeyPair(dataDir); err != nil {
		return nil, err
	}

	return &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS13,

		// Read from disk on EVERY handshake instead of capturing a certificate.
		//
		// Rotation writes a new key and certificate at day 60 of 90 and the
		// runtime kept presenting the superseded one, because the tls.Config
		// was built once at startup and captured by the dispatch connection and
		// the ingest dialler. Core's ResolveScanPointTenant stops resolving the
		// old fingerprint, so dispatch and ingest fail until somebody restarts
		// the process — a self-inflicted outage on a timer, on every scan point
		// in the fleet, thirty days before anything expires.
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return loadKeyPair(dataDir)
		},
	}, nil
}

// loadKeyPair reads the current identity, falling back to the previous one.
//
// SaveIdentity renames the key and the certificate separately, so a crash
// between the two renames leaves a key that does not match its certificate. At
// first enrolment the identity file gates that — LoadIdentity fails and the scan
// point re-enrols cleanly. At ROTATION the identity file already exists, so it
// gates nothing: the scan point believes it is enrolled, cannot build a TLS
// config, and ADR-018 has no re-enrolment path. It is dead until an operator
// deletes the data directory and issues a new token.
//
// The previous pair is kept for exactly this window. It is still valid —
// rotation happens thirty days before expiry — so falling back costs nothing and
// turns a bricked scan point into one that rotates again on the next tick.
func loadKeyPair(dataDir string) (*tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(dataDir, certFile), filepath.Join(dataDir, keyFile))
	if err == nil {
		return &cert, nil
	}

	prev, prevErr := tls.LoadX509KeyPair(
		filepath.Join(dataDir, certFile+prevSuffix), filepath.Join(dataDir, keyFile+prevSuffix))
	if prevErr == nil {
		return &prev, nil
	}
	return nil, fmt.Errorf("scanpoint: load client certificate: %w", err)
}

// Dial opens a gRPC connection with the given TLS configuration.
//
// Keepalive is set because a scan point sits behind customer NAT and stateful
// firewalls that drop idle flows silently. Without it a dispatch stream can be
// dead for an hour with neither end noticing, and the first symptom is a lease
// expiring on a job that was still running.
func Dial(ctx context.Context, addr string, tlsCfg *tls.Config) (*grpc.ClientConn, error) {
	return grpc.NewClient(addr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                HeartbeatInterval,
			Timeout:             HeartbeatInterval,
			PermitWithoutStream: true,
		}),
	)
}

// EngineCapabilities asks the engine binary what it can run.
//
// Asked rather than configured: engines are replaced independently of the
// runtime (ADR-027), so a configured answer is right until someone upgrades one.
// What comes back is self-asserted and a CEILING — Core intersects it with what
// this scan point is independently authorised to run, so declaring a capability
// cannot obtain work it is not permitted to do (common.proto).
func EngineCapabilities(ctx context.Context, binary string) ([]*scanpointv1.Capability, error) {
	// Bounded and time-limited. Output() buffers stdout without a ceiling, and
	// the caller's context has no deadline — so a wedged engine binary hangs
	// startup and every rotation, and a chatty one exhausts memory before it is
	// ever asked to do any work.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// #nosec G204 -- same binary, same reasoning as engineHost.start.
	cmd := exec.CommandContext(ctx, binary, "-capabilities")
	cmd.Env = engineEnv()
	var buf bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &buf, remaining: 64 << 10}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("scanpoint: engine %s would not report capabilities: %w", binary, err)
	}
	out := buf.Bytes()
	var decoded []struct {
		Engine            string `json:"engine"`
		EngineVersion     string `json:"engine_version"`
		RuleFormatVersion string `json:"rule_format_version"`
		Enabled           bool   `json:"enabled"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		return nil, fmt.Errorf("scanpoint: engine capabilities are not JSON: %w", err)
	}
	caps := make([]*scanpointv1.Capability, 0, len(decoded))
	for _, d := range decoded {
		caps = append(caps, &scanpointv1.Capability{
			Engine:            d.Engine,
			EngineVersion:     d.EngineVersion,
			RuleFormatVersion: d.RuleFormatVersion,
			Enabled:           d.Enabled,
		})
	}
	if len(caps) == 0 {
		return nil, errors.New("scanpoint: engine declared no capabilities")
	}
	return caps, nil
}

// limitedWriter stops after n bytes rather than growing without bound.
type limitedWriter struct {
	w         *bytes.Buffer
	remaining int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		// Reported as consumed so the child is not killed by SIGPIPE mid-write;
		// the JSON decode below fails on the truncated document, which is the
		// error the caller wants to see.
		return len(p), nil
	}
	if len(p) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.w.Write(p)
	l.remaining -= n
	return n, err
}
