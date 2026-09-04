// Command cvap-core runs the CVAP Control Plane.
//
// # Two listeners, and why
//
// Enrollment is the one call a scan point makes before it has a certificate, so
// it cannot sit behind tls.RequireAndVerifyClientCert. Dispatch and Ingest must
// (internal/dispatch's package doc says so and gives the reason: a certificate
// is PUBLIC, so under RequireAnyClientCert anyone who has seen a scan point's
// certificate can present it and become that scan point).
//
// One listener cannot be both. Relaxing the mTLS port to serve Enroll would
// weaken the requirement for Dispatch and Ingest as well, so Enroll gets its own
// port with server TLS only, and RotateCertificate — which authenticates with
// the certificate being replaced — is served on the mTLS port. EnrollResponse
// already returns a separate endpoint per service, so the contract anticipates
// them living apart.
//
// Enrollment is registered on the enrollment listener ONLY. Registering it on
// both would give token redemption a second path whose access control differs
// from the first, which is the shape of an authorisation bug nobody notices
// until it is used.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/control/ca"
	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/dispatch"
	"github.com/effaaykhan/cvap/internal/logging"
	"github.com/effaaykhan/cvap/internal/store"

	// Embedded IANA timezone database.
	//
	// scan_policies.time_windows may name a zone — a maintenance window is
	// written in the operator's local time, not in UTC — and dispatch resolves
	// it with time.LoadLocation, which fails closed: a zone it cannot resolve
	// refuses the job rather than silently treating the window as UTC and
	// scanning an hour outside it for half the year.
	//
	// A scratch or distroless image carries no /usr/share/zoneinfo, so without
	// this every named window would fail on the deployment where it matters and
	// pass on every developer's laptop. Roughly 450 KB, in the binary rather
	// than in the base image, so it cannot go missing when the image changes.
	//
	// A FALLBACK, not an override: the system database still wins where there is
	// one, so a host with stale tzdata moves a maintenance window by an hour in
	// whichever direction the rule changed. Embedding removes the "no zones at
	// all" failure, not the "wrong zones" one.
	_ "time/tzdata"
)

var (
	version         = "dev"
	protocolVersion = "v1"
)

// Every variable is read through a LITERAL os.Getenv call rather than a named
// constant, so .github/scripts/check_env_example.py can see it. That gate
// asserts env.example documents exactly what the code reads, in both
// directions, and it matches literals — a constant would make the key invisible
// to it and to anyone grepping for which code reads a setting.

func main() {
	log := logging.New(os.Stdout, logging.Options{Level: levelFromEnv()})
	if err := run(log); err != nil {
		log.Error("control plane stopped", slog.Any("error", err))
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	log.Info("control plane starting",
		slog.String("version", version),
		slog.String("protocol_version", protocolVersion))

	for _, k := range []string{
		"CVAP_CORE_ENROLL_LISTEN", "CVAP_CORE_MTLS_LISTEN", "CVAP_CORE_API_LISTEN",
		"CVAP_CORE_CA_CERT", "CVAP_CORE_CA_KEY", "APP_DATABASE_URL",
	} {
		if os.Getenv(k) == "" {
			return fmt.Errorf("cvap-core: %s is not set", k)
		}
	}

	db, err := store.Open(ctx, store.Config{URL: os.Getenv("APP_DATABASE_URL")})
	if err != nil {
		return fmt.Errorf("cvap-core: database: %w", err)
	}
	defer db.Close()

	authority, err := ca.Open(ca.Config{
		CertPath: os.Getenv("CVAP_CORE_CA_CERT"),
		KeyPath:  os.Getenv("CVAP_CORE_CA_KEY"),
	})
	if err != nil {
		return fmt.Errorf("cvap-core: certificate authority: %w", err)
	}

	hosts := os.Getenv("CVAP_CORE_SERVER_HOSTS")
	if hosts == "" {
		hosts = "localhost,127.0.0.1"
	}
	serverCert, serverKey, err := authority.SignServer(splitHosts(hosts), time.Now())
	if err != nil {
		return fmt.Errorf("cvap-core: server certificate: %w", err)
	}
	keyPair, err := tls.X509KeyPair(serverCert, serverKey)
	if err != nil {
		return fmt.Errorf("cvap-core: server key pair: %w", err)
	}

	clientCAs := x509.NewCertPool()
	for _, der := range authority.Chain() {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("cvap-core: parse CA chain: %w", err)
		}
		clientCAs.AddCert(c)
	}

	versions := enrollment.VersionWindow{Accepted: protocolVersion, MinSupported: protocolVersion}
	endpoints := enrollment.Endpoints{
		Dispatch:  orDefault(os.Getenv("CVAP_CORE_DISPATCH_ENDPOINT"), os.Getenv("CVAP_CORE_MTLS_LISTEN")),
		Ingest:    orDefault(os.Getenv("CVAP_CORE_INGEST_ENDPOINT"), os.Getenv("CVAP_CORE_MTLS_LISTEN")),
		RulePacks: orDefault(os.Getenv("CVAP_CORE_RULEPACKS_ENDPOINT"), os.Getenv("CVAP_CORE_MTLS_LISTEN")),
	}

	enrollSvc := enrollment.New(db, authority, endpoints, versions, log)
	dispatchSvc := dispatch.New(db, versions, log)
	ingestSvc := dispatch.NewIngest(db, log)

	// ------------------------------------------------------------------
	// The enrollment listener: server TLS, no client certificate.
	// ------------------------------------------------------------------
	enrollServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{keyPair},
			MinVersion:   tls.VersionTLS13,
			ClientAuth:   tls.NoClientCert,
		})),
		// No payload-logging interceptor here or on the mTLS server, ever.
		// EnrollRequest carries a bearer token and CredentialGrant carries
		// credential material; an interceptor sees both reflectively and
		// defeats every source-level check (ADR-034).
	)
	scanpointv1.RegisterEnrollmentServer(enrollServer, enrollSvc)

	// ------------------------------------------------------------------
	// The mTLS listener: dispatch, ingest, and certificate rotation.
	// ------------------------------------------------------------------
	mtlsServer := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{keyPair},
			MinVersion:   tls.VersionTLS13,
			// RequireAndVerifyClientCert, not RequireAnyClientCert. A
			// certificate is PUBLIC: under RequireAny, anyone who has seen a
			// scan point's certificate can present it and become that scan
			// point, and PeerFingerprint would hash it happily.
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
		})),
		// MaxConnectionAge and its grace are NOT optional. A peer that answers
		// PINGs but never reads its stream cannot be released by anything
		// else — sendLoop returning frees the handler, and only the transport
		// can free the socket (internal/dispatch package doc).
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge:      4 * time.Hour,
			MaxConnectionAgeGrace: 1 * time.Minute,
			Time:                  30 * time.Second,
			Timeout:               20 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	scanpointv1.RegisterDispatchServer(mtlsServer, dispatchSvc)
	scanpointv1.RegisterIngestServer(mtlsServer, ingestSvc)
	// Rotation only. Enroll is not reachable here: it is on the other listener,
	// and RotateCertificate is the operation that needs the peer certificate.
	scanpointv1.RegisterEnrollmentServer(mtlsServer, rotateOnly{inner: enrollSvc})

	// The sweeper is NOT a background nicety. Leases.ExpireLeases carries
	// ADR-012's at-most-once rule entirely, and a security review found it had
	// no caller: a scan point that died left its job running forever, never
	// retried when retry was safe and never escalated when it was not.
	// Registering Dispatch without starting this puts that back.
	sweeper := dispatch.NewSweeper(db, log)
	go sweeper.Run(ctx)

	// Correlation is the same shape of omission waiting to happen.
	//
	// ADR-006 makes Core the only thing that turns observations into assets, and
	// without this the observation table fills, `asset_id` stays NULL on every
	// row, and the inventory is permanently empty while every gate passes. It is
	// periodic for the reason the sweeper is: the trigger is the ABSENCE of an
	// event — an observation is promoted to `accepted` by a terminal ack that
	// arrives minutes after ingest, and nothing then announces it is ready.
	correlator := correlate.New(db, log)
	go correlator.Run(ctx)

	// The operator API. Everything ADR-024 control 4 and ADR-021 require existed
	// in the store and was unreachable from production until this listener.
	//
	// It is a SEPARATE listener from the two gRPC ones and always will be. A
	// scan point reaches Core over mTLS with a certificate this deployment
	// issued; an operator reaches it over server TLS with a session. Serving
	// both on one port would mean one TLS configuration for two trust models,
	// and the weaker one would win.
	// An optional trust bundle for identity-provider traffic, for an on-prem
	// deployment whose internal provider is issued by a private CA. Absent means
	// the system roots, which is what a public issuer needs.
	oidcRoots, err := loadOIDCRoots(os.Getenv("CVAP_CORE_OIDC_CA_BUNDLE"))
	if err != nil {
		return fmt.Errorf("cvap-core: operator api: %w", err)
	}

	apiSrv, err := api.New(db, log, api.Config{
		Version:             version,
		LocalAuthEnabled:    os.Getenv("CVAP_CORE_LOCAL_AUTH") == "1",
		Insecure:            os.Getenv("CVAP_CORE_API_INSECURE") == "1",
		ListenAddr:          os.Getenv("CVAP_CORE_API_LISTEN"),
		AllowPrivateIssuers: os.Getenv("CVAP_CORE_OIDC_ALLOW_PRIVATE_ISSUER") == "1",
		OIDCRootCAs:         oidcRoots,
		SessionTTL:          apiSessionTTL(),
	})
	if err != nil {
		return fmt.Errorf("cvap-core: operator api: %w", err)
	}

	var wg sync.WaitGroup
	serve := func(name, addr string, s *grpc.Server) error {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("cvap-core: listen %s: %w", name, err)
		}
		log.Info("listening", slog.String("service", name), slog.String("addr", ln.Addr().String()))
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Serve(ln); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
				log.Error("server stopped", slog.String("service", name), slog.Any("error", err))
			}
		}()
		return nil
	}

	if err := serve("enrollment", os.Getenv("CVAP_CORE_ENROLL_LISTEN"), enrollServer); err != nil {
		return err
	}
	if err := serve("dispatch+ingest", os.Getenv("CVAP_CORE_MTLS_LISTEN"), mtlsServer); err != nil {
		return err
	}

	httpSrv := &http.Server{
		Addr:    os.Getenv("CVAP_CORE_API_LISTEN"),
		Handler: apiSrv.Handler(),

		// Bounded, because an operator API is reachable from a browser and
		// therefore from anything that can talk to a browser's network. A
		// connection that sends one byte of a header and waits holds a goroutine
		// and a file descriptor until something times it out; these are what
		// times it out.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	// The same server key pair the enrollment listener presents, and NO client
	// certificate: an operator authenticates with a session, not with a
	// certificate this deployment issued to a scan point.
	httpSrv.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{keyPair},
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.NoClientCert,
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		log.Info("listening", slog.String("service", "operator api"), slog.String("addr", httpSrv.Addr))
		// TLS always, and the certificate is the same server certificate the
		// enrollment listener presents. A session cookie is a bearer credential
		// and Secure is set on it, so a plaintext listener would issue cookies
		// no browser would ever send back.
		if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("server stopped", slog.String("service", "operator api"), slog.Any("error", err))
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Error("operator api shutdown", slog.Any("error", err))
	}
	enrollServer.GracefulStop()
	mtlsServer.GracefulStop()
	wg.Wait()
	return nil
}

// apiSessionTTL reads CVAP_CORE_SESSION_TTL_SECONDS.
//
// Defaults to eight hours, and cannot exceed twelve: the sessions table has a
// CHECK constraint saying so, and api.New refuses a larger value rather than
// clamping it, so a deployment does not believe something about its own
// configuration that the database will later contradict at login time.
func apiSessionTTL() time.Duration {
	v := os.Getenv("CVAP_CORE_SESSION_TTL_SECONDS")
	if v == "" {
		return 8 * time.Hour
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 8 * time.Hour
	}
	return time.Duration(n) * time.Second
}

// rotateOnly serves RotateCertificate and refuses Enroll.
//
// The mTLS listener needs the Enrollment SERVICE registered so that rotation is
// reachable, and gRPC registers services rather than methods. Wrapping it is
// what keeps token redemption to exactly one path: an Enroll call arriving here
// is refused before it reaches the service, rather than succeeding under access
// control that differs from the enrollment listener's.
type rotateOnly struct {
	scanpointv1.UnimplementedEnrollmentServer
	inner *enrollment.Service
}

func (r rotateOnly) Enroll(context.Context, *scanpointv1.EnrollRequest) (*scanpointv1.EnrollResponse, error) {
	return nil, status_Unimplemented()
}

func (r rotateOnly) RotateCertificate(ctx context.Context, req *scanpointv1.RotateRequest) (*scanpointv1.EnrollResponse, error) {
	return r.inner.RotateCertificate(ctx, req)
}

func splitHosts(s string) []string {
	var out []string
	for _, h := range splitComma(s) {
		if h != "" {
			out = append(out, h)
		}
	}
	return out
}

func splitComma(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	return append(out, cur)
}

func orDefault(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

// loadOIDCRoots reads a PEM bundle of additional roots for identity-provider
// traffic.
//
// An empty path means the system roots. A path that does not parse is a FATAL
// startup error rather than a fallback: a deployment that configured a private
// CA and silently got the system store would have single sign-on fail later with
// a certificate error nobody connects to this file.
func loadOIDCRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	// The path is deployment configuration read once at startup, from the same
	// environment that supplies CVAP_CORE_CA_KEY — by a process the operator who
	// set it already runs. There is no traversal boundary here to cross: an
	// operator who can set this variable can already read any file Core can.
	// #nosec G304,G703 -- operator-supplied configuration path, not request input
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("oidc ca bundle: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("oidc ca bundle %s contains no usable certificate", path)
	}
	return pool, nil
}
