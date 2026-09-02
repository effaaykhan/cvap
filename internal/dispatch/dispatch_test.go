package dispatch_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/control/ca"
	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/dispatch"
	"github.com/effaaykhan/cvap/internal/store"
)

// fakeStream implements grpc.BidiStreamingServer[ScanPointMessage, CoreMessage].
//
// A fake rather than a real gRPC transport because what is under test is the
// handler's logic — the handshake, the fencing check, the assignment path — and
// a bufconn server would add a TLS handshake to every case without exercising
// anything this package owns. The peer certificate is injected on the context
// exactly as gRPC would deliver it, which is the part that matters: identity
// comes from there and nowhere else.
type fakeStream struct {
	ctx context.Context

	mu       sync.Mutex
	inbound  chan *scanpointv1.ScanPointMessage
	outbound []*scanpointv1.CoreMessage
	sent     chan *scanpointv1.CoreMessage
	closed   bool
}

func newFakeStream(ctx context.Context) *fakeStream {
	return &fakeStream{
		ctx:     ctx,
		inbound: make(chan *scanpointv1.ScanPointMessage, 16),
		sent:    make(chan *scanpointv1.CoreMessage, 64),
	}
}

func (f *fakeStream) Context() context.Context { return f.ctx }

func (f *fakeStream) Send(m *scanpointv1.CoreMessage) error {
	f.mu.Lock()
	f.outbound = append(f.outbound, m)
	f.mu.Unlock()
	select {
	case f.sent <- m:
	default:
	}
	return nil
}

func (f *fakeStream) Recv() (*scanpointv1.ScanPointMessage, error) {
	select {
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	case m, ok := <-f.inbound:
		if !ok {
			return nil, io.EOF
		}
		return m, nil
	}
}

func (f *fakeStream) push(m *scanpointv1.ScanPointMessage) { f.inbound <- m }

func (f *fakeStream) closeInbound() {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.closed {
		close(f.inbound)
		f.closed = true
	}
}

// waitFor drains sent messages until pred matches or the deadline passes.
func (f *fakeStream) waitFor(t *testing.T, what string, pred func(*scanpointv1.CoreMessage) bool) *scanpointv1.CoreMessage {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case m := <-f.sent:
			if pred(m) {
				return m
			}
		case <-deadline:
			t.Fatalf("timed out waiting for %s", what)
			return nil
		}
	}
}

// Unused halves of grpc.ServerStream.
func (f *fakeStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeStream) SetTrailer(metadata.MD)       {}
func (f *fakeStream) SendMsg(any) error            { return nil }
func (f *fakeStream) RecvMsg(any) error            { return nil }

func testDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set; skipping dispatch integration tests")
	}
	db, err := store.Open(context.Background(), store.Config{URL: url})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

const testVersion = "v1"

func newService(t *testing.T, db *store.DB) *dispatch.Service {
	t.Helper()
	return dispatch.New(db,
		enrollment.VersionWindow{Accepted: testVersion, MinSupported: testVersion},
		slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

// enrolledScanPoint runs a real enrollment and returns the tenant, the leaf and
// the scan point id — so the peer certificate the stream presents is one Core
// actually issued.
func enrolledScanPoint(t *testing.T, db *store.DB) (store.TenantID, *x509.Certificate, uuid.UUID) {
	t.Helper()
	ctx := context.Background()

	dir := t.TempDir()
	certPath, keyPath, err := ca.GenerateSelfSigned(dir, "dispatch test CA", 365*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Open(ca.Config{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}

	svc := enrollment.New(db, authority,
		enrollment.Endpoints{Dispatch: "d:443", Ingest: "i:443", RulePacks: "r:443"},
		enrollment.VersionWindow{Accepted: testVersion, MinSupported: testVersion},
		slog.New(slog.NewJSONHandler(io.Discard, nil)))
	issuer := enrollment.NewIssuer(db)

	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	var zoneID uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Tenants{}).Create(ctx, c, "disp-"+uuid.NewString()[:8], store.DeploymentOnPrem); err != nil {
			return err
		}
		z, err := (store.Zones{}).Create(ctx, c, "z", store.ZoneInternal, 50, "")
		if err != nil {
			return err
		}
		zoneID = z.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Enroll(ctx, &scanpointv1.EnrollRequest{
		EnrollmentToken: issued.Token.Reveal(),
		Csr:             testCSR(t),
		Hostname:        "sp-01",
		AgentVersion:    "0.1.0",
		ProtocolVersion: testVersion,
		Capabilities: []*scanpointv1.Capability{
			{Engine: "discovery", EngineVersion: "0.1.0", Enabled: true},
		},
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	leaf, err := x509.ParseCertificate(resp.GetCertificate())
	if err != nil {
		t.Fatal(err)
	}
	return tenant, leaf, uuid.MustParse(resp.GetScanPointId())
}

func peerCtx(ctx context.Context, leaf *x509.Certificate) context.Context {
	return peer.NewContext(ctx, &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}},
		},
	})
}

// seedQueuedJob puts one claimable discovery job in the queue.
func seedQueuedJob(t *testing.T, db *store.DB, tenant store.TenantID, reassignSafe bool) uuid.UUID {
	t.Helper()
	var jobID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		var policyID, scanID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name) VALUES ($1,$2) RETURNING policy_id`,
			tid, "p-"+uuid.NewString()[:8]).Scan(&policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1,$2,'discovery') RETURNING scan_id`,
			tid, policyID).Scan(&scanID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',$3) RETURNING job_id`,
			tid, scanID, reassignSafe).Scan(&jobID); err != nil {
			return err
		}
		_, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, task_target) VALUES ($1,$2,'10.0.0.7')`,
			tid, jobID)
		return err
	}); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	return jobID
}

// ============================================================================
// Identity comes from the certificate, and only from the certificate.
// ============================================================================

func TestConnectRequiresAClientCertificate(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := svc.Connect(newFakeStream(ctx))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no peer certificate: got %v, want Unauthenticated", status.Code(err))
	}
}

func TestConnectRefusesAnUnenrolledCertificate(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	_, leaf, _ := enrolledScanPoint(t, db)

	// Revoke by replacing the fingerprint the scan point row carries: the
	// certificate is genuine, and Core no longer knows it. That is the whole of
	// revocation — no CRL, no OCSP (ADR-018, ADR-031).
	tenant, _, spID := enrolledScanPoint(t, db)
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.ScanPoints{}).SetStatus(ctx, c, spID, store.ScanPointRevoked)
	}); err != nil {
		t.Fatal(err)
	}
	_ = leaf

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// A certificate from a different CA entirely: never enrolled.
	other := t.TempDir()
	cp, kp, err := ca.GenerateSelfSigned(other, "unrelated", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := ca.Open(ca.Config{CertPath: cp, KeyPath: kp})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ca.ParseCSR(testCSR(t))
	if err != nil {
		t.Fatal(err)
	}
	der, _, _, _, err := auth.SignScanPoint(csr, uuid.New(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	stranger, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	err = svc.Connect(newFakeStream(peerCtx(ctx, stranger)))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unenrolled certificate: got %v, want Unauthenticated", status.Code(err))
	}
}

// Hello.scan_point_id is an echo. A mismatch closes the stream rather than being
// trusted or quietly preferred — both readings hide something an operator needs.
func TestHelloIdMismatchClosesTheStream(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	_, leaf, _ := enrolledScanPoint(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(peerCtx(ctx, leaf))
	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Hello{Hello: &scanpointv1.Hello{
			ScanPointId:     uuid.New().String(), // somebody else
			ProtocolVersion: testVersion,
		}},
	})

	if err := svc.Connect(fs); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("mismatched scan_point_id: got %v, want PermissionDenied", status.Code(err))
	}
}

func TestHandshakeRefusesAnUnsupportedVersion(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	_, leaf, _ := enrolledScanPoint(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(peerCtx(ctx, leaf))
	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Hello{Hello: &scanpointv1.Hello{
			ProtocolVersion: "v0-ancient",
		}},
	})

	err := svc.Connect(fs)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition", status.Code(err))
	}
	if status.Convert(err).Message() == "" {
		t.Error("no operator-facing message; ADR-022 requires words, not a bare code")
	}
}

func TestFirstMessageMustBeHello(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	_, leaf, _ := enrolledScanPoint(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(peerCtx(ctx, leaf))
	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Heartbeat{
			Heartbeat: &scanpointv1.Heartbeat{SentAtUnix: time.Now().Unix()},
		},
	})

	if err := svc.Connect(fs); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("heartbeat before Hello: got %v, want FailedPrecondition", status.Code(err))
	}
}

// ============================================================================
// The loop: handshake, assignment, lease renewal, fencing.
// ============================================================================

func TestConnectAssignsWorkAndFencesTheLease(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID := seedQueuedJob(t, db, tenant, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(peerCtx(ctx, leaf))

	done := make(chan error, 1)
	go func() { done <- svc.Connect(fs) }()

	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Hello{Hello: &scanpointv1.Hello{
			ScanPointId:     spID.String(),
			ProtocolVersion: testVersion,
			AgentVersion:    "0.1.0",
			Capabilities: []*scanpointv1.Capability{
				{Engine: "discovery", EngineVersion: "0.1.0", Enabled: true},
			},
		}},
	})

	sh := fs.waitFor(t, "ServerHello", func(m *scanpointv1.CoreMessage) bool {
		return m.GetServerHello() != nil
	})
	if sh.GetServerHello().GetAcceptedProtocolVersion() != testVersion {
		t.Errorf("ServerHello accepted version = %q", sh.GetServerHello().GetAcceptedProtocolVersion())
	}

	assign := fs.waitFor(t, "JobAssignment", func(m *scanpointv1.CoreMessage) bool {
		return m.GetJob() != nil
	}).GetJob()

	if assign.GetJobId() != jobID.String() {
		t.Errorf("assigned job %s, want %s", assign.GetJobId(), jobID)
	}
	if assign.GetLeaseEpoch() <= 0 {
		t.Error("assignment carries no lease epoch; there is no fencing token")
	}
	if len(assign.GetTasks()) != 1 {
		t.Errorf("assignment carries %d tasks, want 1", len(assign.GetTasks()))
	}
	// ADR-024's ceilings must reach the component that sends packets. A ceiling
	// that does not travel is decorative.
	if c := assign.GetConstraints(); c == nil || c.GetMaxRatePps() == 0 ||
		c.GetFragileRatePps() == 0 || c.GetConnectTimeoutMs() == 0 {
		t.Errorf("assignment carries incomplete constraints: %v", assign.GetConstraints())
	}

	epoch := assign.GetLeaseEpoch()

	// A renewal at the held epoch is granted.
	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_LeaseRenewal{
			LeaseRenewal: &scanpointv1.LeaseRenewal{
				JobId: jobID.String(), LeaseEpoch: epoch,
			},
		},
	})
	grant := fs.waitFor(t, "LeaseGrant", func(m *scanpointv1.CoreMessage) bool {
		return m.GetLease() != nil
	}).GetLease()
	if grant.GetState() != scanpointv1.LeaseState_LEASE_STATE_GRANTED {
		t.Fatalf("renewal at the held epoch: state %v, want GRANTED", grant.GetState())
	}

	// Supersede out of band, exactly as a reassignment would.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Leases{}).Release(ctx, c, jobID, epoch, store.LeaseLost); err != nil {
			return err
		}
		_, err := (store.Leases{}).Grant(ctx, c, jobID, spID, store.LeaseTTL)
		return err
	}); err != nil {
		t.Fatalf("supersede: %v", err)
	}

	// The same renewal is now refused, and says why.
	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_LeaseRenewal{
			LeaseRenewal: &scanpointv1.LeaseRenewal{
				JobId: jobID.String(), LeaseEpoch: epoch,
			},
		},
	})
	lost := fs.waitFor(t, "LeaseGrant after supersession", func(m *scanpointv1.CoreMessage) bool {
		return m.GetLease() != nil &&
			m.GetLease().GetState() != scanpointv1.LeaseState_LEASE_STATE_GRANTED
	}).GetLease()
	if lost.GetState() != scanpointv1.LeaseState_LEASE_STATE_LOST {
		t.Errorf("renewal at a superseded epoch: state %v, want LOST", lost.GetState())
	}
	if lost.GetDetail() == "" {
		t.Error("LEASE_STATE_LOST carries no detail; the operator is told nothing")
	}

	fs.closeInbound()
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		t.Logf("stream ended with %v", err)
	}
}

// A JobTerminal without credentials_zeroised raises an audit event.
//
// The field is an attestation and a compromised scan point can lie. It exists to
// catch OUR bugs: ADR-020 requires zeroisation on every terminal path, and an
// invariant nothing asserts is one nothing notices the loss of.
func TestMissingZeroisationAttestationIsAudited(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID := seedQueuedJob(t, db, tenant, true)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fs := newFakeStream(peerCtx(ctx, leaf))
	done := make(chan error, 1)
	go func() { done <- svc.Connect(fs) }()

	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Hello{Hello: &scanpointv1.Hello{
			ScanPointId: spID.String(), ProtocolVersion: testVersion,
			Capabilities: []*scanpointv1.Capability{
				{Engine: "discovery", EngineVersion: "0.1.0", Enabled: true},
			},
		}},
	})
	assign := fs.waitFor(t, "JobAssignment", func(m *scanpointv1.CoreMessage) bool {
		return m.GetJob() != nil
	}).GetJob()

	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Terminal{
			Terminal: &scanpointv1.JobTerminal{
				JobId:      jobID.String(),
				LeaseEpoch: assign.GetLeaseEpoch(),
				Reason:     scanpointv1.TerminationReason_COMPLETED,
				// credentials_zeroised deliberately absent.
			},
		},
	})

	deadline := time.Now().Add(10 * time.Second)
	var found bool
	for time.Now().Before(deadline) && !found {
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			events, err := (store.AuditEvents{}).ListByResource(ctx, c, "scan_job", jobID, 50)
			if err != nil {
				return err
			}
			for _, e := range events {
				if e.Action == "scan_point.credentials_not_attested" {
					found = true
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !found {
			time.Sleep(150 * time.Millisecond)
		}
	}
	if !found {
		t.Error("a JobTerminal without credentials_zeroised raised no audit event; " +
			"an unchecked attestation is worse than no field at all")
	}

	fs.closeInbound()
	cancel()
	<-done
}
