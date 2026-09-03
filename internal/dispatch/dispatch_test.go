package dispatch_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
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

// waitUntil polls a condition until it holds or the deadline passes.
//
// The dispatch poll is two seconds and the write it triggers lands after the
// message it answers, so a single read straight after pushing a message races
// the handler. Polling asserts the state Core ends in rather than the instant it
// gets there.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
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
		if _, err := (store.Tenants{}).Create(ctx, c, "disp-"+uuid.NewString()[:8],
			"disp"+strings.ReplaceAll(uuid.NewString(), "-", "")[:20]+".test", store.DeploymentOnPrem); err != nil {
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
		// max_rate_pps is LOWER than the platform default on purpose. A seed at
		// the ceiling would pass whether constraintsFor took the minimum or
		// ignored the policy entirely, which is the bug it is meant to catch.
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name, max_rate_pps)
			 VALUES ($1,$2,120) RETURNING policy_id`,
			tid, "p-"+uuid.NewString()[:8]).Scan(&policyID); err != nil {
			return err
		}
		// An allow rule, because allowed_targets is now load-bearing: empty
		// means DENY ALL and the runtime refuses the task. A seed without one
		// produces an assignment no scan point would act on.
		if _, err := c.Exec(ctx,
			`INSERT INTO policy_scope_rules (tenant_id, policy_id, effect, match_type, match_value)
			 VALUES ($1,$2,'allow','cidr','192.0.2.0/24'),
			        ($1,$2,'deny','cidr','192.0.2.99/32')`,
			tid, policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1,$2,'discovery') RETURNING scan_id`,
			tid, policyID).Scan(&scanID); err != nil {
			return err
		}
		// An AUTHORISED target, because Jobs.Claim now refuses a job whose tasks
		// do not trace to one. That refusal is the point — migration 0005 says
		// dispatch must not decompose an unauthorised target, and the old seed
		// created a task with a NULL target_id, so the test was demonstrating
		// the gap rather than the behaviour.
		var targetID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value,
			                           authorization_verified, verified_at)
			 VALUES ($1,$2,'cidr','192.0.2.0/24',true,now()) RETURNING target_id`,
			tid, scanID).Scan(&targetID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',$3) RETURNING job_id`,
			tid, scanID, reassignSafe).Scan(&jobID); err != nil {
			return err
		}
		_, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
			 VALUES ($1,$2,$3,'192.0.2.7')`,
			tid, jobID, targetID)
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
	// that does not travel is decorative — and one that travels at the platform
	// default when the policy lowered it is worse than decorative, because it
	// reads as enforcement while authorising more than the operator asked for.
	c := assign.GetConstraints()
	if c == nil {
		t.Fatal("assignment carries no constraints")
	}
	if c.GetMaxRatePps() != 120 {
		t.Errorf("max_rate_pps = %d, want the policy's 120 rather than the platform 1000",
			c.GetMaxRatePps())
	}
	if c.GetMaxRatePerTarget() != 50 || c.GetFragileRatePps() != 10 ||
		c.GetConnectTimeoutMs() != 3000 || c.GetMaxConcurrentPerTarget() != 20 {
		t.Errorf("constraints below the policy rate are wrong: per_target=%d fragile=%d "+
			"timeout=%d concurrent=%d", c.GetMaxRatePerTarget(), c.GetFragileRatePps(),
			c.GetConnectTimeoutMs(), c.GetMaxConcurrentPerTarget())
	}
	// allowed_targets empty means DENY ALL, so an assignment whose allowlist did
	// not travel is one the scan point must refuse entirely.
	if got := c.GetAllowedTargets(); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Errorf("allowed_targets = %v, want the policy's one allow rule", got)
	}
	if got := c.GetExclusions(); len(got) != 1 || got[0] != "192.0.2.99/32" {
		t.Errorf("exclusions = %v, want the policy's one deny rule", got)
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
		if err := (store.Leases{}).ReleaseAny(ctx, c, jobID, epoch, store.LeaseLost); err != nil {
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

// TestTheTerminalDetailIsPersisted.
//
// ============================================================================
// JobTerminal.detail was produced by the runtime and read by Core nowhere.
// ============================================================================
//
// The proto defines it as "operator-facing detail: which engine failed, which
// target halted the scan"; onTerminal read job id, reason, epoch and the
// zeroisation attestation, and dropped this. An ADR-compliance pass found it.
//
// It matters most for the case ADR-044 corrects: a canonicalisation mismatch and
// a scope violation share SCOPE_VIOLATION_HALT, so this field is the only thing
// that tells an operator which of the two happened — and the two need different
// responses.
func TestTheTerminalDetailIsPersisted(t *testing.T) {
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

	const detail = "target is not in canonical form: 192.000.2.5"
	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Terminal{
			Terminal: &scanpointv1.JobTerminal{
				JobId:               jobID.String(),
				LeaseEpoch:          assign.GetLeaseEpoch(),
				Reason:              scanpointv1.TerminationReason_SCOPE_VIOLATION_HALT,
				CredentialsZeroised: true,
				Detail:              detail,
			},
		},
	})

	deadline := time.Now().Add(10 * time.Second)
	var got string
	for time.Now().Before(deadline) && got == "" {
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			return c.QueryRow(ctx,
				`SELECT coalesce(detail->>'detail', '') FROM audit_events
				  WHERE tenant_id = $1 AND action = 'job.terminated' AND resource_id = $2`,
				tenant.UUID(), jobID).Scan(&got)
		}); err != nil && !errors.Is(err, store.ErrNotFound) {
			t.Fatal(err)
		}
		if got == "" {
			time.Sleep(150 * time.Millisecond)
		}
	}
	if got != detail {
		t.Errorf("the terminal detail was stored as %q, want %q. Without it a scope violation "+
			"and a canonicalisation mismatch are one indistinguishable outcome in the audit "+
			"log, and they need different responses.", got, detail)
	}

	fs.closeInbound()
	cancel()
	<-done
}

// TestOutOfScopeTaskIsRefusedRatherThanDispatched is ADR-024 control 1, site
// one, end to end.
//
// A safety audit found the allowlist Core computed was advisory: put on the
// wire, compared against nothing, and enforced only by a scan point runtime that
// does not exist yet. That is exactly the "enforce at the Scan Point only"
// alternative ADR-024 rejected, arrived at by omission. scan_tasks.task_target
// is free text and Jobs.Claim authorises the parent scan_targets row rather than
// the decomposed value, so a planning bug puts a target on the wire that no
// policy rule covers.
func TestOutOfScopeTaskIsRefusedRatherThanDispatched(t *testing.T) {
	db := testDB(t)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID := seedQueuedJob(t, db, tenant, true)

	// The seed's policy allows 192.0.2.0/24. Move the task outside it, the way a
	// planning defect would: the authorised target_id is untouched.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`UPDATE scan_tasks SET task_target = '198.51.100.9'
			  WHERE tenant_id = $1 AND job_id = $2`, c.Tenant().UUID(), jobID)
		return err
	}); err != nil {
		t.Fatalf("move the task out of scope: %v", err)
	}

	svc := newService(t, db)
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
	fs.waitFor(t, "ServerHello", func(m *scanpointv1.CoreMessage) bool {
		return m.GetServerHello() != nil
	})

	// Give the pump time to poll, refuse and not assign.
	deadline := time.Now().Add(10 * time.Second)
	var terminal *store.Job
	for time.Now().Before(deadline) {
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			j, err := (store.Jobs{}).GetByID(ctx, c, jobID)
			if err != nil {
				return err
			}
			if j.Status == store.JobFailed {
				terminal = j
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if terminal != nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	cancel()
	<-done

	if terminal == nil {
		t.Fatal("the job was never refused. Core computed an allowlist and dispatched a task " +
			"outside it, which makes the allowlist advisory and leaves ADR-024 control 1 with " +
			"one enforcement site instead of two")
	}
	if terminal.TerminationReason == nil ||
		*terminal.TerminationReason != store.TerminationScopeViolationHalt {
		t.Errorf("termination_reason = %v, want scope_violation_halt", terminal.TerminationReason)
	}

	fs.mu.Lock()
	outbound := append([]*scanpointv1.CoreMessage(nil), fs.outbound...)
	fs.mu.Unlock()
	for _, m := range outbound {
		if m.GetJob() != nil {
			t.Errorf("an out-of-scope job was put on the wire: %v", m.GetJob())
		}
	}

	// The audit event, not just the state change. An operator reads the audit
	// log and the UI, never Core's stdout, so a scan that stopped for a scope
	// defect would otherwise look like a scan that stalled.
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		events, err := (store.AuditEvents{}).ListByResource(ctx, c, "scan_job", jobID, 10)
		if err != nil {
			return err
		}
		for _, e := range events {
			if e.Action == "job.scope_refused" {
				return nil
			}
		}
		t.Errorf("no job.scope_refused audit event; got %d events", len(events))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
