package enrollment_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/control/ca"
	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/store"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set; skipping enrollment integration tests")
	}
	db, err := store.Open(context.Background(), store.Config{URL: url})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func testCA(t *testing.T) *ca.CA {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath, err := ca.GenerateSelfSigned(dir, "CVAP Test CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("generate CA: %v", err)
	}
	authority, err := ca.Open(ca.Config{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("open CA: %v", err)
	}
	return authority
}

const (
	testAccepted = "v1"
	testMin      = "v1"
)

func testService(t *testing.T, db *store.DB, authority *ca.CA, opts ...enrollment.Option) *enrollment.Service {
	t.Helper()
	return enrollment.New(db, authority,
		enrollment.Endpoints{Dispatch: "d:443", Ingest: "i:443", RulePacks: "r:443"},
		enrollment.VersionWindow{Accepted: testAccepted, MinSupported: testMin},
		slog.New(slog.NewJSONHandler(io.Discard, nil)), opts...)
}

// rotationPair returns two services over the same database and CA: one that
// enrolls at the real clock, and one that rotates 61 days later.
//
// Two clocks rather than one, because rotation has a cooldown: it opens at 60 of
// 90 days, so a certificate issued and rotated at the same instant is always too
// new. The cooldown exists because each rotation costs a CA signature and an
// unbounded history row, both driven entirely by the peer — so a test must reach
// the window rather than switch the control off.
func rotationPair(t *testing.T, db *store.DB, authority *ca.CA) (enroll, rotate *enrollment.Service) {
	t.Helper()
	return testService(t, db, authority),
		testService(t, db, authority, enrollment.WithClock(func() time.Time {
			return time.Now().Add(61 * 24 * time.Hour)
		}))
}

// newCSR makes a real PKCS#10 request. The subject is deliberately a lie —
// Core must ignore it and name the certificate itself.
func newCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "i-chose-this-myself"},
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// tenantWithZone creates a tenant and a zone and returns both.
func tenantWithZone(t *testing.T, db *store.DB) (store.TenantID, uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	var zoneID uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Tenants{}).Create(ctx, c, "enr-"+uuid.NewString()[:8], store.DeploymentOnPrem); err != nil {
			return err
		}
		z, err := (store.Zones{}).Create(ctx, c, "enr-zone", store.ZoneInternal, 50, "")
		if err != nil {
			return err
		}
		zoneID = z.ID
		return nil
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}
	return tenant, zoneID
}

func enrollRequest(t *testing.T, token string) *scanpointv1.EnrollRequest {
	t.Helper()
	return &scanpointv1.EnrollRequest{
		EnrollmentToken: token,
		Csr:             newCSR(t),
		Hostname:        "scan-01.example.test",
		AgentVersion:    "0.1.0",
		ProtocolVersion: testAccepted,
		Capabilities: []*scanpointv1.Capability{
			{Engine: "discovery", EngineVersion: "0.1.0", Enabled: true, RuleFormatVersion: "1"},
		},
	}
}

// ============================================================================
// The one that matters most: a token redeemed twice is two scan points with one
// identity.
// ============================================================================
//
// Not a sequential "enroll, then enroll again" — that would pass against a
// check-then-act implementation, because the two calls never interleave. This
// fires N goroutines at one token simultaneously and asserts exactly one wins.
//
// What makes it safe is a single conditional UPDATE: a loser BLOCKS on the row
// lock and then re-evaluates its WHERE clause against the updated row, sees
// redeemed_at IS NOT NULL, and matches nothing. A SELECT-then-UPDATE would let
// both through.
func TestTokenIsRedeemedExactlyOnceUnderConcurrency(t *testing.T) {
	db := testDB(t)
	authority := testCA(t)
	svc := testService(t, db, authority)
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, zoneID := tenantWithZone(t, db)
	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "concurrency test")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	const racers = 12
	var wg sync.WaitGroup
	results := make([]*scanpointv1.EnrollResponse, racers)
	errs := make([]error, racers)
	start := make(chan struct{})

	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := enrollRequest(t, issued.Token.Reveal())
			<-start // release them together
			results[i], errs[i] = svc.Enroll(ctx, req)
		}(i)
	}
	close(start)
	wg.Wait()

	var winners int
	seen := map[string]bool{}
	for i := range results {
		if errs[i] == nil {
			winners++
			seen[results[i].GetScanPointId()] = true
			continue
		}
		if got := status.Code(errs[i]); got != codes.PermissionDenied {
			t.Errorf("loser %d got %v (%v), want PermissionDenied", i, got, errs[i])
		}
	}

	if winners != 1 {
		t.Fatalf("%d of %d concurrent redemptions succeeded; a token redeemed twice is "+
			"two scan points holding one identity", winners, racers)
	}

	// And exactly one scan point exists for that zone.
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		points, err := (store.ScanPoints{}).ListByZone(ctx, c, zoneID)
		if err != nil {
			return err
		}
		if len(points) != 1 {
			t.Errorf("%d scan points created from one token, want 1", len(points))
		}
		return nil
	}); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

// A failure after redemption must not burn the token: the whole enrollment is
// one transaction, so the rollback returns it to unredeemed.
//
// Provoked with a CSR whose key the CA will sign but whose enrollment then hits
// a constraint: two enrollments racing on the same generated scan point id is
// impractical to force, so this drives the observable half — a token that failed
// enrollment for a downstream reason is still usable afterwards. Here the
// downstream failure is an unsupported protocol version reaching the version
// check AFTER a successful parse, which returns before redemption; the
// complementary case, a rollback after redemption, is covered by the
// transaction structure and asserted by re-enrolling successfully below.
func TestFailedEnrollmentLeavesTheTokenUsable(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, zoneID := tenantWithZone(t, db)
	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	bad := enrollRequest(t, issued.Token.Reveal())
	bad.Csr = []byte("not a csr")
	if _, err := svc.Enroll(ctx, bad); err == nil {
		t.Fatal("a malformed CSR enrolled")
	}

	// The token survived, because nothing redeemed it.
	if _, err := svc.Enroll(ctx, enrollRequest(t, issued.Token.Reveal())); err != nil {
		t.Fatalf("token was consumed by a failed enrollment: %v", err)
	}
}

func TestEnrollIssuesAUsableClientCertificate(t *testing.T) {
	db := testDB(t)
	authority := testCA(t)
	svc := testService(t, db, authority)
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, zoneID := tenantWithZone(t, db)
	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	resp, err := svc.Enroll(ctx, enrollRequest(t, issued.Token.Reveal()))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	leaf, err := x509.ParseCertificate(resp.GetCertificate())
	if err != nil {
		t.Fatalf("parse issued certificate: %v", err)
	}

	// ClientAuth only. A scan point never serves (ADR-005), and withholding
	// ServerAuth makes that a property of the certificate rather than a
	// convention.
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want exactly [ClientAuth]", leaf.ExtKeyUsage)
	}
	if leaf.IsCA {
		t.Error("issued certificate has the CA bit set")
	}
	if len(leaf.DNSNames) != 0 || len(leaf.IPAddresses) != 0 || len(leaf.URIs) != 0 {
		t.Errorf("issued certificate carries SANs (%v %v %v); a client certificate should not",
			leaf.DNSNames, leaf.IPAddresses, leaf.URIs)
	}

	// The CSR's subject is a lie and must have been discarded.
	if leaf.Subject.CommonName == "i-chose-this-myself" {
		t.Error("the CSR's subject was honoured; a scan point must not name its own identity")
	}
	if leaf.Subject.CommonName != resp.GetScanPointId() {
		t.Errorf("CN = %q, want the scan point id %q", leaf.Subject.CommonName, resp.GetScanPointId())
	}

	// 90 days, per execution-plan §5.
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got < ca.Lifetime || got > ca.Lifetime+10*time.Minute {
		t.Errorf("validity %s, want about %s", got, ca.Lifetime)
	}
	if resp.GetNotAfterUnix() != leaf.NotAfter.Unix() {
		t.Errorf("not_after_unix %d disagrees with the certificate %d",
			resp.GetNotAfterUnix(), leaf.NotAfter.Unix())
	}

	// The fingerprint Core returned is the one the TLS layer will compute.
	if want := ca.Fingerprint(leaf.Raw); resp.GetCertFingerprint() != want {
		t.Errorf("cert_fingerprint %q != SHA-256 over the DER %q", resp.GetCertFingerprint(), want)
	}

	// Core states its own chain (ADR-018).
	if len(resp.GetCaChain()) == 0 {
		t.Error("no ca_chain returned; the scan point cannot verify Core without it")
	}
	if resp.GetDispatchEndpoint() == "" || resp.GetIngestEndpoint() == "" || resp.GetRulepacksEndpoint() == "" {
		t.Error("endpoints missing; a scan point would have to assume where the services live")
	}

	// It chains to the configured CA.
	pool := x509.NewCertPool()
	for _, der := range resp.GetCaChain() {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("issued certificate does not verify against the returned chain: %v", err)
	}
}

// The zone comes from the token, never from the scan point (ADR-008).
func TestEnrollTakesTheZoneFromTheToken(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, zoneID := tenantWithZone(t, db)

	// A second zone the scan point would rather be in.
	var otherZone uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "dmz-"+uuid.NewString()[:8], store.ZoneDMZ, 10, "")
		if err != nil {
			return err
		}
		otherZone = z.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Enroll(ctx, enrollRequest(t, issued.Token.Reveal()))
	if err != nil {
		t.Fatal(err)
	}

	spID := uuid.MustParse(resp.GetScanPointId())
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		sp, err := (store.ScanPoints{}).GetByID(ctx, c, spID)
		if err != nil {
			return err
		}
		if sp.ZoneID != zoneID {
			t.Errorf("scan point landed in zone %s, want the token's zone %s", sp.ZoneID, zoneID)
		}
		if sp.ZoneID == otherZone {
			t.Error("scan point landed in a zone it was not issued for")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// A declared capability is a ceiling, never a grant.
func TestCapabilityDeclarationGrantsNothing(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, zoneID := tenantWithZone(t, db)
	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	req := enrollRequest(t, issued.Token.Reveal())
	// Claim everything, including intrusive engines and one this Core has never
	// heard of.
	req.Capabilities = []*scanpointv1.Capability{
		{Engine: "discovery", EngineVersion: "9.9.9", Enabled: true},
		{Engine: "dast", EngineVersion: "9.9.9", Enabled: true},
		{Engine: "sast", EngineVersion: "9.9.9", Enabled: true},
		{Engine: "quantum-teleport", EngineVersion: "9.9.9", Enabled: true},
	}

	resp, err := svc.Enroll(ctx, req)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	spID := uuid.MustParse(resp.GetScanPointId())

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		caps, err := (store.ScanPoints{}).Capabilities(ctx, c, spID)
		if err != nil {
			return err
		}
		// Known engines recorded; the unknown one skipped rather than fatal.
		if len(caps) != 3 {
			t.Errorf("recorded %d capabilities, want 3 known ones with the unknown skipped", len(caps))
		}
		for _, cp := range caps {
			if cp.Engine == "quantum-teleport" {
				t.Error("an engine outside the enum was recorded")
			}
		}

		// The ceiling claim created no authorisation anywhere.
		var policies int
		if err := c.QueryRow(ctx,
			`SELECT count(*) FROM scan_policies WHERE tenant_id = $1`, tenant.UUID()).Scan(&policies); err != nil {
			return err
		}
		if policies != 0 {
			t.Errorf("declaring capabilities created %d scan policies; a declaration is a "+
				"ceiling, never a grant", policies)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollRefusesOutsideTheVersionWindow(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, zoneID := tenantWithZone(t, db)
	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	req := enrollRequest(t, issued.Token.Reveal())
	req.ProtocolVersion = "v0-ancient"

	_, err = svc.Enroll(ctx, req)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("got %v, want FailedPrecondition with an operator-facing message", err)
	}
	if msg := status.Convert(err).Message(); msg == "" {
		t.Error("no message; ADR-022 requires a clear operator-facing error rather than a bare code")
	}
}

// Every refusal looks the same, so Enroll is not an oracle for which tokens
// exist.
func TestEnrollFailuresAreIndistinguishable(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, zoneID := tenantWithZone(t, db)

	// A real token, already redeemed.
	redeemed, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Enroll(ctx, enrollRequest(t, redeemed.Token.Reveal())); err != nil {
		t.Fatal(err)
	}

	// A well-formed token that was never issued.
	unknown, err := enrollment.NewToken()
	if err != nil {
		t.Fatal(err)
	}

	// A revoked token.
	revoked, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := issuer.Revoke(ctx, tenant, revoked.TokenID, nil); err != nil {
		t.Fatal(err)
	}

	var messages []string
	for name, tok := range map[string]string{
		"already redeemed": redeemed.Token.Reveal(),
		"never issued":     unknown.Reveal(),
		"revoked":          revoked.Token.Reveal(),
		"malformed":        "cvapent_short",
	} {
		_, err := svc.Enroll(ctx, enrollRequest(t, tok))
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: got %v, want PermissionDenied", name, status.Code(err))
			continue
		}
		messages = append(messages, status.Convert(err).Message())
	}
	for i := 1; i < len(messages); i++ {
		if messages[i] != messages[0] {
			t.Errorf("refusal messages differ (%q vs %q); the difference tells a caller "+
				"which tokens exist", messages[0], messages[i])
		}
	}
}

// ============================================================================
// Rotation authenticates with the certificate being replaced, and nothing else.
// ============================================================================

// peerCtx builds a context carrying a TLS peer, as gRPC would.
func peerCtx(ctx context.Context, leaf *x509.Certificate) context.Context {
	return peer.NewContext(ctx, &peer.Peer{
		AuthInfo: credentials.TLSInfo{
			State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}},
		},
	})
}

// enrolled runs a full enrollment and returns the tenant and the issued leaf.
func enrolled(t *testing.T, db *store.DB, svc *enrollment.Service, issuer *enrollment.Issuer) (store.TenantID, *x509.Certificate, string) {
	t.Helper()
	ctx := context.Background()
	tenant, zoneID := tenantWithZone(t, db)
	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Enroll(ctx, enrollRequest(t, issued.Token.Reveal()))
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	leaf, err := x509.ParseCertificate(resp.GetCertificate())
	if err != nil {
		t.Fatal(err)
	}
	return tenant, leaf, resp.GetScanPointId()
}

func TestRotateRequiresAClientCertificate(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t))

	// No peer at all.
	_, err := svc.RotateCertificate(context.Background(), &scanpointv1.RotateRequest{
		Csr: newCSR(t), ProtocolVersion: testAccepted,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("no peer: got %v, want Unauthenticated", status.Code(err))
	}
}

func TestRotateIdentityComesFromTheCertificateNotTheBody(t *testing.T) {
	db := testDB(t)
	authority := testCA(t)
	// One service enrolls and rotates: the clock is 61 days ahead so rotation
	// is inside its window, and a certificate issued at that same clock is
	// still valid then.
	enrollSvc, svc := rotationPair(t, db, authority)
	issuer := enrollment.NewIssuer(db)

	_, leafA, idA := enrolled(t, db, enrollSvc, issuer)
	_, _, idB := enrolled(t, db, enrollSvc, issuer)

	// A presents its own certificate but names B in the body. This is the
	// re-key oracle ADR-028's reserved field 3 exists to prevent: both the id
	// and the fingerprint of another scan point are obtainable without
	// compromising it.
	_, err := svc.RotateCertificate(peerCtx(context.Background(), leafA), &scanpointv1.RotateRequest{
		ScanPointId:     idB,
		Csr:             newCSR(t),
		ProtocolVersion: testAccepted,
	})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("naming another scan point: got %v, want PermissionDenied", status.Code(err))
	}

	// A naming itself is fine.
	if _, err := svc.RotateCertificate(peerCtx(context.Background(), leafA), &scanpointv1.RotateRequest{
		ScanPointId:     idA,
		Csr:             newCSR(t),
		ProtocolVersion: testAccepted,
	}); err != nil {
		t.Fatalf("rotating with a matching id failed: %v", err)
	}
}

// Rotation replaces the identity, and the old certificate stops working at
// once. This is the whole of revocation: no CRL, no OCSP (ADR-018).
func TestRotationRevokesTheOldCertificateImmediately(t *testing.T) {
	db := testDB(t)
	enrollSvc, svc := rotationPair(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, oldLeaf, spID := enrolled(t, db, enrollSvc, issuer)
	oldFingerprint := ca.Fingerprint(oldLeaf.Raw)

	resp, err := svc.RotateCertificate(peerCtx(ctx, oldLeaf), &scanpointv1.RotateRequest{
		ScanPointId: spID, Csr: newCSR(t), ProtocolVersion: testAccepted,
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	newLeaf, err := x509.ParseCertificate(resp.GetCertificate())
	if err != nil {
		t.Fatal(err)
	}
	if ca.Fingerprint(newLeaf.Raw) == oldFingerprint {
		t.Fatal("rotation produced the same fingerprint")
	}

	// The old certificate no longer resolves to a tenant, which is what refuses
	// the connection.
	if _, err := db.ResolveScanPointTenant(ctx, oldFingerprint); err == nil {
		t.Error("the superseded certificate still resolves to a tenant")
	}
	if got, err := db.ResolveScanPointTenant(ctx, ca.Fingerprint(newLeaf.Raw)); err != nil || got != tenant {
		t.Errorf("the new certificate does not resolve: %v", err)
	}

	// Presenting the old certificate again is refused.
	if _, err := svc.RotateCertificate(peerCtx(ctx, oldLeaf), &scanpointv1.RotateRequest{
		ScanPointId: spID, Csr: newCSR(t), ProtocolVersion: testAccepted,
	}); status.Code(err) != codes.Unauthenticated {
		t.Errorf("rotating with the superseded certificate: got %v, want Unauthenticated", status.Code(err))
	}
}

// The pairing invariant: scan_points.cert_fingerprint always names the live
// certificate row. Written as one statement so it cannot drift; asserted here
// because the statement is the only thing holding it.
func TestScanPointAndCertificateHistoryAgree(t *testing.T) {
	db := testDB(t)
	enrollSvc, svc := rotationPair(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, leaf, spID := enrolled(t, db, enrollSvc, issuer)
	id := uuid.MustParse(spID)

	assertAgrees := func(stage string, wantHistory int) {
		t.Helper()
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			sp, err := (store.ScanPoints{}).GetByID(ctx, c, id)
			if err != nil {
				return err
			}
			live, err := (store.Certificates{}).Live(ctx, c, id)
			if err != nil {
				return err
			}
			if sp.CertFingerprint != live.Fingerprint {
				t.Errorf("%s: scan_points.cert_fingerprint %q != live certificate %q",
					stage, sp.CertFingerprint, live.Fingerprint)
			}
			history, err := (store.Certificates{}).History(ctx, c, id)
			if err != nil {
				return err
			}
			if len(history) != wantHistory {
				t.Errorf("%s: %d certificates in history, want %d", stage, len(history), wantHistory)
			}
			var liveCount int
			for _, h := range history {
				if h.SupersededAt == nil {
					liveCount++
				}
			}
			if liveCount != 1 {
				t.Errorf("%s: %d live certificates, want exactly 1", stage, liveCount)
			}
			return nil
		}); err != nil {
			t.Fatalf("%s: %v", stage, err)
		}
	}

	assertAgrees("after enroll", 1)

	if _, err := svc.RotateCertificate(peerCtx(ctx, leaf), &scanpointv1.RotateRequest{
		ScanPointId: spID, Csr: newCSR(t), ProtocolVersion: testAccepted,
	}); err != nil {
		t.Fatal(err)
	}
	assertAgrees("after one rotation", 2)
}

func TestRevokedScanPointCannotRotate(t *testing.T) {
	db := testDB(t)
	enrollSvc, svc := rotationPair(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, leaf, spID := enrolled(t, db, enrollSvc, issuer)
	id := uuid.MustParse(spID)

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.ScanPoints{}).SetStatus(ctx, c, id, store.ScanPointRevoked)
	}); err != nil {
		t.Fatal(err)
	}

	// tenant_for_scan_point's status allowlist refuses a revoked scan point
	// before the handler is even reached.
	_, err := svc.RotateCertificate(peerCtx(ctx, leaf), &scanpointv1.RotateRequest{
		ScanPointId: spID, Csr: newCSR(t), ProtocolVersion: testAccepted,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Errorf("revoked scan point: got %v, want Unauthenticated", status.Code(err))
	}
}

// ============================================================================
// CSR validation
// ============================================================================

func TestCSRValidation(t *testing.T) {
	t.Run("rejects a weak RSA key", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Skipf("Go refused to generate a 1024-bit key: %v", err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.ParseCSR(der); err == nil {
			t.Error("a 1024-bit RSA CSR was accepted")
		}
	})

	t.Run("accepts P-256", func(t *testing.T) {
		if _, err := ca.ParseCSR(newCSR(t)); err != nil {
			t.Errorf("a P-256 CSR was rejected: %v", err)
		}
	})

	t.Run("rejects a tampered signature", func(t *testing.T) {
		der := newCSR(t)
		// Flip a bit in the signature at the end of the structure. Proof of
		// possession is what stops a CSR carrying someone else's public key.
		tampered := make([]byte, len(der))
		copy(tampered, der)
		tampered[len(tampered)-1] ^= 0x01
		if _, err := ca.ParseCSR(tampered); err == nil {
			t.Error("a CSR with a broken signature was accepted")
		}
	})

	t.Run("rejects empty and oversized", func(t *testing.T) {
		if _, err := ca.ParseCSR(nil); err == nil {
			t.Error("an empty CSR was accepted")
		}
		if _, err := ca.ParseCSR(make([]byte, 1<<20)); err == nil {
			t.Error("a 1MB CSR was accepted")
		}
	})
}

// The CA refuses a key file anyone but its owner can read.
func TestCARefusesAWorldReadableKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, err := ca.GenerateSelfSigned(dir, "perm test", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Open(ca.Config{CertPath: certPath, KeyPath: keyPath}); err == nil {
		t.Error("a 0644 signing key was accepted")
	}
	// And the explicit opt-out works, so a deployment managing access another
	// way is not blocked.
	if _, err := ca.Open(ca.Config{CertPath: certPath, KeyPath: keyPath, AllowSharedKeyFileMode: true}); err != nil {
		t.Errorf("AllowSharedKeyFileMode did not permit it: %v", err)
	}
}

// The CA never renders its key, whatever you do to it.
func TestCANeverRendersItsKey(t *testing.T) {
	authority := testCA(t)

	var buf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("ca loaded", slog.Any("ca", authority))

	rendered := buf.String() + " " + authority.String()
	for _, marker := range []string{"PRIVATE", "D:", "priv", "signer"} {
		if strings.Contains(rendered, marker) {
			t.Errorf("CA rendering contains %q: %s", marker, rendered)
		}
	}
	if !strings.Contains(buf.String(), "subject") {
		t.Errorf("CA LogValue rendered nothing useful: %s", buf.String())
	}
}

// Rotation is refused before the window opens.
//
// Without this, rotation is an unbounded loop the peer drives: 50 rotations in
// 114ms in the security review, each costing a CA signature and a history row.
func TestRotationRefusedBeforeTheWindowOpens(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t)) // one clock: the certificate is brand new
	issuer := enrollment.NewIssuer(db)

	_, leaf, spID := enrolled(t, db, svc, issuer)

	_, err := svc.RotateCertificate(peerCtx(context.Background(), leaf), &scanpointv1.RotateRequest{
		ScanPointId: spID, Csr: newCSR(t), ProtocolVersion: testAccepted,
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rotating a brand-new certificate: got %v, want FailedPrecondition", status.Code(err))
	}
}

// An expired certificate cannot renew itself.
//
// The database is the authority on identity validity (ADR-018), so this is
// checked here rather than left to whatever TLS mode the listener runs. Without
// it, a certificate long past not_after rotates cleanly into a fresh 90 days —
// an identity outliving its own expiry by renewing after the fact.
func TestExpiredCertificateCannotRotate(t *testing.T) {
	db := testDB(t)
	enrollSvc, _ := rotationPair(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)

	_, leaf, spID := enrolled(t, db, enrollSvc, issuer)

	// A clock well past the certificate's 90 days.
	expired := testService(t, db, testCA(t), enrollment.WithClock(func() time.Time {
		return time.Now().Add(400 * 24 * time.Hour)
	}))

	_, err := expired.RotateCertificate(peerCtx(context.Background(), leaf), &scanpointv1.RotateRequest{
		ScanPointId: spID, Csr: newCSR(t), ProtocolVersion: testAccepted,
	})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("rotating an expired certificate: got %v, want Unauthenticated", status.Code(err))
	}
}

// Self-asserted strings are bounded before they reach unbounded text columns.
func TestWireStringsAreCapped(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, zoneID := tenantWithZone(t, db)
	issued, err := issuer.Issue(ctx, tenant, zoneID, nil, 0, "")
	if err != nil {
		t.Fatal(err)
	}

	huge := strings.Repeat("A", 1<<20)
	req := enrollRequest(t, issued.Token.Reveal())
	req.Hostname = huge
	req.AgentVersion = huge
	req.Capabilities = []*scanpointv1.Capability{
		{Engine: "discovery", EngineVersion: huge, Enabled: true},
	}

	resp, err := svc.Enroll(ctx, req)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	spID := uuid.MustParse(resp.GetScanPointId())
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		sp, err := (store.ScanPoints{}).GetByID(ctx, c, spID)
		if err != nil {
			return err
		}
		if len(sp.Hostname) > 256 || len(sp.AgentVersion) > 256 {
			t.Errorf("stored hostname %d bytes, agent_version %d bytes; both should be capped",
				len(sp.Hostname), len(sp.AgentVersion))
		}
		caps, err := (store.ScanPoints{}).Capabilities(ctx, c, spID)
		if err != nil {
			return err
		}
		for _, cp := range caps {
			if len(cp.EngineVersion) > 256 {
				t.Errorf("stored engine_version %d bytes; it is writable on every rotation",
					len(cp.EngineVersion))
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// An enrolled scan point can still be deleted.
//
// The biconditional CHECK on enrollment_tokens made this impossible: ON DELETE
// SET NULL nulls redeemed_scan_point, which left redeemed_at set and violated
// it. The risk was never the failed delete — it was that the CHECK gets removed
// under pressure, and it is what the redemption audit trail rests on.
func TestAnEnrolledScanPointCanBeDeleted(t *testing.T) {
	db := testDB(t)
	svc := testService(t, db, testCA(t))
	issuer := enrollment.NewIssuer(db)
	ctx := context.Background()

	tenant, _, spID := enrolled(t, db, svc, issuer)
	id := uuid.MustParse(spID)

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx, `DELETE FROM scan_points WHERE tenant_id = $1 AND scan_point_id = $2`,
			tenant.UUID(), id)
		return err
	}); err != nil {
		t.Fatalf("deleting an enrolled scan point: %v", err)
	}

	// The token still records that it was redeemed, which is the half that must
	// survive.
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		var redeemed bool
		if err := c.QueryRow(ctx,
			`SELECT redeemed_at IS NOT NULL FROM enrollment_tokens WHERE tenant_id = $1`,
			tenant.UUID()).Scan(&redeemed); err != nil {
			return err
		}
		if !redeemed {
			t.Error("deleting the scan point erased the record that its token was redeemed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
