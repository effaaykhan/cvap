// Package enrollment implements the Enrollment service (ADR-005, ADR-018).
//
// Token exchanged exactly once for a client certificate; rotation afterwards
// authenticated by the certificate being replaced. Byte-identical in SaaS and
// on-prem, because the trust anchor is configuration (ADR-018) and there is no
// second code path in the component where ADR-017 would fail first.
//
// # What this package must never do
//
// Log, wrap into an error, or return in a gRPC status: the enrollment token, or
// anything derived from CA key material. The token arrives in a field the
// contract marks debug_redact, which protobuf-go ignores, so the protection is
// PlaintextToken closing every rendering path plus never handing the request
// message to a logging call. See internal/logging/CLAUDE.md and ADR-034.
package enrollment

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/control/ca"
	"github.com/effaaykhan/cvap/internal/store"
)

// Endpoints is what Core tells a scan point about where the other three
// services live.
//
// Stated at enrollment rather than compiled into the agent so that moving ingest
// onto its own hosts is a Core-side change, not a configuration push to every
// scan point in a fleet running months-old builds (ADR-005).
type Endpoints struct {
	Dispatch  string
	Ingest    string
	RulePacks string
}

// VersionWindow is the supported protocol range (ADR-022).
//
// Enforced at enrollment as well as on Hello so a build outside the window
// learns why BEFORE it has an identity, with an operator-facing message, rather
// than enrolling cleanly and failing at the first Connect. Mysterious failure
// inside a network we cannot observe is the thing ADR-022 exists to prevent.
type VersionWindow struct {
	Accepted     string
	MinSupported string
}

// Supported reports whether a declared protocol version may enroll.
//
// Deliberately a simple set membership rather than semver range arithmetic: the
// accepted and minimum values are operator-facing strings from configuration,
// and inventing an ordering over them here would make the answer depend on a
// parser rather than on what an operator configured.
func (w VersionWindow) Supported(v string) bool {
	return v != "" && (v == w.Accepted || v == w.MinSupported)
}

// Clock is injected so certificate validity and token expiry are testable
// without sleeping.
type Clock func() time.Time

// Service implements scanpointv1.EnrollmentServer.
type Service struct {
	scanpointv1.UnimplementedEnrollmentServer

	db        *store.DB
	ca        *ca.CA
	endpoints Endpoints
	versions  VersionWindow
	log       *slog.Logger
	now       Clock
}

// Option adjusts a Service after construction.
type Option func(*Service)

// WithClock replaces the time source.
//
// For tests, which must be able to reach the rotation window without waiting 60
// days. Not a production seam: nothing outside a test should be deciding what
// time it is for certificate validity.
func WithClock(c Clock) Option {
	return func(s *Service) {
		if c != nil {
			s.now = c
		}
	}
}

func New(db *store.DB, authority *ca.CA, endpoints Endpoints, versions VersionWindow, log *slog.Logger, opts ...Option) *Service {
	s := &Service{
		db: db, ca: authority, endpoints: endpoints, versions: versions,
		log: log, now: time.Now,
	}
	for _, o := range opts {
		o(s)
	}
	return s
}

// maxLabelBytes bounds the self-asserted strings a scan point sends.
//
// hostname, agent_version, protocol_version and engine_version all land in
// unbounded `text` columns, and all are attacker-chosen: a scan point sits in a
// network whose compromise the threat model assumes (ADR-020). Without a cap, a
// single enrollment stores megabytes, and engine_version is writable again on
// every rotation. 256 bytes is generous for a hostname and a semver.
const maxLabelBytes = 256

// rotateGrace widens the rotation window so a scan point with a skewed clock, or
// one retrying after a failure, is not locked out of renewing.
const rotateGrace = 24 * time.Hour

// clampLabel truncates rather than refusing.
//
// Refusing would make an over-long hostname a fleet enrollment failure for what
// is a display-only field. Truncation keeps the operator-facing value useful and
// bounds the storage, which is what the cap is for.
func clampLabel(s string) string {
	if len(s) <= maxLabelBytes {
		return s
	}
	return s[:maxLabelBytes]
}

// errEnrollmentRefused is what every enrollment failure returns to the caller.
//
// One message for a malformed token, an unknown token, an expired token, an
// already-redeemed token and a lost race. The caller must not be able to tell
// them apart: a distinguishable error turns Enroll into an oracle for which
// tokens exist, and a scan point has nothing useful to do differently in any of
// those cases anyway. The operator-facing detail goes to the audit log and to
// Core's own logs, where it belongs.
func errEnrollmentRefused() error {
	return status.Error(codes.PermissionDenied, "enrollment refused")
}

// Enroll exchanges a token for a client certificate.
func (s *Service) Enroll(ctx context.Context, req *scanpointv1.EnrollRequest) (*scanpointv1.EnrollResponse, error) {
	// NOTE: req is never logged, never wrapped into an error, and never handed
	// to a formatting verb. It carries the enrollment token in a plain field
	// that the generated String() renders in full.

	// Cheapest refusals first, and each before the token is touched, so a
	// malformed request never consumes one.
	if !s.versions.Supported(req.GetProtocolVersion()) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"protocol version %q is outside the supported window (accepted %q, minimum %q); upgrade the scan point",
			req.GetProtocolVersion(), s.versions.Accepted, s.versions.MinSupported)
	}

	// Token shape BEFORE the CSR, because CSR validation is the expensive half
	// and its cost is partly submitter-chosen (see ca.ParseCSR). Both checks
	// consume nothing, so the ordering does not weaken the "a malformed request
	// never consumes a token" property — it just refuses garbage for a string
	// compare instead of a signature verification.
	token, err := ParseToken(req.GetEnrollmentToken())
	if err != nil {
		return nil, errEnrollmentRefused()
	}
	hash := token.Hash()

	csr, err := ca.ParseCSR(req.GetCsr())
	if err != nil {
		// ca's errors are fixed strings with nothing attacker-derived in them.
		return nil, status.Errorf(codes.InvalidArgument, "certificate request rejected: %v", err)
	}

	// Pre-tenant resolution (ADR-033). Resolution is NOT redemption: this only
	// says which tenant to open a transaction as. Single-use is enforced inside
	// it by the conditional UPDATE.
	tenant, err := s.db.ResolveEnrollmentTokenTenant(ctx, hash)
	if err != nil {
		if errors.Is(err, store.ErrTenantNotResolved) {
			return nil, errEnrollmentRefused()
		}
		s.log.ErrorContext(ctx, "enrollment token resolution failed", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "enrollment unavailable")
	}

	scanPointID := uuid.New()
	var resp *scanpointv1.EnrollResponse

	err = s.db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		// ====================================================================
		// Order inside this transaction, and why it is not the obvious one.
		// ====================================================================
		//
		// The obvious order is redeem-then-create: burn the token first so
		// nothing else can use it. That fails on a foreign key —
		// enrollment_tokens.redeemed_scan_point references scan_points, so the
		// scan point must exist before the token can name it.
		//
		// So the zone is read advisorily, the scan point is created, and the
		// token is redeemed LAST. That is safe because all of it is one
		// transaction: if the redeem matches nothing — already redeemed,
		// expired, or a concurrent caller won — the whole thing rolls back and
		// no scan point survives. The advisory read being stale costs nothing,
		// because the redeem re-checks under a row lock.
		//
		// The single-use guarantee is entirely in that final conditional
		// UPDATE, and moving it earlier would only trade it for a constraint
		// violation.
		zoneID, err := (store.EnrollmentTokens{}).PendingZone(ctx, c, hash)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errEnrollmentRefused()
			}
			return err
		}

		// Sign inside the transaction, so a signing failure rolls everything
		// back rather than burning a token for a certificate never issued.
		der, serial, notBefore, notAfter, err := s.ca.SignScanPoint(csr, scanPointID, s.now())
		if err != nil {
			return err
		}
		fingerprint := ca.Fingerprint(der)

		// The pairing statement: scan point and its first certificate row in
		// one statement, so scan_points.cert_fingerprint and the live
		// certificate cannot diverge. See internal/store/certificates.go.
		//
		// The zone comes from the TOKEN, never from the request. A scan point
		// that could choose its own zone could rewrite the derived exposure of
		// every asset it reports (ADR-008), which is why EnrollRequest has no
		// zone field at all.
		cert, err := (store.Certificates{}).EnrollScanPoint(ctx, c, store.NewScanPoint{
			ScanPointID:     scanPointID,
			ZoneID:          zoneID,
			Hostname:        clampLabel(req.GetHostname()), // operator display only
			AgentVersion:    clampLabel(req.GetAgentVersion()),
			ProtocolVersion: clampLabel(req.GetProtocolVersion()),
			Fingerprint:     fingerprint,
			SerialNumber:    serial,
			NotBefore:       notBefore,
			NotAfter:        notAfter,
		})
		if err != nil {
			return err
		}

		if err := s.recordCapabilities(ctx, c, scanPointID, req.GetCapabilities()); err != nil {
			return err
		}

		// The authoritative single-use gate, and the last thing that can refuse
		// this enrollment. See the note at the top of this transaction.
		redeemed, err := (store.EnrollmentTokens{}).Redeem(ctx, c, hash, scanPointID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errEnrollmentRefused()
			}
			return err
		}

		// Redeem re-read the row under a row lock, so its zone is the
		// authoritative one. It must equal the advisory read; if it ever does
		// not, the scan point has just been created in the wrong zone, which
		// silently corrupts every exposure derived from it (ADR-008). Cheap to
		// check, and the transaction is still open to roll back.
		if redeemed.ZoneID != zoneID {
			return fmt.Errorf("store: token zone changed during enrollment (%s then %s)",
				zoneID, redeemed.ZoneID)
		}

		if err := s.audit(ctx, c, scanPointID, "scan_point.enroll", map[string]any{
			"token_id":    redeemed.TokenID.String(),
			"zone_id":     redeemed.ZoneID.String(),
			"fingerprint": fingerprint,
			"serial":      serial,
			"not_after":   notAfter.UTC().Format(time.RFC3339),
			// The token itself is deliberately absent. token_id identifies which
			// token was used without being one.
		}); err != nil {
			return err
		}

		resp = s.response(scanPointID, der, cert.Fingerprint, notAfter)
		return nil
	})
	if err != nil {
		return nil, s.writeError(ctx, err, "enroll")
	}

	s.log.InfoContext(ctx, "scan point enrolled",
		slog.String("scan_point_id", scanPointID.String()),
		slog.String("cert_fingerprint", resp.GetCertFingerprint()))
	return resp, nil
}

// RotateCertificate issues a new certificate to an already-enrolled scan point.
//
// ============================================================================
// Identity comes from the TLS peer certificate and from NOTHING in the message.
// ============================================================================
//
// RotateRequest.scan_point_id is self-asserted. Field 3 of that message was
// current_fingerprint and is reserved rather than reused (ADR-028): a
// certificate fingerprint is a digest of the public half, returned at enrolment,
// present in audit records, and computable by any peer that completes a
// handshake — so holding one demonstrates nothing. A field shaped like an
// authentication input invites the implementation that checks the body instead
// of the peer certificate, which reads as authentication, passes every test
// written against a well-behaved client, and turns this RPC into a re-key oracle
// for any identity whose id and fingerprint an attacker can obtain.
//
// So: the fingerprint is taken from the connection, resolved through the
// database, and req.scan_point_id is only ever CHECKED against the result.
func (s *Service) RotateCertificate(ctx context.Context, req *scanpointv1.RotateRequest) (*scanpointv1.EnrollResponse, error) {
	peerFingerprint, err := PeerFingerprint(ctx)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "rotation requires a client certificate")
	}

	if !s.versions.Supported(req.GetProtocolVersion()) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"protocol version %q is outside the supported window (accepted %q, minimum %q); upgrade the scan point",
			req.GetProtocolVersion(), s.versions.Accepted, s.versions.MinSupported)
	}

	csr, err := ca.ParseCSR(req.GetCsr())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "certificate request rejected: %v", err)
	}

	// resolveTenant's production caller (ADR-031, ADR-033). This is also the
	// revocation check: a fingerprint scan_points no longer carries resolves to
	// nothing, so a revoked certificate is refused here with no CRL involved.
	tenant, err := s.db.ResolveScanPointTenant(ctx, peerFingerprint)
	if err != nil {
		if errors.Is(err, store.ErrTenantNotResolved) {
			return nil, status.Error(codes.Unauthenticated, "certificate is not enrolled")
		}
		s.log.ErrorContext(ctx, "scan point tenant resolution failed", slog.Any("error", err))
		return nil, status.Error(codes.Internal, "rotation unavailable")
	}

	var resp *scanpointv1.EnrollResponse
	err = s.db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		sp, err := (store.ScanPoints{}).GetByFingerprint(ctx, c, peerFingerprint)
		if err != nil {
			return err
		}

		// The contract's MUST: refuse when the body names a different scan
		// point than the certificate does. Not a security control — the
		// certificate already decided — but a loud failure beats silently
		// ignoring a field, because a scan point sending the wrong id is
		// confused about its own identity and should be told.
		if id := req.GetScanPointId(); id != "" && id != sp.ID.String() {
			return status.Error(codes.PermissionDenied,
				"scan_point_id does not match the presenting certificate")
		}

		if sp.Status == store.ScanPointRevoked || sp.Status == store.ScanPointDisabled {
			return status.Error(codes.PermissionDenied, "scan point is not permitted to rotate")
		}

		// The database is the authority on identity validity (ADR-018), so
		// expiry is checked here and not left entirely to whatever TLS mode the
		// listener runs. Without this, a certificate 310 days past not_after
		// rotates cleanly into a fresh 90 days — an identity that outlived its
		// own expiry by renewing after the fact.
		live, err := (store.Certificates{}).Live(ctx, c, sp.ID)
		if err != nil {
			return err
		}
		now := s.now()
		if now.After(live.NotAfter) || now.Before(live.NotBefore) {
			return status.Error(codes.Unauthenticated,
				"the presented certificate is outside its validity window; re-enroll with a new token")
		}

		// Rotation is expected at 60 of 90 days. Refusing earlier bounds an
		// otherwise unbounded loop: each call costs a CA signature and a history
		// row, both driven by the peer. The grace window keeps a scan point with
		// a slow clock or a retry from being locked out.
		if earliest := live.NotAfter.Add(-(ca.Lifetime - ca.RotateAfter) - rotateGrace); now.Before(earliest) {
			return status.Errorf(codes.FailedPrecondition,
				"too early to rotate; this certificate is valid until %s and rotation opens at %s",
				live.NotAfter.UTC().Format(time.RFC3339), earliest.UTC().Format(time.RFC3339))
		}

		oldFingerprint, err := (store.Certificates{}).Supersede(ctx, c, sp.ID, store.SupersedeRotation)
		if err != nil {
			return err
		}

		der, serial, notBefore, notAfter, err := s.ca.SignScanPoint(csr, sp.ID, s.now())
		if err != nil {
			return err
		}
		fingerprint := ca.Fingerprint(der)

		cert, err := (store.Certificates{}).RotateCertificate(ctx, c, sp.ID,
			fingerprint, serial, notBefore, notAfter)
		if err != nil {
			return err
		}

		if err := s.recordCapabilities(ctx, c, sp.ID, req.GetCapabilities()); err != nil {
			return err
		}

		if err := s.audit(ctx, c, sp.ID, "scan_point.rotate", map[string]any{
			"old_fingerprint": oldFingerprint,
			"new_fingerprint": fingerprint,
			"serial":          serial,
			"not_after":       notAfter.UTC().Format(time.RFC3339),
		}); err != nil {
			return err
		}

		resp = s.response(sp.ID, der, cert.Fingerprint, notAfter)
		return nil
	})
	if err != nil {
		return nil, s.writeError(ctx, err, "rotate")
	}

	s.log.InfoContext(ctx, "scan point rotated certificate",
		slog.String("scan_point_id", resp.GetScanPointId()),
		slog.String("cert_fingerprint", resp.GetCertFingerprint()))
	return resp, nil
}

// PeerFingerprint is the SHA-256 of the client certificate on this connection.
//
// Exported so dispatch and ingest use this exact derivation in session 8. If
// two services compute the fingerprint differently, every scan point fails to
// authenticate against one of them and nothing reports why.
func PeerFingerprint(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", errors.New("enrollment: no peer on context")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", errors.New("enrollment: connection is not mutually authenticated TLS")
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("enrollment: peer presented no certificate")
	}
	return ca.Fingerprint(certs[0].Raw), nil
}

// recordCapabilities stores what the scan point declared.
//
// ============================================================================
// A CEILING, NEVER A GRANT.
// ============================================================================
//
// Capability states what a scan point CAN execute, never what it MAY. Core uses
// it only to WITHHOLD work; authorisation — safety mode, engine enablement,
// policy — comes from Core's own records keyed on the authenticated identity
// (common.proto, and the COMMENT ON COLUMN in migration 0017).
//
// So this function writes to scan_point_capabilities and NOTHING ELSE. It
// creates no policy, enables nothing, and grants nothing. Read as a grant, a
// declaration would let a scan point in a network whose compromise the threat
// model assumes obtain intrusive work by claiming to support it.
//
// An engine name outside the enum is skipped rather than refused: a newer scan
// point declaring an engine this Core has never heard of should still enroll,
// because Core will not dispatch that engine to it regardless. Refusing would
// make every new engine a fleet-wide enrollment outage, which is the failure
// ADR-022's additive-only posture exists to avoid.
func (s *Service) recordCapabilities(ctx context.Context, c *store.Conn, scanPointID uuid.UUID, declared []*scanpointv1.Capability) error {
	for _, d := range declared {
		engine := store.Engine(d.GetEngine())
		if !store.ValidEngine(string(engine)) {
			s.log.WarnContext(ctx, "scan point declared an unknown engine; not recorded",
				slog.String("scan_point_id", scanPointID.String()),
				slog.String("engine", d.GetEngine()))
			continue
		}
		if _, err := (store.ScanPoints{}).DeclareCapability(ctx, c, scanPointID,
			engine, clampLabel(d.GetEngineVersion()), d.GetEnabled()); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) response(scanPointID uuid.UUID, der []byte, fingerprint string, notAfter time.Time) *scanpointv1.EnrollResponse {
	return &scanpointv1.EnrollResponse{
		ScanPointId:             scanPointID.String(),
		Certificate:             der,
		CaChain:                 s.ca.Chain(),
		NotAfterUnix:            notAfter.Unix(),
		CertFingerprint:         fingerprint,
		DispatchEndpoint:        s.endpoints.Dispatch,
		IngestEndpoint:          s.endpoints.Ingest,
		RulepacksEndpoint:       s.endpoints.RulePacks,
		AcceptedProtocolVersion: s.versions.Accepted,
		MinSupportedVersion:     s.versions.MinSupported,
	}
}

func (s *Service) audit(ctx context.Context, c *store.Conn, scanPointID uuid.UUID, action string, detail map[string]any) error {
	return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
		ActorID:      &scanPointID,
		ActorType:    store.ActorScanPoint,
		Action:       action,
		ResourceType: "scan_point",
		ResourceID:   &scanPointID,
		Detail:       detail,
	})
}

// writeError turns an internal failure into something safe to return.
//
// A status the callback already built is passed through; anything else becomes a
// generic Internal, with the real error going to Core's log. Database errors
// carry constraint and column names, which are schema facts, and a scan point in
// a hostile network is the last caller that should receive them.
func (s *Service) writeError(ctx context.Context, err error, op string) error {
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrForeignKey) {
		s.log.WarnContext(ctx, "enrollment write refused",
			slog.String("op", op), slog.Any("error", err))
		return errEnrollmentRefused()
	}
	s.log.ErrorContext(ctx, "enrollment write failed",
		slog.String("op", op), slog.Any("error", err))
	return status.Error(codes.Internal, fmt.Sprintf("%s failed", op))
}
