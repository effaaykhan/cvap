// Package dispatch is the Dispatch service and the job broker behind it.
//
// The broker is internal to Core and has no network path to any scan point
// (ADR-004). Scan points hold a long-lived authenticated stream to this service,
// which pulls from the broker on their behalf; they never learn the broker's
// protocol, address or topic names. That indirection is the seam ADR-003 keeps
// so a broker substitution never touches a scan point.
//
// # Identity
//
// Resolved from the TLS peer certificate on every stream, through the ADR-033
// pre-tenant class. Nothing in any message asserts who the sender is:
// Hello.scan_point_id is an echo, and a mismatch closes the stream rather than
// being trusted or quietly preferred — both readings hide something an operator
// needs to see.
//
// # What does not travel here
//
// Results go to Ingest and rule pack bodies go to RulePacks. Both are bulk, and
// bulk on this stream head-of-line blocks job assignment behind it (ADR-005).
//
// # Registration requirements
//
// When this service is registered on a gRPC server, three things are mandatory
// and none has a safe default:
//
//	tls.RequireAndVerifyClientCert   PeerFingerprint hashes the peer's leaf, and
//	                                 a certificate is PUBLIC. Under
//	                                 RequireAnyClientCert anyone who has seen a
//	                                 scan point's certificate can present it and
//	                                 become that scan point.
//	keepalive.ServerParameters       MaxConnectionAge and MaxConnectionAgeGrace.
//	                                 A peer that answers PINGs but never reads
//	                                 its stream cannot be released by anything
//	                                 else; sendLoop returning frees the handler,
//	                                 and only the transport can free the socket.
//	Sweeper.Run in a goroutine        NOT optional, and not a background nicety.
//	                                 ExpireLeases is where ADR-012's at-most-once
//	                                 rule lives, and a security review found it
//	                                 had no caller: a scan point that died left
//	                                 its job 'running' forever, never retried when
//	                                 retry was safe and never escalated when it
//	                                 was not. Registering Dispatch without the
//	                                 sweeper puts that back. Same for
//	                                 HeartbeatTimeout, which nothing else
//	                                 compares against.
//
// cmd/cvap-core registers nothing yet. When it does, all three go in together.
package dispatch

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/logging"
	"github.com/effaaykhan/cvap/internal/scope"
	"github.com/effaaykhan/cvap/internal/store"
	"github.com/effaaykhan/cvap/internal/target"
)

// Timings from execution-plan §5. Heartbeat every 30s, Core times out at 90s;
// lease TTL 60s with renewal at 20s.
const (
	HeartbeatInterval = 30 * time.Second
	HeartbeatTimeout  = 90 * time.Second

	// pollInterval is how often a connected scan point is offered work. It is
	// deliberately not driven by a database NOTIFY: a poll that misses adds
	// latency, and a NOTIFY that is missed loses the job until something else
	// happens to poll. ADR-003 chose Postgres for dispatch, and polling is the
	// shape that degrades gracefully.
	pollInterval = 2 * time.Second

	// maxJobsPerPoll bounds how much work one scan point is handed at once.
	maxJobsPerPoll = 5

	// sendQueue bounds the outbound buffer per stream. A scan point that stops
	// reading must not make Core grow memory on its behalf — the failure has to
	// land on the connection, not on the process.
	sendQueue = 64
)

// Service implements scanpointv1.DispatchServer.
type Service struct {
	scanpointv1.UnimplementedDispatchServer

	db       *store.DB
	versions enrollment.VersionWindow
	log      *slog.Logger
	now      func() time.Time
}

func New(db *store.DB, versions enrollment.VersionWindow, log *slog.Logger) *Service {
	return &Service{db: db, versions: versions, log: log, now: time.Now}
}

// session is one connected scan point.
type session struct {
	tenant store.TenantID
	spID   uuid.UUID

	// backpressure is the scan point's own signal (ADR-026). It is the ONLY
	// half that can stop the buffer growing, because only dispatch can stop
	// Core handing out more work — an ingest-side signal alone would not be
	// flow control at all.
	backpressure scanpointv1.BackpressureState

	// mu guards backpressure, which the receive loop writes and the pump reads.
	//
	// There was a leases map here, documented as existing "so a renewal can be
	// answered without trusting the message's own claim". It was written and
	// deleted and never read: the actual defence is the holder_scan_point
	// predicate in Leases.Renew, which is sound. A comment describing a defence
	// the code does not implement is worse than no comment, because the next
	// author trusts it.
	mu sync.Mutex
}

// Connect is the long-lived bidirectional stream.
func (s *Service) Connect(stream scanpointv1.Dispatch_ConnectServer) error {
	ctx := stream.Context()

	// Identity first, before a single message is read. A stream that cannot be
	// attributed to a scan point has nothing useful to say.
	fingerprint, err := enrollment.PeerFingerprint(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, "dispatch requires a client certificate")
	}
	tenant, err := s.db.ResolveScanPointTenant(ctx, fingerprint)
	if err != nil {
		if errors.Is(err, store.ErrTenantNotResolved) {
			// Also the revocation path: a fingerprint scan_points no longer
			// carries resolves to nothing, so a revoked scan point is refused
			// here with no CRL involved (ADR-018, ADR-031).
			return status.Error(codes.Unauthenticated, "certificate is not enrolled")
		}
		s.log.ErrorContext(ctx, "dispatch tenant resolution failed", slog.Any("error", err))
		return status.Error(codes.Internal, "dispatch unavailable")
	}

	sess := &session{tenant: tenant}

	// The handshake must be first. A scan point that starts sending heartbeats
	// before Hello has not negotiated a version, and ADR-022 wants an
	// operator-facing refusal rather than a stream that half-works.
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.FailedPrecondition, "the first message on a stream must be Hello")
	}
	if err := s.handshake(ctx, stream, sess, fingerprint, hello); err != nil {
		return err
	}

	// ========================================================================
	// The send loop runs on the HANDLER goroutine. That inversion is the fix
	// for a proven deadlock, not a style choice.
	// ========================================================================
	//
	// Previously the writer was a child goroutine and the handler ran receive,
	// then cancel(), then wg.Wait(). A scan point that half-closes and stops
	// reading wedges that permanently: the transport window fills, the writer
	// parks inside stream.Send, receive returns io.EOF, and cancel() does
	// nothing to a goroutine already blocked in Send — because grpc-go's write
	// quota waits on the STREAM's done channel, which closes when the handler
	// returns. The handler is in wg.Wait(). Circular, and it leaks two
	// goroutines, the session and the RPC per connection, with markOffline never
	// running. N connections from one enrolled scan point is a control-plane DoS.
	//
	// With the send loop on the handler, returning from it IS what unblocks
	// Send, so there is no cycle. receive runs in the child and is unblocked by
	// cancelling its context, which does work: Recv selects on the context.
	//
	// A transport-level backstop is still required when this service is
	// registered — keepalive.ServerParameters{MaxConnectionAge,
	// MaxConnectionAgeGrace} is the only thing that force-closes a peer that
	// answers PINGs but never reads. Noted in the package doc.
	out := make(chan *scanpointv1.CoreMessage, sendQueue)
	urgent := make(chan *scanpointv1.CoreMessage, sendQueue)
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	recvErr := make(chan error, 1)
	go func() { recvErr <- s.receive(streamCtx, stream, sess, out) }()

	go s.pump(streamCtx, sess, out, urgent)

	err = s.sendLoop(streamCtx, stream, out, urgent, recvErr)
	cancel()

	s.markOffline(context.WithoutCancel(ctx), sess)
	return err
}

// sendLoop is the single writer, and it owns the handler goroutine.
//
// It returns when receive reports the stream ended, when a Send fails, or when
// the context is cancelled — and returning is what releases a peer that has
// stopped reading.
func (s *Service) sendLoop(ctx context.Context, stream scanpointv1.Dispatch_ConnectServer, out, urgent <-chan *scanpointv1.CoreMessage, recvErr <-chan error) error {
	send := func(msg *scanpointv1.CoreMessage) error { return stream.Send(msg) }

	for {
		// Drain urgent to empty first. A kill behind a queue of assignments is
		// a kill that misses ADR-024's bound.
		select {
		case msg := <-urgent:
			if err := send(msg); err != nil {
				return err
			}
			continue
		default:
		}

		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-recvErr:
			// The scan point closed, or the receive side failed. Returning
			// here is what unblocks any peer that has stopped reading.
			return err

		case msg := <-urgent:
			if err := send(msg); err != nil {
				return err
			}

		case msg := <-out:
			if err := send(msg); err != nil {
				return err
			}
		}
	}
}

// handshake answers Hello and records what the scan point declared.
func (s *Service) handshake(ctx context.Context, stream scanpointv1.Dispatch_ConnectServer, sess *session, fingerprint string, hello *scanpointv1.Hello) error {
	if !s.versions.Supported(hello.GetProtocolVersion()) {
		// An operator-facing refusal, not a bare status code. A scan point
		// outside the window is in a network we cannot reach to diagnose, and
		// "mysterious failure" is precisely what ADR-022 exists to prevent.
		return status.Errorf(codes.FailedPrecondition,
			"protocol version %q is outside the supported window (accepted %q, minimum %q); "+
				"upgrade the scan point", hello.GetProtocolVersion(),
			s.versions.Accepted, s.versions.MinSupported)
	}

	err := s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		sp, err := (store.ScanPoints{}).GetByFingerprint(ctx, c, fingerprint)
		if err != nil {
			return err
		}

		// Hello.scan_point_id is an ECHO, not an identity. The contract's MUST:
		// close the stream on a mismatch rather than trusting it or quietly
		// preferring the certificate. A mismatch is either our bug or someone's
		// attempt, and both need an operator to see it.
		if claimed := hello.GetScanPointId(); claimed != "" && claimed != sp.ID.String() {
			return status.Error(codes.PermissionDenied,
				"scan_point_id does not match the presenting certificate")
		}

		sess.spID = sp.ID

		// Declared capabilities can only NARROW what Core dispatches. They are
		// recorded, never treated as authorisation (common.proto, migration
		// 0017's COMMENT ON COLUMN).
		for _, d := range hello.GetCapabilities() {
			if !store.ValidEngine(d.GetEngine()) {
				continue
			}
			if _, err := (store.ScanPoints{}).DeclareCapability(ctx, c, sp.ID,
				store.Engine(d.GetEngine()), clamp(d.GetEngineVersion()), d.GetEnabled()); err != nil {
				return err
			}
		}
		return (store.ScanPoints{}).Heartbeat(ctx, c, sp.ID, s.now())
	})
	if err != nil {
		if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
			return err
		}
		s.log.ErrorContext(ctx, "handshake failed", slog.Any("error", err))
		return status.Error(codes.Internal, "handshake failed")
	}

	return stream.Send(&scanpointv1.CoreMessage{
		Msg: &scanpointv1.CoreMessage_ServerHello{
			ServerHello: &scanpointv1.ServerHello{
				AcceptedProtocolVersion: s.versions.Accepted,
				MinSupportedVersion:     s.versions.MinSupported,
			},
		},
	})
}

// receive is the inbound loop.
func (s *Service) receive(ctx context.Context, stream scanpointv1.Dispatch_ConnectServer, sess *session, out chan<- *scanpointv1.CoreMessage) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}

		switch m := msg.Msg.(type) {
		case *scanpointv1.ScanPointMessage_Hello:
			// A second Hello on one stream is a protocol error, not a
			// re-handshake. Allowing it would let a scan point re-declare
			// capabilities mid-stream, which is a shape nothing needs.
			return status.Error(codes.FailedPrecondition, "Hello may be sent once per stream")

		case *scanpointv1.ScanPointMessage_Heartbeat:
			s.onHeartbeat(ctx, sess, m.Heartbeat)

		case *scanpointv1.ScanPointMessage_LeaseRenewal:
			s.onLeaseRenewal(ctx, sess, m.LeaseRenewal, out)

		case *scanpointv1.ScanPointMessage_Progress:
			s.onProgress(ctx, sess, m.Progress)

		case *scanpointv1.ScanPointMessage_Terminal:
			s.onTerminal(ctx, sess, m.Terminal)

		case *scanpointv1.ScanPointMessage_Backpressure:
			s.onBackpressure(ctx, sess, m.Backpressure)

		case *scanpointv1.ScanPointMessage_KillAck:
			s.onKillAck(ctx, sess, m.KillAck)

		case *scanpointv1.ScanPointMessage_CancelAck:
			s.onCancelAck(ctx, sess, m.CancelAck)

		case *scanpointv1.ScanPointMessage_RulePackStatus:
			// RulePacks is session 8. Recorded as seen and otherwise ignored:
			// an unknown-but-valid message must not close the stream, or every
			// protocol addition becomes a fleet outage (ADR-022).

		default:
			s.log.WarnContext(ctx, "unhandled scan point message",
				slog.String("scan_point_id", sess.spID.String()))
		}
	}
}

func (s *Service) onHeartbeat(ctx context.Context, sess *session, hb *scanpointv1.Heartbeat) {
	// observed_rate_pps is an ATTESTATION, not a control. A scan point sending
	// faster than its ceiling can report any number here and nothing in this
	// field slows it down; ADR-024's bound is enforced at planning and on the
	// send path. It is recorded so a rate limiter that is wrong becomes visible
	// before a customer notices, and it is never read as the rate actually sent.
	if err := s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.ScanPoints{}).Heartbeat(ctx, c, sess.spID, s.now())
	}); err != nil {
		s.log.WarnContext(ctx, "heartbeat write failed", slog.Any("error", err))
	}

	if hb.GetBufferedBytes() > 0 {
		s.log.InfoContext(ctx, "scan point buffer",
			slog.String("scan_point_id", sess.spID.String()),
			slog.Uint64("buffered_bytes", hb.GetBufferedBytes()),
			slog.Uint64("buffered_submissions", uint64(hb.GetBufferedSubmissions())))
	}
}

// onLeaseRenewal is the fencing check, answered on the stream.
func (s *Service) onLeaseRenewal(ctx context.Context, sess *session, r *scanpointv1.LeaseRenewal, out chan<- *scanpointv1.CoreMessage) {
	jobID, err := uuid.Parse(r.GetJobId())
	if err != nil {
		s.send(ctx, out, leaseGrant(r.GetJobId(), r.GetLeaseEpoch(), 0,
			scanpointv1.LeaseState_LEASE_STATE_UNKNOWN_JOB, "malformed job id"))
		return
	}

	// ========================================================================
	// Site two for the time dimension of ADR-024 control 1.
	// ========================================================================
	//
	// Core refuses to START a job outside its maintenance window. Nothing at
	// Core stopped one already running: a job claimed at 03:59 under a
	// 22:00-04:00 window renewed every 20 s indefinitely, and the only thing
	// that would ever halt it was window_ends_unix on the wire — a runtime that
	// does not exist yet, running a build we do not control. That is exactly the
	// "enforce at the Scan Point only" alternative ADR-024 rejected, and the
	// target dimension has two sites while the time dimension had one.
	//
	// Refusing the renewal is the lever the architecture already defines:
	// invariant 8 and ADR-012 make a refused renewal a self-abort with
	// credential zeroisation, which is a stronger stop than asking politely.
	// The lease is left for the sweeper rather than released here, so the
	// at-most-once accounting stays in one place.
	windowClosed, why := s.windowClosedForJob(ctx, sess, jobID)
	if windowClosed {
		s.send(ctx, out, leaseGrant(r.GetJobId(), r.GetLeaseEpoch(), 0,
			scanpointv1.LeaseState_LEASE_STATE_LOST, why))
		return
	}

	var granted *store.Lease
	err = s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		// holder_scan_point comes from the resolved session, never the message.
		l, err := (store.Leases{}).Renew(ctx, c, jobID, r.GetLeaseEpoch(), sess.spID, store.LeaseTTL)
		if err != nil {
			return err
		}
		granted = l
		return nil
	})
	if err == nil {
		s.send(ctx, out, leaseGrant(r.GetJobId(), granted.Epoch, granted.ExpiresAt.Unix(),
			scanpointv1.LeaseState_LEASE_STATE_GRANTED, ""))
		return
	}
	if !errors.Is(err, store.ErrNotFound) {
		s.log.ErrorContext(ctx, "lease renewal failed", slog.Any("error", err))
		return
	}

	// Refused. The read below chooses the operator-facing message ONLY — the
	// decision was already made by the conditional UPDATE matching nothing.
	state := scanpointv1.LeaseState_LEASE_STATE_UNKNOWN_JOB
	detail := "Core has no record of this job"
	_ = s.db.Read(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		cur, err := (store.Leases{}).Current(ctx, c, jobID)
		if err != nil {
			return nil
		}
		state = scanpointv1.LeaseState_LEASE_STATE_LOST
		switch {
		case cur.Epoch > r.GetLeaseEpoch():
			detail = fmt.Sprintf("superseded: epoch %d has been issued", cur.Epoch)
		case cur.HolderID != sess.spID:
			detail = "this lease is held by another scan point"
		default:
			detail = "the lease expired"
		}
		return nil
	})

	s.send(ctx, out, leaseGrant(r.GetJobId(), r.GetLeaseEpoch(), 0, state, detail))
}

// windowClosedForJob reports whether this job's policy has left its maintenance
// window, and the operator-facing reason if so.
//
// Fail-OPEN on a read error, deliberately, and this is the one place in the
// change where that is right: a database blip must not mass-revoke the leases of
// every job in flight, which would self-abort the fleet and zeroise its
// credentials over a transient. The start-side check is the one that must fail
// closed, and it does — it withholds work rather than stopping it. A policy that
// cannot be read here simply keeps its lease until the next renewal.
func (s *Service) windowClosedForJob(ctx context.Context, sess *session, jobID uuid.UUID) (bool, string) {
	var policy *store.JobPolicy
	if err := s.db.Read(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		p, err := (store.Policies{}).ForJob(ctx, c, jobID)
		if err != nil {
			return err
		}
		policy = p
		return nil
	}); err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			s.log.WarnContext(ctx, "could not read a policy to check its maintenance window",
				slog.String("job_id", jobID.String()), slog.Any("error", err))
		}
		return false, ""
	}
	if len(policy.TimeWindows) == 0 {
		return false, ""
	}

	windows, err := parseWindows(policy.TimeWindows)
	if err != nil {
		// The start side refuses this job with an audit event naming the policy
		// (refuseJob). Revoking an in-flight lease for the same reason would
		// halt work that was authorised when it started, so the running job is
		// left alone and the scan stops at its next claim instead.
		return false, ""
	}
	if _, open := windowEnd(windows, s.now()); open {
		return false, ""
	}
	return true, "the policy's maintenance window has closed"
}

func (s *Service) onProgress(ctx context.Context, sess *session, p *scanpointv1.JobProgress) {
	jobID, err := uuid.Parse(p.GetJobId())
	if err != nil {
		return
	}
	if err := s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Jobs{}).MarkRunning(ctx, c, jobID, sess.spID)
	}); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.log.WarnContext(ctx, "progress write failed", slog.Any("error", err))
	}
}

// onTerminal records how a job ended. The results themselves go to Ingest.
func (s *Service) onTerminal(ctx context.Context, sess *session, t *scanpointv1.JobTerminal) {
	jobID, err := uuid.Parse(t.GetJobId())
	if err != nil {
		return
	}

	reason := terminationReason(t.GetReason())
	err = s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Jobs{}).Terminate(ctx, c, jobID, sess.spID, reason); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			return err
		}
		if err := (store.Leases{}).Release(ctx, c, jobID, t.GetLeaseEpoch(), sess.spID, store.LeaseReleased); err != nil &&
			!errors.Is(err, store.ErrNotFound) {
			return err
		}

		// JobTerminal.detail is PERSISTED, for every abnormal reason.
		//
		// The proto defines it as "operator-facing detail: which engine failed,
		// which target halted the scan", the runtime fills it in — and Core read
		// it nowhere at all, so every one of those sentences was dropped on
		// arrival. An ADR-compliance pass found it, and it matters most for the
		// case ADR-044 corrects: a canonicalisation mismatch and a scope
		// violation share SCOPE_VIOLATION_HALT, and this field is the only thing
		// that tells them apart.
		//
		// Not recorded for an ordinary completion: an event per finished job is
		// noise that makes the abnormal ones harder to find, and there is
		// nothing to say about a job that ended the way it was meant to.
		if reason != store.TerminationCompleted {
			detail := map[string]any{"reason": string(reason)}
			if d := t.GetDetail(); d != "" {
				// Bounded. It arrives from the network and lands in jsonb that
				// an operator UI renders.
				detail["detail"] = truncate(d, MaxTerminalDetail)
			}
			if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
				ActorID:      &sess.spID,
				ActorType:    store.ActorScanPoint,
				Action:       "job.terminated",
				ResourceType: "scan_job",
				ResourceID:   &jobID,
				Detail:       detail,
			}); err != nil {
				return err
			}
		}

		// credentials_zeroised is an ATTESTATION. A compromised scan point can
		// set it and lie, and nothing here would catch that. It exists to catch
		// OUR bugs: ADR-020 requires zeroisation on completion, lease loss and
		// abort, and an invariant nothing ever asserts is one nothing notices
		// the loss of. So an audit event when it is absent — an unchecked field
		// would be worse than no field at all.
		if !t.GetCredentialsZeroised() {
			if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
				ActorID:      &sess.spID,
				ActorType:    store.ActorScanPoint,
				Action:       "scan_point.credentials_not_attested",
				ResourceType: "scan_job",
				ResourceID:   &jobID,
				Detail: map[string]any{
					"reason": string(reason),
					"note":   "JobTerminal arrived without credentials_zeroised; ADR-020 requires zeroisation on every terminal path",
				},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.log.ErrorContext(ctx, "terminal write failed", slog.Any("error", err))
	}

}

func (s *Service) onBackpressure(ctx context.Context, sess *session, b *scanpointv1.Backpressure) {
	sess.mu.Lock()
	sess.backpressure = b.GetState()
	sess.mu.Unlock()

	s.log.InfoContext(ctx, "scan point backpressure",
		slog.String("scan_point_id", sess.spID.String()),
		slog.String("state", b.GetState().String()),
		slog.Uint64("buffered_bytes", b.GetBufferedBytes()))
}

func (s *Service) onKillAck(ctx context.Context, sess *session, a *scanpointv1.KillAck) {
	killID, err := uuid.Parse(a.GetKillId())
	if err != nil {
		return
	}
	if err := s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.KillSwitches{}).Ack(ctx, c, killID, sess.spID, clampCount(a.GetTasksHalted()))
	}); err != nil {
		s.log.ErrorContext(ctx, "kill ack write failed", slog.Any("error", err))
	}
}

// onCancelAck records that a scan point stopped a job it was told to stop.
//
// ADR-024 requires KillAck because "a 10-second bound Core cannot measure is not
// a control", and the argument does not weaken when the blast radius narrows:
// until this existed, "cancellation sent" was the last thing Core knew about a
// runaway scan, and a scan point that dropped the message looked exactly like
// one that halted.
//
// The scan point is taken from the resolved session and never from the message,
// for the reason Jobs.Terminate carries in its own comment — an ack attributed
// to whoever the sender named lets one scan point answer for another.
func (s *Service) onCancelAck(ctx context.Context, sess *session, a *scanpointv1.CancelAck) {
	jobID, err := uuid.Parse(a.GetJobId())
	if err != nil {
		return
	}
	if err := s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.CancelAcks{}).Record(ctx, c, jobID, sess.spID,
			a.GetLeaseEpoch(), clampCount(a.GetTasksHalted()))
	}); err != nil {
		// ErrNotFound means the acknowledgement was not owed: no unreleased
		// lease on that job at that epoch held by this scan point, under a scan
		// that is actually stopped — or the row is simply already there after a
		// reconnect. Neither is a Core fault and neither is rare, so it is not a
		// Warn; the operator-facing signal is CancelAcks.Unacknowledged, and a
		// refused ack leaves the job in it, which is the conservative answer.
		level := slog.LevelWarn
		if errors.Is(err, store.ErrNotFound) {
			level = slog.LevelDebug
		}
		s.log.Log(ctx, level, "cancel ack was not recorded",
			slog.String("scan_point_id", sess.spID.String()),
			slog.String("job_id", a.GetJobId()),
			slog.Int64("lease_epoch", a.GetLeaseEpoch()),
			slog.Any("error", err))
	}
}

// pump is the outbound loop: offer work, propagate kills.
func (s *Service) pump(ctx context.Context, sess *session, out, urgent chan<- *scanpointv1.CoreMessage) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	sentKills := map[uuid.UUID]bool{}
	sentCancels := map[uuid.UUID]bool{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Kills first, always. A kill switch queued behind job assignment is a
		// kill switch that misses its 10-second bound (ADR-024).
		s.propagateKills(ctx, sess, urgent, sentKills)

		// Then cancellations, also on the urgent channel and also ahead of any
		// assignment. Same reasoning, narrower blast radius: this stops one
		// runaway scan instead of halting the fleet.
		s.propagateCancellations(ctx, sess, urgent, sentCancels)

		sess.mu.Lock()
		bp := sess.backpressure
		sess.mu.Unlock()

		// HARD means the scan point's buffer is near its ceiling: assign
		// nothing. SOFT means assign fewer. This is the only half of ADR-026's
		// flow control that can stop the buffer growing.
		limit := maxJobsPerPoll
		switch bp {
		case scanpointv1.BackpressureState_BACKPRESSURE_STATE_HARD:
			continue
		case scanpointv1.BackpressureState_BACKPRESSURE_STATE_SOFT:
			limit = 1
		}

		s.offerWork(ctx, sess, out, limit)
	}
}

func (s *Service) propagateKills(ctx context.Context, sess *session, urgent chan<- *scanpointv1.CoreMessage, sent map[uuid.UUID]bool) {
	var kills []store.KillSwitch
	if err := s.db.Read(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		// LiveFor, not an unscoped Live: Core decides which scan points a kill
		// covers. A scan point sits in a network whose compromise the threat
		// model assumes (ADR-020), and the one message it must never be able to
		// talk itself out of is the one that stops it.
		kills, err = (store.KillSwitches{}).LiveFor(ctx, c, sess.spID)
		return err
	}); err != nil {
		s.log.ErrorContext(ctx, "kill switch read failed", slog.Any("error", err))
		return
	}
	for _, k := range kills {
		if sent[k.ID] {
			continue
		}
		// Mark sent only if it was actually QUEUED. Marking before the attempt
		// meant a kill dropped by a full queue was never re-offered on that
		// stream — and the scan point with a full outbound queue is by
		// definition the one not draining messages, which is the one that most
		// needs halting. Left unmarked, the next tick tries again.
		if s.trySend(urgent, &scanpointv1.CoreMessage{
			Msg: &scanpointv1.CoreMessage_Kill{
				Kill: &scanpointv1.KillSwitch{
					KillId: k.ID.String(),
					// How much of what this scan point holds to halt. Delivery
					// is already narrowed by LiveFor; this says what the
					// operator meant, so a per-scan kill does not read as a
					// fleet-wide one. A scope Core cannot express halts
					// everything, which is what a bare kill_id meant before the
					// field existed.
					Scope: killScope(k.Scope),
				},
			},
		}) {
			sent[k.ID] = true
			continue
		}
		s.log.WarnContext(ctx, "kill switch could not be queued; will retry next tick",
			slog.String("scan_point_id", sess.spID.String()),
			slog.String("kill_id", k.ID.String()))
	}
}

// cancelGraceMs is the runtime's SIGTERM-then-SIGKILL window for engine
// processes on cancellation.
//
// ADR-027 fixes the mechanism and not the number; ADR-024 bounds the whole
// propagation at 10 s. Five seconds leaves room for the message to arrive and
// the runtime to act inside that bound, and an engine given five seconds to
// close a socket cleanly is one that does not leave a half-open connection on a
// device the fragile flag exists to protect.
const cancelGraceMs = 5000

// propagateCancellations sends CancelJob for this scan point's jobs whose scan
// an operator has cancelled.
//
// It mirrors propagateKills including the retry: sent is marked only when the
// message was actually QUEUED, because a scan point with a full outbound queue
// is by definition the one not draining messages, and therefore the one whose
// runaway job most needs stopping. Marked before the attempt, a cancellation
// dropped by a full queue would never be re-offered on that stream.
func (s *Service) propagateCancellations(ctx context.Context, sess *session, urgent chan<- *scanpointv1.CoreMessage, sent map[uuid.UUID]bool) {
	var jobs []store.CancellableJob
	if err := s.db.Read(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		var err error
		jobs, err = (store.Jobs{}).CancellableFor(ctx, c, sess.spID)
		return err
	}); err != nil {
		s.log.ErrorContext(ctx, "cancellation read failed", slog.Any("error", err))
		return
	}

	for _, j := range jobs {
		if sent[j.JobID] {
			continue
		}
		if s.trySend(urgent, &scanpointv1.CoreMessage{
			Msg: &scanpointv1.CoreMessage_Cancel{
				Cancel: &scanpointv1.CancelJob{
					JobId: j.JobID.String(),
					// The incarnation Core means, not whatever is running under
					// that job id after a reassignment.
					LeaseEpoch: j.Epoch,
					// Which of the two happened, not a generic word for both.
					// An operator reading "cancelled" about a scan they killed
					// has been told something untrue about their own action, and
					// this string reaches the audit log.
					Reason:  "scan " + j.ScanID.String() + " was " + string(j.ScanStatus),
					GraceMs: cancelGraceMs,
				},
			},
		}) {
			sent[j.JobID] = true
			s.log.InfoContext(ctx, "cancellation sent",
				slog.String("scan_point_id", sess.spID.String()),
				slog.String("job_id", j.JobID.String()),
				slog.String("scan_id", j.ScanID.String()),
				slog.String("scan_status", string(j.ScanStatus)),
				slog.Int64("lease_epoch", j.Epoch))
			continue
		}
		s.log.WarnContext(ctx, "cancellation could not be queued; will retry next tick",
			slog.String("scan_point_id", sess.spID.String()),
			slog.String("job_id", j.JobID.String()))
	}
}

// errOutOfScope marks a job refused by the Core-side scope check.
var errOutOfScope = errors.New("dispatch: job refused by the Core-side scope check")

// refuseJob ends a job Core will not dispatch, and records why.
//
// Terminal rather than left queued, because a job Core refuses will be refused
// identically on every poll: leaving it claimable is a two-second loop that
// stops after MaxAttempts and takes the reason with it.
//
// The audit event is the point. A safety audit observed that the previous
// version logged to slog and dispatched anyway, and that an operator reads the
// audit log and the UI rather than Core's stdout — so a scan that stopped
// because of a scope defect looked like a scan that had stalled. The lease is
// released in the same transaction so the sweeper has nothing to find.
func (s *Service) refuseJob(ctx context.Context, c *store.Conn, jobID, spID uuid.UUID, policy *store.JobPolicy, why string) error {
	s.log.ErrorContext(ctx, "job refused by the Core-side scope check",
		slog.String("job_id", jobID.String()),
		slog.String("scan_point_id", spID.String()),
		slog.String("policy_id", policy.ID.String()),
		slog.String("policy", policy.Name),
		slog.String("reason", why))

	// scope_violation_halt is documented in migration 0005 as the scan-point
	// side refusing a target. A Core-side refusal is the same class of event and
	// wants the same visibility; the enum value carries both, and this comment
	// is here so the widening is deliberate rather than assumed.
	if err := (store.Jobs{}).Terminate(ctx, c, jobID, spID, store.TerminationScopeViolationHalt); err != nil &&
		!errors.Is(err, store.ErrNotFound) {
		return err
	}

	id := jobID
	return (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
		ActorType:    store.ActorSystem,
		Action:       "job.scope_refused",
		ResourceType: "scan_job",
		ResourceID:   &id,
		Detail: map[string]any{
			"policy_id":     policy.ID.String(),
			"policy":        policy.Name,
			"reason":        why,
			"scan_point_id": spID.String(),
		},
	})
}

// offerWork claims jobs and assigns them, granting a lease for each.
//
// The claim and the lease are ONE transaction: a job marked assigned with no
// lease is a job nothing will ever expire, and it would sit in that state until
// someone noticed.
func (s *Service) offerWork(ctx context.Context, sess *session, out chan<- *scanpointv1.CoreMessage, limit int) {
	var assignments []*scanpointv1.JobAssignment

	// One clock for the whole pass. Both the claim predicate and the
	// window_ends_unix on the constraints are computed from it, so the two
	// cannot disagree about whether a maintenance window is open — which is the
	// only way a job could be claimed inside its window and then have an end
	// already in the past put on the wire.
	now := s.now()

	err := s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		caps, err := (store.ScanPoints{}).Capabilities(ctx, c, sess.spID)
		if err != nil {
			return err
		}
		// The capability ceiling from Core's side: never dispatch an engine
		// this scan point has not declared and enabled. Withholding only.
		var engines []store.Engine
		for _, cp := range caps {
			if cp.Enabled {
				engines = append(engines, cp.Engine)
			}
		}
		if len(engines) == 0 {
			return nil
		}

		// ADR-024 in the time dimension. Jobs under a policy that is outside its
		// maintenance window right now are not claimed at all, which leaves them
		// QUEUED for the window to open — claiming and then releasing would burn
		// an attempt every two seconds and hit MaxAttempts inside ten, so the
		// window would destroy the scan it was written to protect.
		closed, err := s.windowClosedPolicies(ctx, c, now)
		if err != nil {
			return err
		}

		jobs, err := (store.Jobs{}).Claim(ctx, c, sess.spID, engines, limit, closed)
		if err != nil {
			return err
		}

		for _, j := range jobs {
			lease, err := (store.Leases{}).Grant(ctx, c, j.ID, sess.spID, store.LeaseTTL)
			if err != nil {
				return err
			}
			tasks, err := (store.Jobs{}).Tasks(ctx, c, j.ID)
			if err != nil {
				return err
			}

			// Per job, not per stream: two jobs on one scan point can belong to
			// scans under different policies, and one policy's lowered ceiling
			// must not leak onto the other's work in either direction.
			policy, err := (store.Policies{}).ForJob(ctx, c, j.ID)
			if err != nil {
				return err
			}
			rules, err := (store.Policies{}).ScopeRules(ctx, c, policy.ID)
			if err != nil {
				return err
			}
			constraints, cerr := constraintsFor(policy, rules, now)
			if cerr != nil {
				// A policy whose rules cannot be expressed on the wire produces
				// no assignment at all. Failing the job is deliberate: the
				// alternative is dispatching one the scan point must refuse,
				// which burns an attempt each poll and goes silent after
				// MaxAttempts — a scan that stops for a reason nobody recorded.
				if err := s.refuseJob(ctx, c, j.ID, sess.spID, policy, cerr.Error()); err != nil {
					return err
				}
				continue
			}

			// ================================================================
			// Site one of ADR-024 control 1, checked here and again at the scan
			// point. Neither side trusts the other.
			// ================================================================
			//
			// scan_tasks.task_target is free text and Jobs.Claim authorises the
			// parent scan_targets row, not the decomposed value, so a planning
			// bug can put a target in a task that its scan was never authorised
			// for. Until this existed the allowlist Core computed was advisory:
			// put on the wire, compared against nothing, and enforced only by a
			// runtime that is not written yet. That is precisely the
			// "enforce at the Scan Point only" alternative ADR-024 rejected.
			for _, t := range tasks {
				// Canonicalised at planning and re-computed here, because a
				// row can be written by something that skipped planning:
				// scan_tasks.task_target is free text with no constraint tying
				// it to its scan_targets row. The scan point runs the same
				// comparison again on its own machine (ADR-024, ADR-044).
				canon, canonical := target.Matches(t.TaskTarget)
				ok, why := canonical, "target is not in canonical form"
				if canonical {
					ok, why = scope.Permits(canon, constraints.GetAllowedTargets(), constraints.GetExclusions())
				}
				if ok {
					continue
				}
				if err := s.refuseJob(ctx, c, j.ID, sess.spID, policy,
					fmt.Sprintf("task %s target %q is out of policy scope: %s", t.ID, t.TaskTarget, why)); err != nil {
					return err
				}
				cerr = errOutOfScope
				break
			}
			if cerr != nil {
				continue
			}

			// ADR-021. Recorded when intrusive work actually goes out, which is
			// a different fact from the operator selecting it: the selection
			// event says what was authorised, this says what was dispatched and
			// to which scan point. The mode here is already the LOWER of the
			// policy ceiling and the scan's opt-in, so an event appearing at all
			// means both halves said intrusive.
			if constraints.GetSafetyMode() == string(store.SafetyIntrusive) {
				id := j.ID
				if err := (store.AuditEvents{}).Record(ctx, c, store.AuditEvent{
					ActorType:    store.ActorSystem,
					Action:       "job.intrusive_dispatched",
					ResourceType: "scan_job",
					ResourceID:   &id,
					Detail: map[string]any{
						"policy_id":          policy.ID.String(),
						"policy":             policy.Name,
						"policy_safety_mode": string(policy.SafetyMode),
						"scan_safety_mode":   string(policy.ScanSafetyMode),
						"scan_point_id":      sess.spID.String(),
						"scan_id":            j.ScanID.String(),
					},
				}); err != nil {
					return err
				}
			}

			wire := &scanpointv1.JobAssignment{
				JobId:            j.ID.String(),
				Engine:           string(j.Engine),
				LeaseEpoch:       lease.Epoch,
				LeaseExpiresUnix: lease.ExpiresAt.Unix(),
				ReassignSafe:     j.ReassignSafe,
				Constraints:      constraints,
			}
			for _, t := range tasks {
				wire.Tasks = append(wire.Tasks, &scanpointv1.Task{
					TaskId: t.ID.String(),
					Target: t.TaskTarget,
					// ADR-024 control 3. Without this the runtime is told
					// fragile_rate_pps on the constraints and never told which
					// task it applies to, so a fragile device is scanned at the
					// per-target rate — a ceiling with no subject.
					Fragile: t.Fragile,
				})
			}
			assignments = append(assignments, wire)

		}
		return nil
	})
	if err != nil {
		s.log.ErrorContext(ctx, "job assignment failed", slog.Any("error", err))
		return
	}

	for _, a := range assignments {
		s.send(ctx, out, &scanpointv1.CoreMessage{
			Msg: &scanpointv1.CoreMessage_Job{Job: a},
		})
	}
}

// markOffline records that the stream ended.
func (s *Service) markOffline(ctx context.Context, sess *session) {
	if sess.spID == uuid.Nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := s.db.Write(ctx, sess.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.ScanPoints{}).SetStatus(ctx, c, sess.spID, store.ScanPointOffline)
	}); err != nil {
		s.log.WarnContext(ctx, "could not mark scan point offline", slog.Any("error", err))
	}
}

// send queues an outbound message, dropping rather than blocking if the scan
// point has stopped reading.
//
// Dropping is right: blocking here would let one unresponsive scan point stall
// the goroutine that also propagates kill switches, and a full queue already
// means this scan point is not acting on what it has been sent.
func (s *Service) send(ctx context.Context, out chan<- *scanpointv1.CoreMessage, msg *scanpointv1.CoreMessage) {
	// No ctx.Done() case: Go picks uniformly among ready cases, so a select with
	// both `out <- msg` and `<-ctx.Done()` can take the cancellation branch and
	// drop a message even when the queue has room. `default` already makes this
	// non-blocking, which is all it needed.
	select {
	case out <- msg:
	default:
		// logging.Proto, never slog.Any: CoreMessage's oneof can carry a
		// CredentialGrant, whose generated String() renders the material in
		// full (ADR-034, internal/logging/CLAUDE.md).
		s.log.WarnContext(ctx, "outbound queue full; message dropped",
			logging.ProtoAttr("dropped", msg))
	}
}

// trySend queues without blocking and reports whether it succeeded, so a caller
// that must retry — the kill switch — can tell the difference between sent and
// dropped. send() cannot: it drops silently by design.
func (s *Service) trySend(ch chan<- *scanpointv1.CoreMessage, msg *scanpointv1.CoreMessage) bool {
	select {
	case ch <- msg:
		return true
	default:
		return false
	}
}

func leaseGrant(jobID string, epoch, expires int64, state scanpointv1.LeaseState, detail string) *scanpointv1.CoreMessage {
	return &scanpointv1.CoreMessage{
		Msg: &scanpointv1.CoreMessage_Lease{
			Lease: &scanpointv1.LeaseGrant{
				JobId:            jobID,
				LeaseEpoch:       epoch,
				LeaseExpiresUnix: expires,
				State:            state,
				Detail:           detail,
			},
		},
	}
}

// defaultConstraints carries ADR-024's platform ceilings to the scan point.
//
// A ceiling that does not reach the component sending packets is decorative, so
// every one of these travels. ADR-024 is the authority for the numbers and they
// are not restated anywhere else; policies may LOWER them and never raise them.
// Platform ceilings, from ADR-024's table. That ADR is the authority; these are
// the one copy in Go, named rather than inline so the next reader can find them.
const (
	platformMaxRatePPS             = 1000
	platformMaxRatePerTarget       = 50
	platformFragileRatePPS         = 10
	platformMaxConcurrentPerTarget = 20
	platformConnectTimeoutMs       = 3000
)

// constraintsFor derives what one job's scan point is allowed to do.
//
// ============================================================================
// min(platform, policy). It was platform alone, which inverts ADR-024.
// ============================================================================
//
// The old defaultConstraints() returned the platform table and nothing else, so
// a policy that lowered the rate to 50 pps was handed 1,000 — twenty times what
// its operator asked for, against an estate they had reason to be careful with.
// ADR-024 control 2 is "a policy may LOWER and may never RAISE"; taking the
// minimum honours both halves in one expression, and a policy value above the
// ceiling is ignored rather than trusted. The column's CHECK bounds it too, and
// that duplication is deliberate: a ceiling enforced in one place is decorative,
// and the place that must never be wrong is the one deciding what goes on the
// wire.
//
// The per-target limits are clamped to the per-scan-point rate as well. A
// per-target ceiling above the whole scan point's budget is not just meaningless
// — it is dangerous, because a runtime reading max_rate_per_target = 50 while
// the scan point ceiling is 5 has been told it may send ten times the rate at a
// single host. Fragile is clamped again beneath that, since ADR-024 control 3
// says it caps rate REGARDLESS of what the policy permits.
//
// safety_mode is not a quantity, so it is not minimised arithmetically — but it
// is still reduced, by ADR-021's other axis. The POLICY sets the ceiling and the
// SCAN opts in beneath it, and intrusive travels only when both say so. A policy
// left on intrusive after a test window authorises nothing on its own, which is
// the failure ADR-021 was written against; hardcoding "safe" was the opposite
// failure and looked like everything working.
//
// max_concurrent_per_target joins the minimum as of migration 0024. It is a
// separate lever rather than a derivative of the rate: a host answering 20
// simultaneous connects at 5 pps is under more pressure than one answering a
// single connection at 50 pps, and connection count is what tips a printer over.
// An operator who lowered max_rate_pps to protect a fragile estate was still
// being handed 20 concurrent connections per host.
//
// now is passed rather than read, so that the maintenance-window decision made
// here is the same one Jobs.Claim was given. Two clocks would let a job be
// claimed inside its window and dispatched with an end already in the past.
func constraintsFor(p *store.JobPolicy, rules []store.ScopeRule, now time.Time) (*scanpointv1.ScanConstraints, error) {
	rate := uint32(platformMaxRatePPS)
	if p != nil && p.MaxRatePPS != nil {
		// Bounded as int BEFORE any conversion. The value comes from a column,
		// and a negative or oversized row converted to uint32 would wrap into a
		// huge ceiling — the one direction ADR-024 forbids, arrived at by an
		// integer overflow rather than by anybody's decision. The column's CHECK
		// bounds it as well; this is the half that does not trust the database.
		if v := *p.MaxRatePPS; v > 0 && v < platformMaxRatePPS {
			rate = uint32(v)
		}
	}

	perTarget := min(uint32(platformMaxRatePerTarget), rate)
	fragile := min(uint32(platformFragileRatePPS), perTarget)

	concurrent := uint32(platformMaxConcurrentPerTarget)
	if p != nil && p.MaxConcurrentPerTarget != nil {
		// Bounded as int BEFORE any conversion, for the reason max_rate_pps is:
		// a negative or oversized row converted to uint32 wraps into a huge
		// ceiling, which is the one direction ADR-024 forbids, arrived at by an
		// integer overflow rather than by anybody's decision.
		if v := *p.MaxConcurrentPerTarget; v > 0 && v < platformMaxConcurrentPerTarget {
			concurrent = uint32(v)
		}
	}

	mode := string(store.SafetySafe)
	if p != nil && p.SafetyMode == store.SafetyIntrusive && p.ScanSafetyMode == store.SafetyIntrusive {
		mode = string(store.SafetyIntrusive)
	}

	allowed, exclusions, err := scopePlan(rules)
	if err != nil {
		return nil, err
	}

	var windowEnds int64
	if p != nil {
		windows, werr := parseWindows(p.TimeWindows)
		if werr != nil {
			// Fails the job, with the audit event refuseJob writes. Same
			// posture as an unexpressible scope rule: a restriction nobody can
			// evaluate must not become no restriction, and it must not stop the
			// scan silently either.
			return nil, fmt.Errorf("policy time_windows: %w", werr)
		}
		end, open := windowEnd(windows, now)
		if !open {
			// Unreachable when the caller is offerWork: the same windows were
			// evaluated against the same `now` to build Jobs.Claim's exclusion
			// list, so a closed policy's jobs were never claimed. Kept as a
			// consistency check rather than an assumption, because the cost of
			// being wrong is packets outside a maintenance window.
			return nil, fmt.Errorf("policy is outside its maintenance window at %s", now.UTC().Format(time.RFC3339))
		}
		if !end.IsZero() {
			windowEnds = end.Unix()
		}
	}

	return &scanpointv1.ScanConstraints{
		MaxRatePps:             rate,
		MaxRatePerTarget:       perTarget,
		FragileRatePps:         fragile,
		MaxConcurrentPerTarget: concurrent,
		ConnectTimeoutMs:       platformConnectTimeoutMs,
		SafetyMode:             mode,
		AllowedTargets:         allowed,
		Exclusions:             exclusions,
		// 0 when the policy sets no window: unrestricted, the opposite
		// convention to allowed_targets and for the reason ADR-037 gives.
		WindowEndsUnix: windowEnds,
	}, nil
}

// windowClosedPolicies lists the tenant's policies that are outside their
// maintenance window at now, for Jobs.Claim to exclude.
//
// A policy whose windows cannot be parsed is deliberately NOT excluded. Excluding
// it would leave its jobs queued forever with nothing said about why; leaving it
// in means the job is claimed, constraintsFor refuses it, and refuseJob
// terminates it with an audit event naming the policy. A scan that stops has to
// say so — the same choice scope.go makes for a rule it cannot express.
func (s *Service) windowClosedPolicies(ctx context.Context, c *store.Conn, now time.Time) ([]uuid.UUID, error) {
	windowed, err := (store.Policies{}).WithTimeWindows(ctx, c)
	if err != nil {
		return nil, err
	}

	var closed []uuid.UUID
	for _, w := range windowed {
		parsed, perr := parseWindows(w.TimeWindows)
		if perr != nil {
			// Debug, not Error. Nothing repairs a broken policy row, so an
			// Error here is one line per connected scan point every two
			// seconds, forever, in the sink the kill switch and the scope
			// refusals share. The operator-facing record is the
			// job.scope_refused audit event refuseJob writes when the job is
			// actually claimed and refused — once per job, not once per poll.
			s.log.DebugContext(ctx, "policy time_windows cannot be evaluated; its jobs will be refused",
				slog.String("policy_id", w.PolicyID.String()),
				slog.Any("error", perr))
			continue
		}
		if _, open := windowEnd(parsed, now); !open {
			closed = append(closed, w.PolicyID)
		}
	}
	return closed, nil
}

// killScope maps the stored scope onto the wire enum.
//
// An unknown scope becomes UNSPECIFIED, which the contract defines as "halt
// everything". That is the fail-safe direction and it is also what a bare
// kill_id meant before the field existed: a kill_scope value this build has not
// been taught about must not become a narrower kill than the operator asked for.
func killScope(k store.KillScope) scanpointv1.KillScope {
	switch k {
	case store.KillTenant:
		return scanpointv1.KillScope_KILL_SCOPE_TENANT
	case store.KillZone:
		return scanpointv1.KillScope_KILL_SCOPE_ZONE
	case store.KillScan:
		return scanpointv1.KillScope_KILL_SCOPE_SCAN
	default:
		return scanpointv1.KillScope_KILL_SCOPE_UNSPECIFIED
	}
}

func terminationReason(r scanpointv1.TerminationReason) store.TerminationReason {
	switch r {
	case scanpointv1.TerminationReason_COMPLETED:
		return store.TerminationCompleted
	case scanpointv1.TerminationReason_LEASE_LOST:
		return store.TerminationLeaseLost
	case scanpointv1.TerminationReason_CANCELLED:
		return store.TerminationCancelled
	case scanpointv1.TerminationReason_KILLED:
		return store.TerminationKilled
	case scanpointv1.TerminationReason_ENGINE_FAILURE:
		return store.TerminationEngineFailure
	case scanpointv1.TerminationReason_WINDOW_EXPIRED:
		return store.TerminationWindowExpired
	case scanpointv1.TerminationReason_SCOPE_VIOLATION_HALT:
		return store.TerminationScopeViolationHalt
	default:
		// An unspecified reason from a newer scan point is not a stream error.
		// Recording it as engine_failure would be a lie; lease_lost is the
		// conservative reading — the job did not complete and its results are
		// treated accordingly.
		return store.TerminationLeaseLost
	}
}

// clampCount bounds a self-asserted count before it reaches an int4 column.
//
// tasks_halted arrives as uint32 and lands in a Postgres `int`, so any value
// above 2^31-1 fails the INSERT — turning a scan point's arithmetic bug, or its
// mischief, into a lost acknowledgement and a kill that reads as unacknowledged
// forever. Clamping keeps the ack, which is the part ADR-024 needs; the number
// beside it is an attestation either way.
func clampCount(n uint32) int {
	const maxInt32 = 1<<31 - 1
	if n > maxInt32 {
		return maxInt32
	}
	return int(n)
}

// clamp bounds a self-asserted string before it reaches an unbounded text
// column. Same reasoning as enrollment: every value here originates in a network
// whose compromise the threat model assumes.
func clamp(s string) string {
	const max = 256
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// MaxTerminalDetail bounds JobTerminal.detail before it is stored.
//
// It is scan-point-supplied text that ends up in a jsonb column an operator UI
// renders. 1 KiB is far more than any message the runtime produces and far less
// than a scan point could send.
const MaxTerminalDetail = 1024

// truncate bounds a string from the wire.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
