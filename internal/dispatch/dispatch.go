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
	"github.com/effaaykhan/cvap/internal/store"
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
		return (store.KillSwitches{}).Ack(ctx, c, killID, sess.spID, int(a.GetTasksHalted()))
	}); err != nil {
		s.log.ErrorContext(ctx, "kill ack write failed", slog.Any("error", err))
	}
}

// pump is the outbound loop: offer work, propagate kills.
func (s *Service) pump(ctx context.Context, sess *session, out, urgent chan<- *scanpointv1.CoreMessage) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	sentKills := map[uuid.UUID]bool{}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		// Kills first, always. A kill switch queued behind job assignment is a
		// kill switch that misses its 10-second bound (ADR-024).
		s.propagateKills(ctx, sess, urgent, sentKills)

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
		kills, err = (store.KillSwitches{}).Live(ctx, c)
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
				Kill: &scanpointv1.KillSwitch{KillId: k.ID.String()},
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

// offerWork claims jobs and assigns them, granting a lease for each.
//
// The claim and the lease are ONE transaction: a job marked assigned with no
// lease is a job nothing will ever expire, and it would sit in that state until
// someone noticed.
func (s *Service) offerWork(ctx context.Context, sess *session, out chan<- *scanpointv1.CoreMessage, limit int) {
	var assignments []*scanpointv1.JobAssignment

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

		jobs, err := (store.Jobs{}).Claim(ctx, c, sess.spID, engines, limit)
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

			wire := &scanpointv1.JobAssignment{
				JobId:            j.ID.String(),
				Engine:           string(j.Engine),
				LeaseEpoch:       lease.Epoch,
				LeaseExpiresUnix: lease.ExpiresAt.Unix(),
				ReassignSafe:     j.ReassignSafe,
				Constraints:      defaultConstraints(),
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
func defaultConstraints() *scanpointv1.ScanConstraints {
	return &scanpointv1.ScanConstraints{
		MaxRatePps:             1000,
		MaxRatePerTarget:       50,
		FragileRatePps:         10,
		MaxConcurrentPerTarget: 20,
		ConnectTimeoutMs:       3000,
		SafetyMode:             "safe",
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
