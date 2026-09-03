package scanpoint

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/google/uuid"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/enginewire"
	"github.com/effaaykhan/cvap/internal/logging"
)

// Runtime is the scan point.
//
// ============================================================================
// Reconnect carries no new message. Renewal IS the reconciliation.
// ============================================================================
//
// A scan point that reconnects mid-job must not start that job again. There is
// no wire field for "here is what I am running" — proto/ is frozen and
// additive-only (ADR-022) — and none is needed, because lease renewal already
// asks the only question that matters. On a fresh stream the runtime renews
// every job it holds; Core answers from job_leases.holder_scan_point, which is
// authoritative and survives the disconnect. GRANTED means carry on. LOST or
// UNKNOWN_JOB means self-abort.
//
// The job table is the other half. An assignment for a job_id already running is
// never started twice, whatever Core sends — see onAssignment for the three
// epoch cases.
//
// ============================================================================
// Self-abort is a timer, not an event.
// ============================================================================
//
// The failure that matters is the one where nothing arrives: the stream is down,
// so no LeaseGrant will ever say LOST. Waiting for a message would mean scanning
// forever through a partition. watchLeases compares the clock against each
// job's expiry and aborts on its own, which is what makes ADR-012's "must
// self-abort" true while disconnected — the only state in which it is load-
// bearing.
type Runtime struct {
	cfg      Config
	log      *slog.Logger
	identity *Identity

	submit *Submitter

	// engineCaps is what the engine binary reported at startup, declared on
	// Hello. Self-asserted and a CEILING, never a grant: Core intersects it
	// with what this scan point is independently authorised to run, so
	// declaring a capability cannot obtain work (common.proto).
	engineCaps []*scanpointv1.Capability

	now func() time.Time

	mu   sync.Mutex
	jobs map[string]*job

	// out carries messages to the send loop. Buffered and non-blocking: a Core
	// that stops reading must not wedge a job's terminal path.
	out chan *scanpointv1.ScanPointMessage
}

func NewRuntime(cfg Config, log *slog.Logger, id *Identity, caps []*scanpointv1.Capability, submit *Submitter) *Runtime {
	return &Runtime{
		cfg:        cfg,
		log:        log,
		identity:   id,
		submit:     submit,
		engineCaps: caps,
		now:        time.Now,
		jobs:       make(map[string]*job),
		out:        make(chan *scanpointv1.ScanPointMessage, 64),
	}
}

// Run connects, and keeps connecting, until ctx is cancelled.
//
// Jobs survive a disconnect. They are not cancelled when the stream drops,
// because a network blip is not lease loss and killing work on one would turn
// every hiccup into a wasted scan — the lease clock decides, not the socket.
func (r *Runtime) Run(ctx context.Context, connect func(context.Context) (scanpointv1.Dispatch_ConnectClient, func() error, error)) {
	go r.watchLeases(ctx)

	// Shutdown is a self-abort, not an exit. jobCtx was created, cancelled and
	// watched by nothing, so SIGTERM to the runtime left engine process groups
	// running with no supervisor, no lease and no kill switch — reproduced by a
	// safety audit. A scan point shutting down has exactly the obligation one
	// that lost its lease has: stop the work, zeroise, submit what was
	// gathered (ADR-026). The noop engine happens to die of SIGPIPE on its next
	// write; an engine that writes rarely does not.
	defer r.shutdown()

	backoff := ReconnectMin
	for ctx.Err() == nil {
		err := r.session(ctx, connect)
		if ctx.Err() != nil {
			return
		}
		r.log.Warn("dispatch stream ended; reconnecting",
			slog.Duration("in", backoff), slog.Any("error", err))

		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(backoff)):
		}
		backoff = min(backoff*2, ReconnectMax)
	}
}

// session is one connection: handshake, then the three loops.
func (r *Runtime) session(ctx context.Context, connect func(context.Context) (scanpointv1.Dispatch_ConnectClient, func() error, error)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, closeConn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = closeConn() }()

	if err := stream.Send(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Hello{Hello: &scanpointv1.Hello{
			ScanPointId:     r.identity.ScanPointID,
			ProtocolVersion: r.cfg.ProtocolVersion,
			AgentVersion:    r.cfg.AgentVersion,
			Capabilities:    r.engineCaps,
		}},
	}); err != nil {
		return err
	}

	first, err := stream.Recv()
	if err != nil {
		return err
	}
	sh := first.GetServerHello()
	if sh == nil {
		return errors.New("scanpoint: first message from Core was not ServerHello")
	}
	if n := sh.GetDeprecationNotice(); n != "" {
		// Operator-facing and surfaced at warn: ADR-022 wants a build outside
		// the window told so in words, not failing mysteriously in a network
		// nobody can reach to diagnose.
		r.log.Warn("Core sent a deprecation notice", slog.String("notice", n))
	}
	r.log.Info("connected",
		slog.String("scan_point_id", r.identity.ScanPointID),
		slog.String("accepted_protocol_version", sh.GetAcceptedProtocolVersion()))

	// A fresh stream renews everything still running. This is the reconciliation
	// — Core tells us which of our jobs we still hold.
	r.renewAll()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r.sendLoop(ctx, stream) }()
	go func() { defer wg.Done(); r.periodic(ctx) }()

	err = r.receiveLoop(ctx, stream)
	cancel()
	wg.Wait()
	return err
}

func (r *Runtime) receiveLoop(ctx context.Context, stream scanpointv1.Dispatch_ConnectClient) error {
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		switch m := msg.Msg.(type) {
		case *scanpointv1.CoreMessage_Job:
			r.onAssignment(ctx, m.Job)
		case *scanpointv1.CoreMessage_Lease:
			r.onLeaseGrant(m.Lease)
		case *scanpointv1.CoreMessage_Cancel:
			r.onCancel(m.Cancel)
		case *scanpointv1.CoreMessage_Kill:
			r.onKill(m.Kill)
		case *scanpointv1.CoreMessage_Credential:
			r.onCredential(m.Credential)
		case *scanpointv1.CoreMessage_RulePack:
			// RulePacks is a later session. An unknown-but-valid message must
			// not end the stream, or every protocol addition becomes a fleet
			// outage (ADR-022).
		default:
			r.log.Warn("unhandled message from Core")
		}
	}
}

func (r *Runtime) sendLoop(ctx context.Context, stream scanpointv1.Dispatch_ConnectClient) {
	for {
		select {
		case <-ctx.Done():
			return
		case msg := <-r.out:
			if err := stream.Send(msg); err != nil {
				return
			}
		}
	}
}

// periodic drives the heartbeat, lease renewal and backpressure.
func (r *Runtime) periodic(ctx context.Context) {
	hb := time.NewTicker(HeartbeatInterval)
	defer hb.Stop()
	renew := time.NewTicker(LeaseRenewInterval)
	defer renew.Stop()

	r.sendHeartbeat()
	for {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			r.sendHeartbeat()
		case <-renew.C:
			r.renewAll()
		}
	}
}

func (r *Runtime) sendHeartbeat() {
	count, bytes := r.submit.Buffered()
	r.send(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Heartbeat{Heartbeat: &scanpointv1.Heartbeat{
			SentAtUnix: r.now().Unix(),
			ActiveJobs: u32(len(r.snapshot())),
			// The buffer depth is the only way Core can see a scan point
			// approaching its ceiling rather than learning about it once data
			// starts being shed (dispatch.proto).
			BufferedSubmissions: u32(count),
			BufferedBytes:       bytes,
			// An attestation, not a control. The no-op engine sends nothing,
			// and reporting zero is the truth rather than a placeholder.
			ObservedRatePps: 0,
		}},
	})

	if p := r.submit.Pressure(); p != scanpointv1.BackpressureState_BACKPRESSURE_STATE_OK {
		count, bytes := r.submit.Buffered()
		r.send(&scanpointv1.ScanPointMessage{
			Msg: &scanpointv1.ScanPointMessage_Backpressure{Backpressure: &scanpointv1.Backpressure{
				State:               p,
				BufferedSubmissions: u32(count),
				BufferedBytes:       bytes,
				ReportedAtUnix:      r.now().Unix(),
			}},
		})
	}
}

func (r *Runtime) renewAll() {
	for _, j := range r.snapshot() {
		r.send(&scanpointv1.ScanPointMessage{
			Msg: &scanpointv1.ScanPointMessage_LeaseRenewal{LeaseRenewal: &scanpointv1.LeaseRenewal{
				JobId:         j.id,
				LeaseEpoch:    j.currentEpoch(),
				RenewedAtUnix: r.now().Unix(),
			}},
		})
	}
}

// watchLeases is the self-abort that does not need Core to say anything.
func (r *Runtime) watchLeases(ctx context.Context) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := r.now()
		for _, j := range r.snapshot() {
			if j.leaseLapsed(now) {
				r.log.Error("lease expired without a renewal; self-aborting",
					slog.String("job_id", j.id),
					slog.Int64("lease_epoch", j.epoch),
					slog.Time("expired_at", j.expiry()))
				go r.abort(j, scanpointv1.TerminationReason_LEASE_LOST)
			}
		}
	}
}

// shutdown aborts every running job and waits for them.
//
// Bounded: a scan point that will not exit is its own problem, and unsubmitted
// results are re-derivable from a re-run, which is what reassign_safe governs.
// The wait is generous enough to cover SIGTERM plus the SIGKILL escalation.
func (r *Runtime) shutdown() {
	jobs := r.snapshot()
	if len(jobs) == 0 {
		return
	}
	r.log.Warn("shutting down with jobs in flight; self-aborting each",
		slog.Int("jobs", len(jobs)))

	for _, j := range jobs {
		go r.abort(j, scanpointv1.TerminationReason_LEASE_LOST)
	}

	deadline := time.After(MaxStopGrace + 5*time.Second)
	for _, j := range jobs {
		select {
		case <-j.done:
		case <-deadline:
			r.log.Error("a job did not finish aborting before shutdown gave up",
				slog.String("job_id", j.id))
			return
		}
	}
}

func (r *Runtime) snapshot() []*job {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*job, 0, len(r.jobs))
	for _, j := range r.jobs {
		out = append(out, j)
	}
	return out
}

func (r *Runtime) lookup(id string) *job {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.jobs[id]
}

// onAssignment is where reconnect stops being able to duplicate work.
func (r *Runtime) onAssignment(ctx context.Context, a *scanpointv1.JobAssignment) {
	id := a.GetJobId()

	if existing := r.lookup(id); existing != nil {
		switch {
		case a.GetLeaseEpoch() == existing.epoch:
			// A duplicate delivery — a redelivery after a reconnect, or Core
			// offering the same work twice. Ignored, not restarted: the job is
			// already running under this exact incarnation.
			r.log.Info("ignoring a duplicate assignment for a job already running",
				slog.String("job_id", id), slog.Int64("lease_epoch", a.GetLeaseEpoch()))
			return
		case a.GetLeaseEpoch() > existing.currentEpoch():
			// A higher epoch means the incarnation we hold lost its lease and
			// Core requeued the job — which it only does for reassign_safe
			// work. The old one must die before the new one starts, or this
			// scan point runs the same targets twice at once.
			r.log.Warn("assignment supersedes a running incarnation; aborting the old one first",
				slog.String("job_id", id),
				slog.Int64("held_epoch", existing.currentEpoch()),
				slog.Int64("new_epoch", a.GetLeaseEpoch()))
			r.abort(existing, scanpointv1.TerminationReason_LEASE_LOST)

			// WAIT for it. abort returns immediately when another abort already
			// owns the terminal path, so without this the old engine was still
			// running when the new incarnation started — two engines against
			// the same targets — and the old one's terminate() then deleted the
			// job id from the table, which by then named the NEW incarnation.
			// Nothing could cancel or kill it after that.
			select {
			case <-existing.done:
			case <-ctx.Done():
				return
			}
		default:
			// Older than what we hold: a message that overtook a newer one, or
			// a stale redelivery. Acting on it would fence us off our own job.
			r.log.Warn("ignoring an assignment older than the incarnation held",
				slog.String("job_id", id),
				slog.Int64("held_epoch", existing.currentEpoch()),
				slog.Int64("offered_epoch", a.GetLeaseEpoch()))
			return
		}
	}

	// A saturated buffer refuses work rather than dropping results (ADR-026).
	if p := r.submit.Pressure(); p == scanpointv1.BackpressureState_BACKPRESSURE_STATE_HARD {
		r.log.Error("refusing an assignment: the result buffer is full",
			slog.String("job_id", id))
		r.sendTerminal(id, a.GetLeaseEpoch(), scanpointv1.TerminationReason_ENGINE_FAILURE,
			"", true, true, "result buffer full; work refused rather than results dropped")
		return
	}

	// Everything the terminal path touches is built HERE, before the job is
	// visible and before any goroutine runs. A cancel or a kill arriving on the
	// next message now finds a real host to stop and a real context to cancel.
	jobCtx, cancel := context.WithCancel(ctx)
	c := a.GetConstraints()
	j := &job{
		id:           id,
		epoch:        a.GetLeaseEpoch(),
		reassignSafe: a.GetReassignSafe(),
		constraints:  c,
		tasks:        a.GetTasks(),
		cancel:       cancel,
		host: newEngineHost(r.log, r.cfg.EngineBinary, id,
			c.GetAllowedTargets(), c.GetExclusions()),
		done: make(chan struct{}),
	}
	j.setExpiry(time.Unix(a.GetLeaseExpiresUnix(), 0))

	r.mu.Lock()
	r.jobs[id] = j
	r.mu.Unlock()

	go r.runJob(jobCtx, j)
}

// runJob hosts the engine for one assignment.
func (r *Runtime) runJob(ctx context.Context, j *job) {
	defer close(j.done)

	// The zeroise guarantee, on every path including panic. ADR-020 requires it
	// on completion, lease loss AND abort, and a deferred call is the only
	// construct that covers a path nobody thought of.
	defer j.zeroiseCredentials()
	defer j.cancel()

	host := j.host

	if err := host.start(ctx, j.wireTargets(), j.budget()); err != nil {
		if errors.Is(err, errStopBeforeStart) {
			// A cancel, a kill or a lost lease got here first and already owns
			// the terminal path. No engine was spawned, which is the whole
			// point: the previous shape reported the job terminal and then
			// started the work anyway.
			r.log.Warn("job stopped before its engine started", slog.String("job_id", j.id))
			return
		}
		if errors.Is(err, ErrOutOfScope) {
			// The two enforcement sites disagreed. Core planned work this
			// runtime will not do, which is either a planning bug or a Core
			// this scan point should not be trusting — and either way the
			// operator needs to know rather than have the job quietly trimmed.
			r.log.Error("refusing a job: a target is outside the authorised scope",
				slog.String("job_id", j.id), slog.Any("error", err))
			r.finish(j, scanpointv1.TerminationReason_SCOPE_VIOLATION_HALT, true, err.Error())
			return
		}
		r.log.Error("engine failed to start",
			slog.String("job_id", j.id), slog.Any("error", err))
		r.finish(j, scanpointv1.TerminationReason_ENGINE_FAILURE, true, err.Error())
		return
	}

	host.pump()
	outcome := host.wait()

	switch outcome {
	case EngineCompleted:
		r.finish(j, scanpointv1.TerminationReason_COMPLETED, false, "")
	case EngineFailed:
		// The engine died on its own: a crash, an OOM kill, a non-zero exit, or
		// stdout closing without a done message. Not lease loss, not
		// cancellation, not completion — ENGINE_FAILURE, so an operator reading
		// the audit trail looks at the engine rather than at the network.
		//
		// The engine is NOT restarted. A crashed engine restarted under the
		// same lease would re-run targets the first attempt may already have
		// touched, which is duplicate execution against a customer's estate
		// under a lease that says one execution. Whether the work re-runs is
		// Core's decision, through reassign_safe (ADR-012), not this runtime's.
		r.log.Error("engine died; job failed",
			slog.String("job_id", j.id), slog.String("outcome", outcome.String()))
		r.finish(j, scanpointv1.TerminationReason_ENGINE_FAILURE, true, "engine process died")
	case EngineStopped:
		// The runtime asked. abort() owns the terminal path and has already run
		// or is running; nothing to do here.
	}
}

// finish submits and reports a job that ended without an abort.
func (r *Runtime) finish(j *job, reason scanpointv1.TerminationReason, incomplete bool, detail string) {
	if !j.beginAbort(reason) {
		return // an abort got here first and owns the terminal path
	}
	r.terminate(j, reason, incomplete, detail)
}

// abort is the self-abort procedure: stop, zeroise, submit, report.
//
// The order is load-bearing. Zeroisation happens BEFORE submission because
// submission can block for a long time against an unreachable Core, and
// credential lifetime must not be tied to how long an upload takes (ADR-020).
// Results are submitted after, always, because they are never discarded
// (ADR-026) — the partial record is what an operator reads to find out what an
// intrusive job touched before it died, which is the content of ADR-012's
// escalation.
func (r *Runtime) abort(j *job, reason scanpointv1.TerminationReason) {
	if !j.beginAbort(reason) {
		return
	}

	// 1. Stop the work. SIGTERM, then SIGKILL after the grace window.
	if j.cancel != nil {
		j.cancel()
	}
	if j.host != nil {
		j.host.stop(EngineStopGrace)
	}

	// 2. Zeroise, before anything that can block.
	j.zeroiseCredentials()

	r.terminate(j, reason, true, reason.String())
}

// terminate submits whatever was gathered and sends JobTerminal.
func (r *Runtime) terminate(j *job, reason scanpointv1.TerminationReason, incomplete bool, detail string) {
	j.zeroiseCredentials()

	var observations []*scanpointv1.Observation
	var completed, failed uint32
	if j.host != nil {
		obs, _, truncated := j.host.results()
		var dropped int
		observations, dropped = r.toWire(obs)
		completed = u32(len(observations))
		if truncated || dropped > 0 {
			// Truncated at the per-job bound, or an observation the engine
			// produced that Core would reject. Either way this is not a whole
			// scan, and saying so is the difference between a partial result
			// and a clean run the customer acts on.
			incomplete = true
		}
	}
	if n := u32(len(j.tasks)); n > completed {
		failed = n - completed
	}

	submissionID := uuid.NewString()
	err := r.submit.Enqueue(&Submission{
		SubmissionID: submissionID,
		JobID:        j.id,
		LeaseEpoch:   j.currentEpoch(),
		Incomplete:   incomplete,
		Reason:       reason,
		Observations: observations,
	})
	if err != nil {
		// The buffer refused. Reported rather than absorbed: the alternative is
		// dropping results, which ADR-026 exists to prevent, and an operator
		// needs to know that this job's record was lost at the scan point
		// rather than at Core.
		r.log.Error("results could not be buffered",
			slog.String("job_id", j.id),
			slog.String("submission_id", submissionID),
			slog.Any("error", err))
	}

	epoch := j.currentEpoch()
	r.sendTerminal(j.id, epoch, reason, submissionID, incomplete,
		j.credentialsZeroised(), detail)
	r.sendTaskCounts(j.id, epoch, completed, failed)

	// Only if the table still holds THIS job. A superseded incarnation's
	// terminate arriving after its replacement was installed would otherwise
	// delete the replacement, leaving a running engine nothing can reach.
	r.mu.Lock()
	if r.jobs[j.id] == j {
		delete(r.jobs, j.id)
	}
	r.mu.Unlock()
}

func (r *Runtime) sendTerminal(jobID string, epoch int64, reason scanpointv1.TerminationReason,
	submissionID string, incomplete, zeroised bool, detail string,
) {
	r.send(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Terminal{Terminal: &scanpointv1.JobTerminal{
			JobId:        jobID,
			LeaseEpoch:   epoch,
			Reason:       reason,
			SubmissionId: submissionID,
			Incomplete:   incomplete,
			EndedAtUnix:  r.now().Unix(),
			Detail:       detail,
			// An attestation Core audits when absent, answered from the state
			// of the holder rather than from a flag somebody set.
			CredentialsZeroised: zeroised,
		}},
	})
}

func (r *Runtime) sendTaskCounts(jobID string, epoch int64, completed, failed uint32) {
	r.send(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_Progress{Progress: &scanpointv1.JobProgress{
			JobId:          jobID,
			LeaseEpoch:     epoch,
			TasksCompleted: completed,
			TasksFailed:    failed,
			ReportedAtUnix: r.now().Unix(),
		}},
	})
}

func (r *Runtime) onLeaseGrant(g *scanpointv1.LeaseGrant) {
	j := r.lookup(g.GetJobId())
	if j == nil {
		return
	}
	switch g.GetState() {
	case scanpointv1.LeaseState_LEASE_STATE_GRANTED:
		// Core's epoch is authoritative and may exceed what was asked with
		// (dispatch.proto), so it is adopted rather than compared.
		j.setEpoch(g.GetLeaseEpoch())
		j.setExpiry(time.Unix(g.GetLeaseExpiresUnix(), 0))
	case scanpointv1.LeaseState_LEASE_STATE_LOST,
		scanpointv1.LeaseState_LEASE_STATE_UNKNOWN_JOB:
		r.log.Error("lease lost; self-aborting",
			slog.String("job_id", g.GetJobId()),
			slog.String("state", g.GetState().String()),
			slog.String("detail", g.GetDetail()))
		go r.abort(j, scanpointv1.TerminationReason_LEASE_LOST)
	}
}

func (r *Runtime) onCancel(c *scanpointv1.CancelJob) {
	j := r.lookup(c.GetJobId())
	if j == nil {
		return
	}
	if c.GetLeaseEpoch() != j.currentEpoch() {
		// Names an incarnation this runtime does not hold. Ignored: acting on
		// it would stop work Core never meant to touch.
		r.log.Warn("ignoring a cancellation for an epoch not held",
			slog.String("job_id", c.GetJobId()),
			slog.Int64("held_epoch", j.currentEpoch()),
			slog.Int64("named_epoch", c.GetLeaseEpoch()))
		return
	}

	// Bounded at the receiver — see MaxStopGrace. grace_ms arrives from the
	// network, and ADR-024's 10 s propagation bound is "not adjustable".
	grace := EngineStopGrace
	if ms := c.GetGraceMs(); ms > 0 {
		grace = time.Duration(ms) * time.Millisecond
	}
	if grace > MaxStopGrace {
		r.log.Warn("cancellation grace exceeds the ADR-024 propagation bound; clamping",
			slog.Duration("requested", grace), slog.Duration("clamped_to", MaxStopGrace))
		grace = MaxStopGrace
	}
	r.log.Warn("cancellation received",
		slog.String("job_id", c.GetJobId()), slog.String("reason", c.GetReason()))

	go func() {
		if j.beginAbort(scanpointv1.TerminationReason_CANCELLED) {
			if j.cancel != nil {
				j.cancel()
			}
			if j.host != nil {
				j.host.stop(grace)
			}
			j.zeroiseCredentials()
			r.terminate(j, scanpointv1.TerminationReason_CANCELLED, true, c.GetReason())
		}
		// Acknowledged whether or not this caller owned the abort: Core is
		// asking whether the cancellation arrived, and it did.
		r.send(&scanpointv1.ScanPointMessage{
			Msg: &scanpointv1.ScanPointMessage_CancelAck{CancelAck: &scanpointv1.CancelAck{
				JobId:       c.GetJobId(),
				LeaseEpoch:  c.GetLeaseEpoch(),
				AckedAtUnix: r.now().Unix(),
				TasksHalted: u32(len(j.tasks)),
			}},
		})
	}()
}

func (r *Runtime) onKill(k *scanpointv1.KillSwitch) {
	scope := k.GetScope()
	r.log.Error("kill switch received",
		slog.String("kill_id", k.GetKillId()), slog.String("scope", scope.String()))

	var halted uint32
	if scope != scanpointv1.KillScope_KILL_SCOPE_SCAN {
		// TENANT, ZONE, or UNSPECIFIED. Unspecified is an older Core that does
		// not set the field, and the only correct reading of a bare kill_id is
		// the widest one — so it halts everything, which is what it meant
		// before the field existed.
		for _, j := range r.snapshot() {
			halted += u32(len(j.tasks))
			go r.abort(j, scanpointv1.TerminationReason_KILLED)
		}
	}
	// KILL_SCOPE_SCAN halts nothing here: Core marks the scan killed and the
	// jobs arrive individually as CancelJob, which name the job and the epoch.
	// The ack is still sent — every scope is acknowledged, because it measures
	// RECEIPT, and a scope a runtime decided needed no answer is a scope whose
	// propagation Core cannot measure at all (dispatch.proto).
	r.send(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_KillAck{KillAck: &scanpointv1.KillAck{
			KillId:      k.GetKillId(),
			AckedAtUnix: r.now().Unix(),
			TasksHalted: halted,
		}},
	})
}

func (r *Runtime) onCredential(g *scanpointv1.CredentialGrant) {
	j := r.lookup(g.GetJobId())
	if j == nil {
		// No job to hold it for. The material is dropped on the floor rather
		// than stored anywhere, which is the only safe thing to do with a
		// credential nothing asked for.
		// Erased rather than merely dropped: the decoded message still holds the
		// material, and a credential nothing asked for is one nothing will ever
		// zeroise.
		clear(g.Material)
		r.log.Warn("credential grant for a job this scan point is not running",
			slog.String("grant_id", g.GetGrantId()))
		return
	}
	// NewCredential takes ownership of the protobuf field's array, so zeroising
	// later erases the decoded message's copy too.
	// Appended, never replacing. A grant that displaced its predecessor left the
	// old material resident for the life of the process while
	// credentials_zeroised answered about the REPLACEMENT — so Core's audit
	// recorded the invariant as satisfied over a secret that still existed.
	j.addCredential(NewCredential(g.GetGrantId(), g.GetJobId(), g.GetCredKind().String(),
		g.GetScope(), time.Unix(g.GetExpiresUnix(), 0), g.GetMaterial()))
	r.log.Info("credential received",
		slog.String("job_id", g.GetJobId()),
		slog.String("grant_id", g.GetGrantId()),
		// logging.ProtoAttr, never slog.Any: the generated type's String()
		// renders material in full (ADR-034).
		logging.ProtoAttr("grant", g))
}

// toWire converts engine output, dropping what Core would refuse.
//
// ============================================================================
// The engine boundary is a trust boundary, not an internal conversion.
// ============================================================================
//
// Core validates every one of these — uuid parse, known observation_type, valid
// JSON payload, confidence in range, observed_at inside the retention window —
// and answers REJECTED_MALFORMED for the WHOLE CHUNK. The submitter then
// correctly clears the buffer without retrying, because unparseable input will
// not become parseable.
//
// So one bad observation destroyed a whole job's evidence. An engine writes a
// raw banner into a payload without encoding it, and a host serving a crafted
// banner suppresses the findings about itself AND every other host in the job —
// an evidence-suppression primitive reachable from any scanned target, with
// JobTerminal already reporting COMPLETED.
//
// Dropping the offending one and keeping the rest is the only outcome that is
// not attacker-controlled. The drop count feeds `incomplete`, so a partial
// result is never reported as a whole one.
func (r *Runtime) toWire(obs []enginewire.Observation) ([]*scanpointv1.Observation, int) {
	out := make([]*scanpointv1.Observation, 0, len(obs))
	dropped := 0
	for _, o := range obs {
		if why := validObservation(o); why != "" {
			dropped++
			r.log.Error("engine produced an observation Core would refuse; dropping it",
				slog.String("observation_id", o.ObservationID),
				slog.String("reason", why))
			continue
		}
		out = append(out, &scanpointv1.Observation{
			ObservationId: o.ObservationID,
			TaskId:        o.TaskID,
			// The zone this scan point was enrolled into is Core's to decide;
			// the runtime does not carry one and does not assert one. An
			// observation naming a zone the scan point was not enrolled into is
			// quarantined at ingest, and the field exists for a scan point that
			// straddles segments — not so that it may choose (ingest.proto).
			ZoneId:          "",
			ObservationType: o.Type,
			Payload:         o.Payload,
			Confidence:      o.Confidence,
			ObservedAtUnix:  o.ObservedAt.Unix(),
		})
	}
	return out, dropped
}

// validObservation applies the same predicates Core applies at ingest.
//
// Deliberately the same set, so the two cannot drift into a state where the
// runtime forwards something Core rejects. Anything Core would call malformed is
// dropped here, where the cost is one observation rather than a whole chunk.
func validObservation(o enginewire.Observation) string {
	if _, err := uuid.Parse(o.ObservationID); err != nil {
		return "observation_id is not a uuid"
	}
	if _, err := uuid.Parse(o.TaskID); err != nil {
		return "task_id is not a uuid"
	}
	if o.Type == "" {
		return "no observation_type"
	}
	if len(o.Payload) == 0 || !json.Valid(o.Payload) {
		return "payload is not valid JSON"
	}
	c := float64(o.Confidence)
	if math.IsNaN(c) || math.IsInf(c, 0) || c < 0 || c > 1 {
		return "confidence out of range"
	}
	if o.ObservedAt.IsZero() {
		return "no observed_at"
	}
	return ""
}

// send queues without blocking. A Core that has stopped reading must not wedge a
// job's terminal path; the message is dropped and the sweeper covers the gap.
func (r *Runtime) send(msg *scanpointv1.ScanPointMessage) {
	select {
	case r.out <- msg:
	default:
		r.log.Warn("outbound queue full; message dropped",
			logging.ProtoAttr("dropped", msg))
	}
}

// jitter spreads reconnects. A Core restart disconnects every scan point at
// once, and an unjittered backoff brings them all back in the same instant.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return ReconnectMin
	}
	n, err := uuid.NewRandom()
	if err != nil {
		return d
	}
	// Between 50% and 100% of the interval.
	frac := float64(n[0])/512.0 + 0.5
	return time.Duration(float64(d) * frac)
}
