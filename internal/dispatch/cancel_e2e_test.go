package dispatch_test

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/google/uuid"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/store"
)

// TestScanKillReachesTheWireAndIsAcknowledged is ADR-024 control 4 end to end,
// on the stream rather than in the store.
//
// Four things had to hold at once and none of them did before this session:
//
//   - A scan-scoped kill has to stop the scan. The wire KillSwitch carries no
//     job ids, so a scan point receiving one cannot tell which of its jobs are
//     covered; KillSwitches.Issue marks the scan killed and the existing per-job
//     path does the naming.
//   - KillSwitch has to say how much to halt. Before the scope field, a per-scan
//     kill and a tenant-wide kill were the same bytes, so the only correct
//     reading was the widest one.
//   - A KILLED scan has to produce CancelJob. Jobs.Claim excluded 'killed' from
//     the outset while CancellableFor matched 'cancelled' only, so a killed
//     scan's in-flight jobs — the ones demonstrably still touching the estate —
//     were told nothing.
//   - The cancellation has to be measurable. ADR-024 requires KillAck because "a
//     10-second bound Core cannot measure is not a control", and the argument
//     does not weaken when the blast radius narrows.
func TestScanKillReachesTheWireAndIsAcknowledged(t *testing.T) {
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

	assign := fs.waitFor(t, "JobAssignment", func(m *scanpointv1.CoreMessage) bool {
		return m.GetJob() != nil
	}).GetJob()
	if assign.GetJobId() != jobID.String() {
		t.Fatalf("assigned job %s, want %s", assign.GetJobId(), jobID)
	}
	epoch := assign.GetLeaseEpoch()

	// The scan point is now holding the job. An operator kills the scan.
	var scanID uuid.UUID
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		j, err := (store.Jobs{}).GetByID(ctx, c, jobID)
		if err != nil {
			return err
		}
		scanID = j.ScanID
		_, err = (store.KillSwitches{}).Issue(ctx, c, store.KillScan, nil, &scanID, nil, "runaway scan")
		return err
	}); err != nil {
		t.Fatalf("issue kill: %v", err)
	}

	kill := fs.waitFor(t, "KillSwitch", func(m *scanpointv1.CoreMessage) bool {
		return m.GetKill() != nil
	}).GetKill()
	if kill.GetScope() != scanpointv1.KillScope_KILL_SCOPE_SCAN {
		t.Errorf("kill scope = %v, want KILL_SCOPE_SCAN. Without the scope a per-scan kill "+
			"and a tenant-wide kill are the same message, and the only safe reading of "+
			"that message is to halt everything.", kill.GetScope())
	}

	// And the jobs it covers arrive individually, naming the incarnation.
	cancelMsg := fs.waitFor(t, "CancelJob", func(m *scanpointv1.CoreMessage) bool {
		return m.GetCancel() != nil
	}).GetCancel()
	if cancelMsg.GetJobId() != jobID.String() {
		t.Errorf("CancelJob names %s, want %s", cancelMsg.GetJobId(), jobID)
	}
	if cancelMsg.GetLeaseEpoch() != epoch {
		t.Errorf("CancelJob epoch = %d, want the held %d", cancelMsg.GetLeaseEpoch(), epoch)
	}
	if cancelMsg.GetGraceMs() == 0 {
		t.Error("CancelJob carries no grace window; the runtime has no SIGTERM period")
	}

	// The scan point answers. Without this Core's last knowledge is
	// "cancellation sent", and a dropped message looks exactly like a halt.
	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_CancelAck{CancelAck: &scanpointv1.CancelAck{
			JobId:       jobID.String(),
			LeaseEpoch:  epoch,
			TasksHalted: 1,
		}},
	})

	waitUntil(t, "the cancellation to be acknowledged", func() bool {
		var acked bool
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			un, err := (store.CancelAcks{}).Unacknowledged(ctx, c, scanID)
			if err != nil {
				return err
			}
			acked = len(un) == 0
			return nil
		}); err != nil {
			t.Fatalf("read unacknowledged: %v", err)
		}
		return acked
	})

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		acks, err := (store.CancelAcks{}).ForScan(ctx, c, scanID)
		if err != nil {
			return err
		}
		if len(acks) != 1 {
			t.Fatalf("cancel acks = %d, want 1", len(acks))
		}
		if acks[0].Epoch != epoch {
			t.Errorf("ack epoch = %d, want %d", acks[0].Epoch, epoch)
		}
		if acks[0].ScanPointID != spID {
			t.Errorf("ack attributed to %v, want the session's %v — the scan point comes "+
				"from the resolved identity, never from the message", acks[0].ScanPointID, spID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	fs.closeInbound()
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		t.Logf("stream ended with %v", err)
	}
}

// TestALeaseIsNotRenewedPastTheMaintenanceWindow gives the time dimension its
// second enforcement site.
//
// Core refused to START a job outside its window and had nothing to stop one
// already running: a job claimed at 03:59 under a 22:00-04:00 window renewed
// every 20 s indefinitely, and the only thing that would ever halt it was
// window_ends_unix on the wire — a runtime that does not exist yet, running a
// build we do not control. ADR-024 control 1 rejected single-site enforcement
// outright, and the target dimension had two sites while time had one.
//
// Refusing the renewal is the lever the architecture already defines: invariant
// 8 and ADR-012 make a refused renewal a self-abort with credential zeroisation.
func TestALeaseIsNotRenewedPastTheMaintenanceWindow(t *testing.T) {
	db := testDB(t)
	svc := newService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)

	// A job already leased, under a policy whose window is shut right now. It is
	// seeded leased rather than dispatched because the start-side check would
	// correctly refuse to hand it out — which is the point: this is the job that
	// was legitimately claimed while the window was open.
	var jobID uuid.UUID
	var epoch int64
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		// 00:00-00:01 UTC: shut for all but one minute a day. A test that
		// depends on the wall clock for its answer is one that fails at 00:00
		// for a reason nobody will find, so the assertion below tolerates it.
		var policyID, scanID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name, time_windows)
			 VALUES ($1,$2,'[{"start":"00:00","end":"00:01"}]'::jsonb) RETURNING policy_id`,
			tid, "win-"+uuid.NewString()[:8]).Scan(&policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1,$2,'discovery')
			 RETURNING scan_id`, tid, policyID).Scan(&scanID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, status, scan_point_id)
			 VALUES ($1,$2,'discovery','running',$3) RETURNING job_id`,
			tid, scanID, spID).Scan(&jobID); err != nil {
			return err
		}
		l, err := (store.Leases{}).Grant(ctx, c, jobID, spID, store.LeaseTTL)
		if err != nil {
			return err
		}
		epoch = l.Epoch
		return nil
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if time.Now().UTC().Hour() == 0 && time.Now().UTC().Minute() == 0 {
		t.Skip("the seeded window is open this minute; skipping rather than asserting the opposite")
	}

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

	fs.push(&scanpointv1.ScanPointMessage{
		Msg: &scanpointv1.ScanPointMessage_LeaseRenewal{
			LeaseRenewal: &scanpointv1.LeaseRenewal{JobId: jobID.String(), LeaseEpoch: epoch},
		},
	})

	grant := fs.waitFor(t, "LeaseGrant", func(m *scanpointv1.CoreMessage) bool {
		return m.GetLease() != nil && m.GetLease().GetJobId() == jobID.String()
	}).GetLease()

	if grant.GetState() != scanpointv1.LeaseState_LEASE_STATE_LOST {
		t.Errorf("renewal outside the maintenance window: state %v, want LOST. Core has three "+
			"levers to stop a running job and was using none of them; the scan point's own "+
			"clock was the only thing between the estate and an unbounded scan.",
			grant.GetState())
	}
	if grant.GetDetail() == "" {
		t.Error("the refusal carries no detail; the operator is told nothing")
	}

	fs.closeInbound()
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
		t.Logf("stream ended with %v", err)
	}
}
