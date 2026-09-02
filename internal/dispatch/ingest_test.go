package dispatch_test

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/dispatch"
	"github.com/effaaykhan/cvap/internal/store"
)

// fakeIngestStream implements grpc.BidiStreamingServer[ResultChunk, SubmitAck].
type fakeIngestStream struct {
	ctx     context.Context
	inbound chan *scanpointv1.ResultChunk

	mu   sync.Mutex
	acks []*scanpointv1.SubmitAck
}

func newIngestStream(ctx context.Context) *fakeIngestStream {
	return &fakeIngestStream{ctx: ctx, inbound: make(chan *scanpointv1.ResultChunk, 32)}
}

func (f *fakeIngestStream) Context() context.Context { return f.ctx }

func (f *fakeIngestStream) Send(a *scanpointv1.SubmitAck) error {
	f.mu.Lock()
	f.acks = append(f.acks, a)
	f.mu.Unlock()
	return nil
}

func (f *fakeIngestStream) Recv() (*scanpointv1.ResultChunk, error) {
	select {
	case <-f.ctx.Done():
		return nil, f.ctx.Err()
	case c, ok := <-f.inbound:
		if !ok {
			return nil, io.EOF
		}
		return c, nil
	}
}

func (f *fakeIngestStream) allAcks() []*scanpointv1.SubmitAck {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*scanpointv1.SubmitAck, len(f.acks))
	copy(out, f.acks)
	return out
}

func (f *fakeIngestStream) lastAck(t *testing.T) *scanpointv1.SubmitAck {
	t.Helper()
	acks := f.allAcks()
	if len(acks) == 0 {
		t.Fatal("no acks were sent")
	}
	return acks[len(acks)-1]
}

func (f *fakeIngestStream) SetHeader(metadata.MD) error  { return nil }
func (f *fakeIngestStream) SendHeader(metadata.MD) error { return nil }
func (f *fakeIngestStream) SetTrailer(metadata.MD)       {}
func (f *fakeIngestStream) SendMsg(any) error            { return nil }
func (f *fakeIngestStream) RecvMsg(any) error            { return nil }

// leased assigns a job to the scan point and returns the job id and epoch.
func leased(t *testing.T, db *store.DB, tenant store.TenantID, spID uuid.UUID) (uuid.UUID, uuid.UUID, uuid.UUID, int64) {
	t.Helper()
	jobID := seedQueuedJob(t, db, tenant, true)

	var epoch int64
	var taskID, zoneID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10); err != nil {
			return err
		}
		l, err := (store.Leases{}).Grant(ctx, c, jobID, spID, store.LeaseTTL)
		if err != nil {
			return err
		}
		epoch = l.Epoch

		tasks, err := (store.Jobs{}).Tasks(ctx, c, jobID)
		if err != nil {
			return err
		}
		taskID = tasks[0].ID

		sp, err := (store.ScanPoints{}).GetByID(ctx, c, spID)
		if err != nil {
			return err
		}
		zoneID = sp.ZoneID
		return nil
	}); err != nil {
		t.Fatalf("lease: %v", err)
	}
	return jobID, taskID, zoneID, epoch
}

func chunk(subID string, jobID uuid.UUID, epoch int64, idx uint32, final bool, taskID, zoneID uuid.UUID, n int) *scanpointv1.ResultChunk {
	obs := make([]*scanpointv1.Observation, 0, n)
	for i := 0; i < n; i++ {
		obs = append(obs, &scanpointv1.Observation{
			ObservationId:   uuid.NewString(),
			TaskId:          taskID.String(),
			ZoneId:          zoneID.String(),
			ObservationType: "host",
			Payload:         []byte(`{"probed":false}`),
			Confidence:      0.5,
			ObservedAtUnix:  time.Now().Unix(),
		})
	}
	return &scanpointv1.ResultChunk{
		SubmissionId: subID,
		JobId:        jobID.String(),
		LeaseEpoch:   epoch,
		ChunkIndex:   idx,
		Final:        final,
		Observations: obs,
	}
}

func runIngest(t *testing.T, svc *dispatch.IngestService, leaf *x509.Certificate, chunks ...*scanpointv1.ResultChunk) *fakeIngestStream {
	t.Helper()
	ctx, cancel := context.WithTimeout(peerCtx(context.Background(), leaf), 30*time.Second)
	t.Cleanup(cancel)

	fs := newIngestStream(ctx)
	for _, c := range chunks {
		fs.inbound <- c
	}
	close(fs.inbound)

	if err := svc.SubmitResults(fs); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("SubmitResults: %v", err)
	}
	return fs
}

func newIngestService(t *testing.T, db *store.DB) *dispatch.IngestService {
	t.Helper()
	return dispatch.NewIngest(db, slog.New(slog.NewJSONHandler(io.Discard, nil)))
}

// ============================================================================
// The happy path, and the property that makes it safe.
// ============================================================================

func TestSubmissionLandsPendingThenPromotes(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID, taskID, zoneID, epoch := leased(t, db, tenant, spID)

	subID := "sub-" + uuid.NewString()
	ctx, cancel := context.WithTimeout(peerCtx(context.Background(), leaf), 30*time.Second)
	defer cancel()

	fs := newIngestStream(ctx)
	fs.inbound <- chunk(subID, jobID, epoch, 0, false, taskID, zoneID, 2)

	done := make(chan error, 1)
	go func() { done <- svc.SubmitResults(fs) }()

	// After the first non-final chunk, rows exist and are invisible to the
	// pipeline. That is the whole point of pending: an in-flight submission is
	// not readable as accepted without the pipeline knowing submissions exist.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var pending int64
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			var err error
			pending, err = (store.Observations{}).PendingOlderThan(ctx, c,
				time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if pending >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		got, err := (store.Observations{}).ListByTask(ctx, c, taskID, 100)
		if err != nil {
			return err
		}
		if len(got) != 0 {
			t.Errorf("ListByTask returned %d rows mid-upload; a pending submission must be "+
				"invisible to the finding pipeline", len(got))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	fs.inbound <- chunk(subID, jobID, epoch, 1, true, taskID, zoneID, 3)
	close(fs.inbound)
	if err := <-done; err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("SubmitResults: %v", err)
	}

	if got := fs.lastAck(t); got.GetStatus() != scanpointv1.SubmitStatus_ACCEPTED {
		t.Errorf("terminal ack status %v, want ACCEPTED", got.GetStatus())
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		got, err := (store.Observations{}).ListByTask(ctx, c, taskID, 100)
		if err != nil {
			return err
		}
		if len(got) != 5 {
			t.Errorf("after the terminal ack the pipeline sees %d observations, want 5", len(got))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ============================================================================
// Epoch rejection. The first thing that must be right.
// ============================================================================

func TestSupersededEpochIsQuarantinedNotDropped(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID, taskID, zoneID, epoch := leased(t, db, tenant, spID)

	// Supersede: the scan point still holds `epoch`, Core has issued epoch+1.
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Leases{}).ReleaseAny(ctx, c, jobID, epoch, store.LeaseLost); err != nil {
			return err
		}
		_, err := (store.Leases{}).Grant(ctx, c, jobID, spID, store.LeaseTTL)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	subID := "sub-" + uuid.NewString()
	fs := runIngest(t, svc, leaf,
		chunk(subID, jobID, epoch, 0, false, taskID, zoneID, 2),
		chunk(subID, jobID, epoch, 1, true, taskID, zoneID, 2))

	ack := fs.lastAck(t)
	if ack.GetStatus() != scanpointv1.SubmitStatus_ACCEPTED_QUARANTINED {
		t.Fatalf("superseded epoch: ack %v, want ACCEPTED_QUARANTINED. Rejecting or "+
			"dropping loses the record of what the job touched (ADR-012)", ack.GetStatus())
	}
	if ack.GetDetail() == "" {
		t.Error("quarantine ack carries no detail; the operator is told nothing")
	}

	ctx := context.Background()
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		// STORED: the rows exist.
		q, err := (store.Observations{}).ListQuarantined(ctx, c,
			time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 100)
		if err != nil {
			return err
		}
		if len(q) != 4 {
			t.Errorf("%d quarantined observations, want 4 — they must be STORED", len(q))
		}

		// WITHHELD: the pipeline cannot see them.
		accepted, err := (store.Observations{}).ListByTask(ctx, c, taskID, 100)
		if err != nil {
			return err
		}
		if len(accepted) != 0 {
			t.Errorf("the pipeline sees %d observations from a superseded epoch; they must "+
				"be withheld", len(accepted))
		}

		// SURFACED: the submission is on the operator queue, with a reason.
		subs, err := (store.Submissions{}).ListQuarantined(ctx, c, 50)
		if err != nil {
			return err
		}
		var found bool
		for _, s := range subs {
			if s.ID == subID {
				found = true
				if s.QuarantineReason == nil || *s.QuarantineReason == "" {
					t.Error("quarantined submission has no reason recorded")
				}
			}
		}
		if !found {
			t.Error("the quarantined submission is not on the operator queue")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Supersession MIDWAY through an upload quarantines the whole submission,
// including chunks that were accepted before it happened. This is the case the
// pending state exists for: with rows landing accepted, chunk 0 would already be
// readable by the pipeline before chunk 1 revealed the problem.
func TestSupersessionMidUploadQuarantinesEverything(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID, taskID, zoneID, epoch := leased(t, db, tenant, spID)

	subID := "sub-" + uuid.NewString()
	ctx, cancel := context.WithTimeout(peerCtx(context.Background(), leaf), 30*time.Second)
	defer cancel()

	fs := newIngestStream(ctx)
	fs.inbound <- chunk(subID, jobID, epoch, 0, false, taskID, zoneID, 2)

	done := make(chan error, 1)
	go func() { done <- svc.SubmitResults(fs) }()

	// Wait for chunk 0 to land, then supersede.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var n int64
		if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
			var err error
			n, err = (store.Observations{}).PendingOlderThan(ctx, c,
				time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if n >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Leases{}).ReleaseAny(ctx, c, jobID, epoch, store.LeaseLost); err != nil {
			return err
		}
		_, err := (store.Leases{}).Grant(ctx, c, jobID, spID, store.LeaseTTL)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	fs.inbound <- chunk(subID, jobID, epoch, 1, true, taskID, zoneID, 2)
	close(fs.inbound)
	<-done

	if got := fs.lastAck(t).GetStatus(); got != scanpointv1.SubmitStatus_ACCEPTED_QUARANTINED {
		t.Fatalf("mid-upload supersession: ack %v, want ACCEPTED_QUARANTINED", got)
	}

	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		accepted, err := (store.Observations{}).ListByTask(ctx, c, taskID, 100)
		if err != nil {
			return err
		}
		if len(accepted) != 0 {
			t.Errorf("%d observations from the pre-supersession chunks reached the pipeline; "+
				"the whole submission must be quarantined together", len(accepted))
		}
		q, err := (store.Observations{}).ListQuarantined(ctx, c,
			time.Now().Add(-time.Hour), time.Now().Add(time.Hour), 100)
		if err != nil {
			return err
		}
		if len(q) != 4 {
			t.Errorf("%d quarantined observations, want all 4", len(q))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// An epoch Core never issued, and a job held by another scan point. Both
// quarantine rather than reject: either our bug or an attempt, and neither is a
// reason to drop the record.
func TestUnissuedEpochAndWrongHolderQuarantine(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID, taskID, zoneID, epoch := leased(t, db, tenant, spID)

	t.Run("epoch from the future", func(t *testing.T) {
		subID := "sub-" + uuid.NewString()
		fs := runIngest(t, svc, leaf,
			chunk(subID, jobID, epoch+99, 0, true, taskID, zoneID, 1))
		if got := fs.lastAck(t).GetStatus(); got != scanpointv1.SubmitStatus_ACCEPTED_QUARANTINED {
			t.Errorf("unissued epoch: ack %v, want ACCEPTED_QUARANTINED", got)
		}
	})

	t.Run("job held by another scan point", func(t *testing.T) {
		_, otherLeaf, otherSP := enrolledScanPoint(t, db)
		_ = otherSP
		subID := "sub-" + uuid.NewString()
		// otherLeaf belongs to a different tenant entirely, so this is refused
		// at identity rather than quarantined — the stronger outcome.
		ctx, cancel := context.WithTimeout(peerCtx(context.Background(), otherLeaf), 20*time.Second)
		defer cancel()
		fs := newIngestStream(ctx)
		fs.inbound <- chunk(subID, jobID, epoch, 0, true, taskID, zoneID, 1)
		close(fs.inbound)
		err := svc.SubmitResults(fs)
		acks := fs.allAcks()
		if err == nil && len(acks) > 0 &&
			acks[len(acks)-1].GetStatus() == scanpointv1.SubmitStatus_ACCEPTED {
			t.Error("a scan point submitted for a job in another tenant and was accepted")
		}
	})
}

// ============================================================================
// Idempotency and the five statuses.
// ============================================================================

func TestDuplicateSubmissionIsRejected(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID, taskID, zoneID, epoch := leased(t, db, tenant, spID)

	subID := "sub-" + uuid.NewString()
	runIngest(t, svc, leaf, chunk(subID, jobID, epoch, 0, true, taskID, zoneID, 1))

	// The same submission_id again: a scan point that lost the ack and retried.
	fs := runIngest(t, svc, leaf, chunk(subID, jobID, epoch, 0, true, taskID, zoneID, 1))
	if got := fs.lastAck(t).GetStatus(); got != scanpointv1.SubmitStatus_REJECTED_DUPLICATE {
		t.Errorf("duplicate submission_id: ack %v, want REJECTED_DUPLICATE", got)
	}
}

func TestMalformedChunksAreRejectedNotStored(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID, taskID, zoneID, epoch := leased(t, db, tenant, spID)

	t.Run("unknown observation_type", func(t *testing.T) {
		c := chunk("sub-"+uuid.NewString(), jobID, epoch, 0, true, taskID, zoneID, 1)
		c.Observations[0].ObservationType = "telepathy"
		fs := runIngest(t, svc, leaf, c)
		if got := fs.lastAck(t).GetStatus(); got != scanpointv1.SubmitStatus_REJECTED_MALFORMED {
			t.Errorf("unknown observation_type: ack %v, want REJECTED_MALFORMED", got)
		}
	})

	t.Run("missing submission_id", func(t *testing.T) {
		c := chunk("", jobID, epoch, 0, true, taskID, zoneID, 1)
		fs := runIngest(t, svc, leaf, c)
		if got := fs.lastAck(t).GetStatus(); got != scanpointv1.SubmitStatus_REJECTED_MALFORMED {
			t.Errorf("missing submission_id: ack %v, want REJECTED_MALFORMED", got)
		}
	})
}

func TestIngestRequiresAClientCertificate(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := svc.SubmitResults(newIngestStream(ctx))
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no peer certificate: got %v, want Unauthenticated", status.Code(err))
	}
}

// ============================================================================
// The ratchet.
// ============================================================================

func TestIngestStateIsARatchet(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID, taskID, zoneID, epoch := leased(t, db, tenant, spID)

	subID := "sub-" + uuid.NewString()
	runIngest(t, svc, leaf, chunk(subID, jobID, epoch, 0, true, taskID, zoneID, 1))

	ctx := context.Background()

	// accepted -> quarantined is refused. Promotion happens once.
	err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`UPDATE observations SET ingest_state = 'quarantined'
			  WHERE tenant_id = $1 AND submission_id = $2`, tenant.UUID(), subID)
		return err
	})
	if err == nil {
		t.Error("accepted -> quarantined was permitted; ingest_state must be a ratchet")
	}

	// quarantined -> accepted is the one that matters: the finding pipeline runs
	// as the same database role as ingest, so a grant cannot express "ingest may
	// set this and the pipeline may not". The ratchet can.
	qSub := "sub-" + uuid.NewString()
	qJob, qTask, qZone, qEpoch := leased(t, db, tenant, spID)
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Leases{}).ReleaseAny(ctx, c, qJob, qEpoch, store.LeaseLost); err != nil {
			return err
		}
		_, err := (store.Leases{}).Grant(ctx, c, qJob, spID, store.LeaseTTL)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	runIngest(t, svc, leaf, chunk(qSub, qJob, qEpoch, 0, true, qTask, qZone, 1))

	err = db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`UPDATE observations SET ingest_state = 'accepted'
			  WHERE tenant_id = $1 AND submission_id = $2`, tenant.UUID(), qSub)
		return err
	})
	if err == nil {
		t.Fatal("quarantined -> accepted was permitted. The finding pipeline could clear " +
			"the flag it filters on, which means it enforces nothing (ADR-026)")
	}
}

// TestSubmissionIdCollisionAcrossTenantsIsNotADuplicate is the M1 fix from the
// security review, and the reason migration 0022 exists.
//
// submission_id is generated at the scan point, so it is attacker-chosen. While
// it was the global primary key, tenant B submitting an id tenant A had already
// used hit a unique violation, which mapError turns into ErrConflict and ingest
// answers REJECTED_DUPLICATE. Two things wrong with that at once: B is told to
// clear a buffer whose contents were never stored — a result discarded, which
// ADR-026 says never happens — and the answer is a blind existence oracle for
// another tenant's submission ids.
//
// Sabotage-checked by putting a global unique index back on submission_id, which
// fails this test. Worth knowing for next time: the reinstated index was not
// named result_submissions_pkey, so ingest's constraint-name discrimination did
// not recognise it and the ack came back RETRY_LATER rather than
// REJECTED_DUPLICATE — an infinite retry instead of a discard. The collision is
// wrong for B either way; only which wrong answer it gets depends on the name.
func TestSubmissionIdCollisionAcrossTenantsIsNotADuplicate(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)

	tenantA, leafA, spA := enrolledScanPoint(t, db)
	tenantB, leafB, spB := enrolledScanPoint(t, db)
	if tenantA == tenantB {
		t.Fatal("fixture gave both scan points the same tenant; this test proves nothing")
	}

	jobA, taskA, zoneA, epochA := leased(t, db, tenantA, spA)
	jobB, taskB, zoneB, epochB := leased(t, db, tenantB, spB)

	// The same string, chosen by both. Nothing stops a scan point picking it.
	subID := "sub-collision-" + uuid.NewString()

	// This test leaves its rows behind, and cannot do otherwise.
	//
	// A t.Cleanup deleting them fails with "permission denied for table
	// result_submissions": cvap_app holds SELECT, INSERT and UPDATE and no
	// DELETE, because ADR-026 says results are always stored. The refusal is the
	// invariant working, so it is recorded here rather than worked around.
	//
	// The consequence lands on the dev loop, not on CI. After this test runs,
	// the database holds the one state 0022's DOWN migration refuses to roll
	// back through — a submission_id held by two tenants — so `make
	// migrate-verify` on that same database fails inside `down -all` with a
	// message about rollback safety. It is right to fail; it is confusing to
	// meet. Reset the dev database (`make down && make up && make migrate-up`)
	// before verifying migrations after a test run. CI starts from a fresh
	// Postgres and never sees it.

	fsA := runIngest(t, svc, leafA, chunk(subID, jobA, epochA, 0, true, taskA, zoneA, 2))
	if got := fsA.lastAck(t).GetStatus(); got != scanpointv1.SubmitStatus_ACCEPTED {
		t.Fatalf("tenant A ack %v, want ACCEPTED", got)
	}

	fsB := runIngest(t, svc, leafB, chunk(subID, jobB, epochB, 0, true, taskB, zoneB, 3))
	if got := fsB.lastAck(t).GetStatus(); got != scanpointv1.SubmitStatus_ACCEPTED {
		t.Fatalf("tenant B ack %v, want ACCEPTED. A submission id another tenant happens to "+
			"have used is not a duplicate; answering REJECTED_DUPLICATE discards B's results "+
			"and tells B something true about A.", got)
	}

	// Both tenants' observations landed, and each sees only its own.
	for _, tc := range []struct {
		name   string
		tenant store.TenantID
		task   uuid.UUID
		want   int
	}{{"A", tenantA, taskA, 2}, {"B", tenantB, taskB, 3}} {
		if err := db.Read(context.Background(), tc.tenant, func(ctx context.Context, c *store.Conn) error {
			got, err := (store.Observations{}).ListByTask(ctx, c, tc.task, 100)
			if err != nil {
				return err
			}
			if len(got) != tc.want {
				t.Errorf("tenant %s sees %d observations, want %d", tc.name, len(got), tc.want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
