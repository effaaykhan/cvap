package e2e

import (
	"context"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/store"
)

// ============================================================================
// F1b — a non-reassign_safe job whose lease is lost is FAILED, not re-scanned.
// ============================================================================
//
// F1a proved the DB fencing (Jobs.Terminate) with a forced completion race. This
// is the half that matters operationally: ADR-012 exists because double-scanning
// a production host is harmful, so the assertion is about WORK — packets at
// targets — not about a status column. A non-reassign_safe job that loses its
// lease must FAIL and stay failed; it must never be handed back out and scanned
// a second time, by this scan point or any other.
//
// The partition is real in the way this suite's other lease tests are real: the
// scan point stops renewing (which is what a partition IS), the lease expires,
// and Core's own ExpireLeases decides the job's fate — the same function the
// running Sweeper calls, invoked here out of band only to remove the 10 s timing
// dependency. Nothing reaches into the scan point.
//
// Work is observed through result_submissions.lease_epoch: a re-scan can only
// happen under a NEW lease epoch (a fresh Grant on a requeued job), so the job
// being scanned exactly once is exactly "one distinct submitting epoch". A
// requeue-everything bug turns that into two, and also leaves the job completing
// rather than failing — which is the immediate assertion the sabotage trips.
//
// This sabotage binds because the test calls ExpireLeases IN-PROCESS (the
// out-of-band expiry below), where -overlay applies — not inside cvap-core,
// which the harness builds as a separate binary the overlay cannot reach. The
// mutant requeues the non-reassign_safe job, and the immediate jobStatus check
// sees 'queued' instead of 'failed'. (Contrast F2, whose decision runs only in
// the binary and is sabotaged at the unit layer — ADR-056.)
//
// mutate:subject internal/store/leases.go
// mutate:test    ./test/e2e/ -run TestNonReassignSafeJobFailsAndIsNotRescanned
//
// mutate:case    every expired lease is requeued, ignoring reassign_safe
// mutate:old     		   SET status = CASE WHEN j.reassign_safe THEN 'queued'::job_status
// mutate:new     		   SET status = CASE WHEN true THEN 'queued'::job_status
func TestNonReassignSafeJobFailsAndIsNotRescanned(t *testing.T) {
	h := newSlowHarness(t)
	h.setReassignSafe(false)
	h.startCore()
	h.startScanPoint()

	// Wait until the job is genuinely running under a lease, then a beat so the
	// engine is mid-scan rather than just spawned.
	var epoch int64
	eventually(t, "the job to be leased", 40*time.Second, func() bool {
		e, err := h.currentLease()
		if err != nil {
			return false
		}
		epoch = e
		return true
	})
	time.Sleep(1500 * time.Millisecond)
	if h.observationCount() >= taskCount {
		t.Skip("the job finished before its lease could be expired; raise slowPerTarget")
	}

	// The partition: the scan point stopped renewing long enough to expire, and
	// Core's ExpireLeases runs. For a non-reassign_safe job this is where
	// at-most-once is won — the job must go to failed/lease_lost, not back to the
	// queue (leases.go). Expiring out of band uses the real function; the
	// backdate is only because clock_timestamp() has not reached the 60 s TTL.
	if err := h.db.Write(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := c.Exec(ctx,
			`UPDATE job_leases SET expires_at = clock_timestamp() - interval '1 second'
			  WHERE tenant_id = $1 AND job_id = $2 AND epoch = $3 AND state = 'granted'`,
			c.Tenant().UUID(), h.jobID, epoch); err != nil {
			return err
		}
		_, err := (store.Leases{}).ExpireLeases(ctx, c, 100)
		return err
	}); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	// Immediate, because ExpireLeases decided synchronously: a non-reassign_safe
	// job is failed with lease_lost. Under the requeue-everything sabotage it is
	// 'queued' here instead, and this trips before any re-scan can even begin.
	status, reason := h.jobStatus()
	if status != string(store.JobFailed) {
		t.Fatalf("job status %q after lease loss, want failed; a non-reassign_safe job put "+
			"back in the queue is one about to be scanned a second time (ADR-012)", status)
	}
	if reason == nil || *reason != string(store.TerminationLeaseLost) {
		t.Errorf("termination_reason = %v, want lease_lost", reason)
	}

	// The scan point notices the lost lease on its next renewal, self-aborts, and
	// submits what it gathered marked incomplete. That is the ONE submission this
	// job may ever produce.
	eventually(t, "the incomplete submission from the self-abort", 60*time.Second, func() bool {
		for _, s := range h.submissions() {
			if s.Incomplete {
				return true
			}
		}
		return false
	})

	// The work assertion. A second scan of these targets could only arrive under
	// a second lease epoch; there must be exactly one. Give a requeue+rescan the
	// time it would need to appear before concluding it did not.
	time.Sleep(3 * time.Second)
	epochs := h.submissionEpochs()
	if len(epochs) != 1 {
		t.Fatalf("submissions span %d lease epochs (%v); more than one means the targets were "+
			"scanned again — the double-scan ADR-012 forbids", len(epochs), epochs)
	}
	if epochs[0] != epoch {
		t.Errorf("the only submission is at epoch %d, want the original %d", epochs[0], epoch)
	}
	// And the job did not quietly complete on a second pass.
	if status, _ := h.jobStatus(); status != string(store.JobFailed) {
		t.Errorf("job status drifted to %q; a failed non-reassign_safe job must stay failed", status)
	}
}
