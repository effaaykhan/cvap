package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/store"
)

// ============================================================================
// F2 — a submission at a superseded epoch is ACCEPTED_QUARANTINED, end to end.
// ============================================================================
//
// ADR-026's reversal turns on a three-way distinction — accepted, quarantined,
// rejected — and the quarantine arm is the subtle one: results from a scan point
// whose lease was superseded are STORED but WITHHELD from the finding pipeline,
// never dropped and never processed. The store/ingest logic has unit coverage
// (TestSupersededEpochIsQuarantinedNotDropped); what has not been observed is a
// REAL scan point submitting at a stale epoch over real gRPC and the verdict
// coming out ACCEPTED_QUARANTINED. TestSelfAbortOnLeaseLoss permits either
// accepted or quarantined by design; this pins the quarantine.
//
// The partition-then-heal is the same real mechanism the self-abort test uses:
// the lease is released and a HIGHER epoch granted (a reassignment), so the scan
// point's in-flight submission, still stamped with the old epoch, is superseded
// by the time it lands. checkEpoch (ingest.go) compares submitted vs current and
// quarantines the lower.
//
// "Not processed" is asserted directly: the read paths filter
// ingest_state='accepted', so zero accepted observations means the finding
// pipeline can never see them. "Not dropped" is the quarantined count being
// positive and the submission being stored, not REJECTED.
//
// This test carries NO mutate declaration, and that is deliberate rather than an
// omission. checkEpoch runs inside cvap-core, which the harness builds as a
// separate binary with `go build` — a subprocess that does not inherit `go
// test`'s -overlay, so an overlay mutation cannot reach it and would test
// nothing here. The logic's sabotage lives at the unit layer, on
// TestSupersededEpochIsQuarantinedNotDropped (internal/dispatch/ingest_test.go),
// where the overlay bites; this test is the end-to-end observation the unit test
// cannot give. Same principle as the build-tag rule (ADR-056): a sabotage the
// deployed binary's test cannot experience is not a sabotage.
func TestSupersededSubmissionIsQuarantinedEndToEnd(t *testing.T) {
	h := newSlowHarness(t)
	h.startCore()
	h.startScanPoint()

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
		t.Skip("the job finished before its lease could be superseded; raise slowPerTarget")
	}

	// Heal-with-reassignment: release the current lease and grant a higher epoch
	// to the same scan point. The scan point has not renewed yet, so its terminal
	// submission still carries the old epoch — which is now superseded. This is
	// exactly what a reassignment after a partition does, done with the real
	// functions.
	if err := h.db.Write(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Leases{}).ReleaseAny(ctx, c, h.jobID, epoch, store.LeaseLost); err != nil {
			return err
		}
		_, err := (store.Leases{}).Grant(ctx, c, h.jobID, h.enrolledScanPoint(), store.LeaseTTL)
		return err
	}); err != nil {
		t.Fatalf("supersede the lease: %v", err)
	}
	t.Logf("superseded epoch %d with %d", epoch, epoch+1)

	// The scan point self-aborts on its next renewal and submits what it gathered
	// at the now-stale epoch. That submission must be quarantined, and quarantined
	// for THE SUPERSEDED EPOCH specifically — a quarantine for some other reason
	// (zone, unknown task) would satisfy a bare status check while the epoch
	// fencing was skipped, which is exactly what the sabotage removes. So the
	// assertion is on the reason, not just the status.
	var found submissionRow
	eventually(t, "the stale-epoch submission to be quarantined", 60*time.Second, func() bool {
		for _, s := range h.submissions() {
			if store.SubmitStatus(s.Status) == store.SubmitAcceptedQuarantined {
				found = s
				return true
			}
		}
		return false
	})
	if store.SubmitStatus(found.Status) != store.SubmitAcceptedQuarantined {
		t.Fatalf("submission status = %q, want accepted_quarantined; a submission at a "+
			"superseded epoch must be stored and withheld, not accepted (ADR-026)", found.Status)
	}
	if found.QuarantineReason == nil || !strings.Contains(*found.QuarantineReason, "superseded") {
		t.Fatalf("quarantine reason = %v, want one naming the superseded epoch; a quarantine "+
			"for any other reason means the epoch fencing was skipped", found.QuarantineReason)
	}

	// Give any in-flight promotion a moment to settle, then prove the three-way
	// distinction with the observation ledger.
	time.Sleep(2 * time.Second)
	accepted, quarantined := h.observationStates()
	if accepted != 0 {
		t.Errorf("%d observations are accepted; a superseded submission must not reach the "+
			"finding pipeline — the read paths filter ingest_state='accepted'", accepted)
	}
	if quarantined == 0 {
		t.Error("no observations were quarantined; the results were dropped rather than " +
			"stored-and-withheld, which is the failure ADR-026 exists to prevent")
	}
	// Not silent. ADR-026's quarantine leaves an audit trail for the operator
	// investigating a fencing event.
	if h.quarantineAuditCount() == 0 {
		t.Error("no submission.quarantined audit event; the quarantine was silent")
	}
}
