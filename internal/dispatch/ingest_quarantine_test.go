package dispatch_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	scanpointv1 "github.com/effaaykhan/cvap/gen/cybersentinel/scanpoint/v1"
	"github.com/effaaykhan/cvap/internal/store"
)

// A quarantine raised in a chunk that is then refused as malformed must still
// reach the ledger (ADR-095). errMalformed rolls the chunk's transaction back
// on purpose, and that rollback took the refusal record with it — the
// internal/store CLAUDE.md shape: a scan point could probe the package, zone
// and task gates indefinitely and leave no trace. The record is rewritten in a
// fresh transaction on that path.
func TestAQuarantineRaisedInAMalformedChunkIsStillRecorded(t *testing.T) {
	db := testDB(t)
	svc := newIngestService(t, db)
	tenant, leaf, spID := enrolledScanPoint(t, db)
	jobID, taskID, zoneID, epoch := leased(t, db, tenant, spID)

	subID := "sub-" + uuid.NewString()
	bad := chunk(subID, jobID, epoch, 1, false, taskID, zoneID, 2)
	bad.Observations[0].ObservationType = "package" // gate violation: a discovery job
	bad.Observations[0].Payload = []byte(`{"address":"203.0.113.77","family":"ubuntu","release":"hardy","release_source":"os-release","installed":[]}`)
	bad.Observations[1].Confidence = 2.0 // malformed: the chunk is refused

	runIngest(t, svc, leaf, chunk(subID, jobID, epoch, 0, false, taskID, zoneID, 1))
	ack := runIngest(t, svc, leaf, bad).lastAck(t)
	if ack.GetStatus() != scanpointv1.SubmitStatus_REJECTED_MALFORMED {
		t.Fatalf("malformed chunk acked %v, want REJECTED_MALFORMED", ack.GetStatus())
	}
	var status string
	var reason *string
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT status::text, quarantine_reason FROM result_submissions WHERE tenant_id = $1 AND submission_id = $2`,
			c.Tenant().UUID(), subID).Scan(&status, &reason)
	}); err != nil {
		t.Fatal(err)
	}
	if status != "accepted_quarantined" || reason == nil {
		t.Fatalf("ledger after a quarantine raised in a malformed chunk: status=%s reason=%v; the refusal record must survive the rollback", status, reason)
	}
}
