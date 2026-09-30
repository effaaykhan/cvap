package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// Grant issue and delivery are two facts (migration 0053).
//
// Before the split, `credential.granted` and the grant row both committed inside
// the dispatch transaction and asserted a delivery that happened afterwards —
// and failed, measured at 4 of 9 trials, when the outbound queue was full. The
// record was not lost; it was WRONG, which on the credential path is worse. A
// missing audit is a gap. An audit saying a secret reached a fingerprint it never
// reached is evidence pointing at the wrong conclusion.
func seedGrant(t *testing.T, db *store.DB, tenant store.TenantID) uuid.UUID {
	t.Helper()
	var grantID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		suffix := uuid.NewString()[:8]
		var policyID, scanID, jobID, profileID uuid.UUID
		if err := c.QueryRow(ctx, `INSERT INTO scan_policies (tenant_id, name) VALUES ($1,$2) RETURNING policy_id`,
			tid, "grant-"+suffix).Scan(&policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `INSERT INTO scans (tenant_id, policy_id, scan_type, status)
			VALUES ($1,$2,'discovery','running') RETURNING scan_id`, tid, policyID).Scan(&scanID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `INSERT INTO scan_jobs (tenant_id, scan_id, engine, status)
			VALUES ($1,$2,'host','assigned') RETURNING job_id`, tid, scanID).Scan(&jobID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx, `INSERT INTO credential_profiles (tenant_id, name, username, cred_type, secret_ref)
			VALUES ($1,$2,'root','ssh','vault://test') RETURNING credential_profile_id`,
			tid, "prof-"+suffix).Scan(&profileID); err != nil {
			return err
		}
		var err error
		grantID, _, err = (store.CredentialGrants{}).Issue(ctx, c, store.GrantIssue{
			ProfileID: profileID, JobID: jobID, Kind: store.CredKindRawSecret,
			TargetScope: []string{"10.0.0.1"}, DeliveredToFingerprint: "SHA256:fp-" + suffix,
			TTL: time.Hour,
		})
		return err
	}); err != nil {
		t.Fatalf("seed grant: %v", err)
	}
	return grantID
}

func deliveredAt(t *testing.T, db *store.DB, tenant store.TenantID, id uuid.UUID) *time.Time {
	t.Helper()
	var at *time.Time
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT delivered_at FROM credential_grants WHERE tenant_id=$1 AND grant_id=$2`,
			tenant.UUID(), id).Scan(&at)
	}); err != nil {
		t.Fatal(err)
	}
	return at
}

// An issued grant is NOT delivered. This is the state that previously could not
// be expressed, and therefore could never be wrong.
func TestAnIssuedGrantIsNotDelivered(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "grant-issue")
	id := seedGrant(t, db, tenant)

	if at := deliveredAt(t, db, tenant, id); at != nil {
		t.Errorf("a freshly issued grant reports delivered_at = %v; issue is not delivery, and the row asserting otherwise is what B52 measured", *at)
	}

	var undelivered []uuid.UUID
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var e error
		undelivered, e = (store.CredentialGrants{}).Undelivered(ctx, c, 10)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if len(undelivered) != 1 || undelivered[0] != id {
		t.Errorf("Undelivered returned %v, want the one issued grant: 'issued but never delivered' must be queryable without joining an event against the absence of another", undelivered)
	}
}

// Delivery is recorded separately, and only once — a retry must not move the
// timestamp forward and make a late delivery look prompt.
func TestDeliveryIsRecordedOnceAndSeparately(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "grant-deliver")
	id := seedGrant(t, db, tenant)

	// AFTER issued_at, which the row sets with now() at sub-second precision.
	// Truncating to the second put delivery a fraction BEFORE issue and the
	// credential_grants_delivery_after_issue CHECK refused it — the constraint
	// working, and the test wrong.
	first := time.Now().UTC().Add(time.Second)
	mark := func(at time.Time) {
		if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
			return (store.CredentialGrants{}).MarkDelivered(ctx, c, id, at)
		}); err != nil {
			t.Fatal(err)
		}
	}
	mark(first)
	got := deliveredAt(t, db, tenant, id)
	if got == nil {
		t.Fatal("delivery was not recorded")
	}
	mark(first.Add(time.Hour))
	again := deliveredAt(t, db, tenant, id)
	if !again.Equal(*got) {
		t.Errorf("a second MarkDelivered moved delivered_at %v -> %v; it is idempotent on the first write so a retry cannot make a late delivery look prompt", *got, *again)
	}

	var undelivered []uuid.UUID
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		var e error
		undelivered, e = (store.CredentialGrants{}).Undelivered(ctx, c, 10)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if len(undelivered) != 0 {
		t.Errorf("a delivered grant still reads as undelivered: %v", undelivered)
	}
}

// The database refuses a grant zeroised on a scan point it never reached. Before
// 0053 that state was not expressible, so it was never wrong — the invariant the
// split exists to make checkable.
func TestAGrantCannotBeZeroisedWithoutBeingDelivered(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "grant-zeroise")
	id := seedGrant(t, db, tenant)

	err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, e := c.Exec(ctx, `UPDATE credential_grants SET zeroised_at = now()
		                      WHERE tenant_id=$1 AND grant_id=$2`, tenant.UUID(), id)
		return e
	})
	if err == nil {
		t.Fatal("zeroising an undelivered grant was ACCEPTED; a scan point cannot erase material it never received, and before 0053 nothing said so")
	}
}
