package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// seedZonedPoint creates a zone and an online discovery-capable scan point in
// it, returning both ids. seedScanPoint does the same and discards the zone,
// which is exactly the value every test in this file is about.
func seedZonedPoint(t *testing.T, db *store.DB, tenant store.TenantID) (zoneID, spID uuid.UUID) {
	t.Helper()
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "zone-"+uuid.NewString()[:8], store.ZoneInternal, 50, "")
		if err != nil {
			return err
		}
		zoneID = z.ID
		sp, err := (store.ScanPoints{}).Create(ctx, c, z.ID, "sp", "0.1.0", "v1", "fp-"+uuid.NewString())
		if err != nil {
			return err
		}
		spID = sp.ID
		if err := (store.ScanPoints{}).Heartbeat(ctx, c, sp.ID, time.Now()); err != nil {
			return err
		}
		_, err = (store.ScanPoints{}).DeclareCapability(ctx, c, sp.ID, store.EngineDiscovery, "0.1.0", true)
		return err
	}); err != nil {
		t.Fatalf("seed zoned scan point: %v", err)
	}
	return zoneID, spID
}

// policyJob is the policy -> scan -> authorised target -> job -> task chain,
// with the policy columns this file exercises set explicitly.
type policyJob struct {
	PolicyID uuid.UUID
	ScanID   uuid.UUID
	JobID    uuid.UUID
}

// seedPolicyJob builds that chain. allowedZones and timeWindows are raw jsonb;
// pass "[]" for the unrestricted case, which is what every existing row holds.
func seedPolicyJob(t *testing.T, db *store.DB, tenant store.TenantID, safetyMode, allowedZones, timeWindows string) policyJob {
	t.Helper()
	var pj policyJob
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name, safety_mode, allowed_zones, time_windows)
			 VALUES ($1,$2,$3::safety_mode,$4::jsonb,$5::jsonb) RETURNING policy_id`,
			tid, "pol-"+uuid.NewString()[:8], safetyMode, allowedZones, timeWindows).Scan(&pj.PolicyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1,$2,'discovery')
			 RETURNING scan_id`, tid, pj.PolicyID).Scan(&pj.ScanID); err != nil {
			return err
		}
		var targetID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value,
			                           authorization_verified, verified_at)
			 VALUES ($1,$2,'cidr','192.0.2.0/24',true,now()) RETURNING target_id`,
			tid, pj.ScanID).Scan(&targetID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',true) RETURNING job_id`,
			tid, pj.ScanID).Scan(&pj.JobID); err != nil {
			return err
		}
		// 192.0.2.0/24 is TEST-NET-1: reserved for documentation, never routed,
		// and already in lab/scope.txt.
		_, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
			 VALUES ($1,$2,$3,'192.0.2.1')`, tid, pj.JobID, targetID)
		return err
	}); err != nil {
		t.Fatalf("seed policy job: %v", err)
	}
	return pj
}

func claimCount(t *testing.T, db *store.DB, tenant store.TenantID, spID uuid.UUID, closed []uuid.UUID) int {
	t.Helper()
	var n int
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, spID, []store.Engine{store.EngineDiscovery}, 10, closed)
		n = len(jobs)
		return err
	}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	return n
}

// ============================================================================
// allowed_zones
// ============================================================================

// TestAScanPointOutsideAllowedZonesCannotClaim closes a gap a safety audit
// found: the column was selected by nothing, so an operator restricting a scan
// to their DMZ had written a comment.
//
// The empty case is the other half, and it runs the OPPOSITE way to
// allowed_targets (ADR-037). Every scan_policies row that exists defaults to
// '[]', so reading empty as deny-all would have stopped the fleet on the
// migration that enforced this.
func TestAScanPointOutsideAllowedZonesCannotClaim(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "zones-"+uuid.NewString()[:8])

	zoneA, spA := seedZonedPoint(t, db, tenant)
	zoneB, _ := seedZonedPoint(t, db, tenant)

	t.Run("a policy naming another zone refuses the claim", func(t *testing.T) {
		seedPolicyJob(t, db, tenant, "safe", `["`+zoneB.String()+`"]`, "[]")
		if n := claimCount(t, db, tenant, spA, nil); n != 0 {
			t.Errorf("claimed %d jobs from a zone the policy does not allow, want 0", n)
		}
	})

	t.Run("a policy naming this zone allows it", func(t *testing.T) {
		seedPolicyJob(t, db, tenant, "safe", `["`+zoneA.String()+`"]`, "[]")
		if n := claimCount(t, db, tenant, spA, nil); n != 1 {
			t.Errorf("claimed %d jobs from the zone the policy allows, want 1", n)
		}
	})

	t.Run("an empty allowed_zones is unrestricted", func(t *testing.T) {
		seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
		if n := claimCount(t, db, tenant, spA, nil); n != 1 {
			t.Errorf("claimed %d jobs under a policy with no zone restriction, want 1. "+
				"Empty means unrestricted for a list that enumerates constraint (ADR-037); "+
				"the other reading stops every policy that exists today.", n)
		}
	})

	t.Run("a zone list naming neither zone refuses", func(t *testing.T) {
		seedPolicyJob(t, db, tenant, "safe", `["`+uuid.NewString()+`"]`, "[]")
		if n := claimCount(t, db, tenant, spA, nil); n != 0 {
			t.Errorf("claimed %d jobs against a zone list that names no real zone, want 0", n)
		}
	})
}

// ============================================================================
// time_windows
// ============================================================================

// TestAClosedWindowLeavesTheJobQueued is the property that makes maintenance
// windows survivable.
//
// A job outside its window must not be claimed and then put back: Claim
// increments attempt, MaxAttempts is 5, and the dispatch poll is two seconds, so
// claim-and-release would burn the job in ten seconds and the window would
// destroy the scan it was written to protect. Queued, untouched, attempt zero.
func TestAClosedWindowLeavesTheJobQueued(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "windows-"+uuid.NewString()[:8])
	_, spID := seedZonedPoint(t, db, tenant)

	pj := seedPolicyJob(t, db, tenant, "safe", "[]",
		`[{"start":"22:00","end":"04:00"}]`)

	if n := claimCount(t, db, tenant, spID, []uuid.UUID{pj.PolicyID}); n != 0 {
		t.Errorf("claimed %d jobs under a policy outside its maintenance window, want 0", n)
	}

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		j, err := (store.Jobs{}).GetByID(ctx, c, pj.JobID)
		if err != nil {
			return err
		}
		if j.Status != store.JobQueued {
			t.Errorf("job status = %q, want %q — a closed window defers work, it does not fail it",
				j.Status, store.JobQueued)
		}
		if j.Attempt != 0 {
			t.Errorf("attempt = %d, want 0. Burning an attempt per poll reaches MaxAttempts "+
				"in ten seconds and kills the scan the window exists to protect.", j.Attempt)
		}
		if j.ScanPointID != nil {
			t.Errorf("scan_point_id = %v, want nil", j.ScanPointID)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Same job, window open: the exclusion list is the only thing that changed.
	if n := claimCount(t, db, tenant, spID, nil); n != 1 {
		t.Errorf("claimed %d jobs inside the window, want 1 — if this is 0 the case above "+
			"proves nothing", n)
	}
}

// TestWithTimeWindowsReturnsOnlyRestrictedPolicies asserts the read dispatch
// makes on every poll stays narrow, and that an unrestricted policy is absent
// rather than present-and-empty.
func TestWithTimeWindowsReturnsOnlyRestrictedPolicies(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "windowed-"+uuid.NewString()[:8])

	unrestricted := seedPolicyJob(t, db, tenant, "safe", "[]", "[]")
	restricted := seedPolicyJob(t, db, tenant, "safe", "[]",
		`[{"start":"22:00","end":"04:00","days":["sat"],"tz":"Europe/London"}]`)

	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		got, err := (store.Policies{}).WithTimeWindows(ctx, c)
		if err != nil {
			return err
		}
		if len(got) != 1 {
			t.Fatalf("WithTimeWindows returned %d policies, want 1", len(got))
		}
		if got[0].PolicyID != restricted.PolicyID {
			t.Errorf("returned policy %v, want the restricted one %v", got[0].PolicyID, restricted.PolicyID)
		}
		if len(got[0].TimeWindows) == 0 {
			t.Error("time_windows came back empty; dispatch has nothing to evaluate")
		}
		_ = unrestricted
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestTimeWindowsAndAllowedZonesMustBeArrays is the container-type CHECK from
// migration 0024. Everything inside is validated in Core, fail-closed; this is
// the one thing the database can hold on its own, and it also stops
// jsonb_array_length in the partial index from erroring on a non-array.
func TestTimeWindowsAndAllowedZonesMustBeArrays(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db, "arrays-"+uuid.NewString()[:8])

	for _, tc := range []struct{ name, zones, windows string }{
		{"an object for time_windows", "[]", `{"start":"22:00"}`},
		{"a string for allowed_zones", `"dmz"`, "[]"},
		{"a number for time_windows", "[]", "3"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
				_, err := c.Exec(ctx,
					`INSERT INTO scan_policies (tenant_id, name, allowed_zones, time_windows)
					 VALUES ($1,$2,$3::jsonb,$4::jsonb)`,
					c.Tenant().UUID(), "bad-"+uuid.NewString()[:8], tc.zones, tc.windows)
				return err
			})
			if err == nil {
				t.Error("the database accepted a non-array in a column dispatch iterates over")
			}
		})
	}
}
