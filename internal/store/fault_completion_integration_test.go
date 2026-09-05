package store_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// ============================================================================
// F1a — a non-reassign_safe job is COMPLETED by at most one scan point.
// ============================================================================
//
// This is the store half of F1 (ADR-012). The e2e half (fault_partition e2e)
// asserts the operationally-important thing — that at most one scan point
// SENDS PACKETS at the targets — because ADR-012 exists to stop a production
// host being double-scanned, not to keep a status column tidy. This half proves
// the DB seam that makes that true: Jobs.Terminate's predicate.
//
// Forced interleaving, the way session 7 forced token single-use with twelve
// goroutines at one token: the guarantee is a claim about a real race, and a
// sequential test cannot see a race lost. Twelve goroutines call Terminate at
// once, released by a barrier — six as the assigned holder, six as a DIFFERENT
// scan point. Exactly one may win, it must be the holder's, and the job must end
// completed exactly once.
//
// The two clauses this proves are BOTH load-bearing (jobs.go Terminate) and
// BOTH asserted below (winners==1 and byOther==0):
//
//	status IN ('assigned','running')  the first completion moves the job to a
//	                                  terminal status; a second Terminate then
//	                                  matches zero rows. Without it, the holder
//	                                  could complete a job twice.
//	scan_point_id = $3                the holder clause (an IDOR fix). Without
//	                                  it, a second scan point completes another's
//	                                  job — which is two scan points completing
//	                                  one job, the exact thing F1 forbids.
//
// The sabotage below removes the status gate; that alone drives winners past one
// and fails the test deterministically (8/8).
//
// The holder clause (scan_point_id = $3) is a SEPARATE property — one scan point
// must not complete another's job — and it is NOT reliably tested by this race:
// whether a dropped holder clause is caught depends on which racer wins the row
// lock, so byOther==0 can pass by luck (~75%). It is therefore proved
// deterministically by TestTerminateRefusesANonHolder below instead. That clause
// carries no DECLARED mutation because `scan_point_id = $3` is textually
// identical across five queries in jobs.go (Claim, MarkRunning, Terminate, …),
// so no single-line anchor is unique — the ADR-056 case of a property whose
// sabotage cannot be uniquely anchored. Its efficacy was verified by hand: a
// holder-less Terminate predicate kills TestTerminateRefusesANonHolder on every
// run, where it survived this race one time in four.
//
// mutate:subject internal/store/jobs.go
// mutate:test    ./internal/store/ -run TestNonReassignSafeJobCompletedByAtMostOneScanPoint
//
// mutate:case    a terminal job can be completed again (the status gate is gone)
// mutate:old     		   AND status IN ('assigned', 'running')
// mutate:new     		   AND status = status
func TestNonReassignSafeJobCompletedByAtMostOneScanPoint(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "f1a-"+uuid.NewString()[:8])

	holder := seedScanPoint(t, db, tenant)
	other := seedScanPoint(t, db, tenant)
	// reassign_safe = false: the job whose duplication ADR-012 says must never
	// happen silently. Nothing here reassigns it; the point is that even under a
	// completion race it terminates once, for one holder.
	jobID := seedJob(t, db, tenant, holder, false)

	// Assign it to the holder. Claim sets status='assigned' and scan_point_id,
	// which are exactly the two columns Terminate's predicate reads.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, holder, []store.Engine{store.EngineDiscovery}, 10, nil)
		if err != nil {
			return err
		}
		if len(jobs) != 1 || jobs[0].ID != jobID {
			t.Fatalf("claim assigned %d jobs, want the one seeded", len(jobs))
		}
		return nil
	}); err != nil {
		t.Fatalf("claim: %v", err)
	}

	const racers = 12
	// Even racers as the true holder, odd as a different scan point. Both report
	// TerminationCompleted; Core derives the status, so a mismatched holder is
	// not a different verb, it is the same completion aimed at a job it does not
	// hold — which is precisely how the IDOR looked on the wire.
	holders := make([]uuid.UUID, racers)
	for i := range holders {
		if i%2 == 0 {
			holders[i] = holder
		} else {
			holders[i] = other
		}
	}

	var wg sync.WaitGroup
	errs := make([]error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
				return (store.Jobs{}).Terminate(ctx, c, jobID, holders[i], store.TerminationCompleted)
			})
		}(i)
	}
	close(start)
	wg.Wait()

	winners, byOther := 0, 0
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
			if holders[i] != holder {
				byOther++
			}
		case errors.Is(err, store.ErrNotFound):
			// The refusal. Every loser sees exactly this: the job is already
			// terminal, or it was never theirs to complete.
		default:
			t.Errorf("racer %d: unexpected error %v", i, err)
		}
	}

	if winners != 1 {
		t.Fatalf("%d racers completed the job; a non-reassign_safe job completed more than "+
			"once is two scan points' worth of work on one target (ADR-012)", winners)
	}
	if byOther != 0 {
		t.Fatalf("%d completions came from a scan point that did not hold the job; the holder "+
			"clause is what stops one scan point completing another's work", byOther)
	}

	// The job is completed, once, by the holder — not failed, not held by anyone
	// else.
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		j, err := (store.Jobs{}).GetByID(ctx, c, jobID)
		if err != nil {
			return err
		}
		if j.Status != store.JobCompleted {
			t.Errorf("job status %q, want completed", j.Status)
		}
		if j.ScanPointID == nil || *j.ScanPointID != holder {
			t.Errorf("job held by %v, want the original holder %v", j.ScanPointID, holder)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// ============================================================================
// F1a, the holder half — a scan point cannot complete another's job.
// ============================================================================
//
// Terminate's `scan_point_id = $3` is an IDOR fix (jobs.go): without it, any
// scan point in the tenant completes any other's in-flight job, which fences the
// victim off its own work and — because the job is then terminal — no sweep ever
// recovers it. The concurrent race above cannot test this reliably (the outcome
// depends on who wins the row lock), so this proves it sequentially and
// deterministically: the non-holder is refused while the job is still assignable,
// the job is left untouched, and only the holder can complete it.
//
// No declared mutation: the `scan_point_id = $3` predicate is identical across
// five queries in jobs.go, so it has no unique single-line anchor for the mutate
// harness (ADR-056). Verified by hand instead — a holder-less predicate
// (scan_point_id compared to itself) makes this test fail on every run.
func TestTerminateRefusesANonHolder(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tenant := newTenant(t, db, "f1h-"+uuid.NewString()[:8])

	holder := seedScanPoint(t, db, tenant)
	other := seedScanPoint(t, db, tenant)
	jobID := seedJob(t, db, tenant, holder, false)

	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		jobs, err := (store.Jobs{}).Claim(ctx, c, holder, []store.Engine{store.EngineDiscovery}, 10, nil)
		if err != nil {
			return err
		}
		if len(jobs) != 1 {
			t.Fatalf("claim assigned %d jobs, want 1", len(jobs))
		}
		return nil
	}); err != nil {
		t.Fatalf("claim: %v", err)
	}

	// The non-holder's completion is refused — the job is still assignable, so
	// without the holder clause it would succeed.
	err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Jobs{}).Terminate(ctx, c, jobID, other, store.TerminationCompleted)
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a non-holder completed the job (got %v, want ErrNotFound); one scan point "+
			"can fence another off its own work (ADR-012 IDOR)", err)
	}

	// The job is untouched: still assigned to the holder, not terminal.
	if err := db.Read(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		j, err := (store.Jobs{}).GetByID(ctx, c, jobID)
		if err != nil {
			return err
		}
		if j.Status != store.JobAssigned {
			t.Errorf("job status %q after a non-holder's attempt, want still assigned", j.Status)
		}
		if j.ScanPointID == nil || *j.ScanPointID != holder {
			t.Errorf("job holder changed to %v, want %v", j.ScanPointID, holder)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The real holder completes it.
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Jobs{}).Terminate(ctx, c, jobID, holder, store.TerminationCompleted)
	}); err != nil {
		t.Fatalf("the holder could not complete its own job: %v", err)
	}
}
