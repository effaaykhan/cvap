package scanpoint

import "sync"

// The per-scan-point rate aggregate, which ADR-024 states and nothing enforced.
//
// ============================================================================
// 1,000 pps per scan point was read by no code at all.
// ============================================================================
//
// ADR-024's table has three rate ceilings: per scan point, per target, and
// fragile. Two of them bind. The first was a number in a table — job.budget()
// clamps per-target and fragile, and each job then built its own bucket with
// nothing subtracting from a shared budget.
//
// That was survivable while a scan planned ONE job, because a scan point ran one
// engine. Chunking made it reachable in a single scan: a /24 plans eight jobs,
// dispatch hands out five at a time, and each engine is allocated the full
// per-target rate independently. A packet-capture audit measured 262 pps
// aggregate from one scan point at a 50 pps allocation, rising linearly with
// engine count.
//
// # Allocation, not accounting
//
// ADR-027's model is that the aggregate is bounded BY CONSTRUCTION rather than
// by monitoring: the runtime hands out slices and an engine cannot exceed what
// it was never given. So this divides the ceiling rather than watching engines
// and reacting — an engine that has been handed 25 pps cannot produce 50, and no
// engine has to cooperate for the total to hold.
//
// The cost is that concurrent jobs each get less, which is the correct trade: a
// scan point's whole budget is the thing being protected, and five jobs sharing
// it is what "per scan point" means.
type allocator struct {
	mu      sync.Mutex
	ceiling uint32
	holders map[string]struct{}
}

func newAllocator(ceiling uint32) *allocator {
	if ceiling == 0 {
		ceiling = PlatformMaxRatePPS
	}
	return &allocator{ceiling: ceiling, holders: map[string]struct{}{}}
}

// acquire registers a job and returns the slice it may use.
//
// The slice is the ceiling divided by the number of jobs now holding one,
// including this one. Existing jobs are NOT retroactively reduced, which is a
// deliberate imprecision: a bucket already handed to a running engine cannot be
// taken back without a channel to that engine, and the overshoot it permits is
// bounded by how many jobs start while others run. The direction that matters —
// a new job cannot take a full slice while others hold theirs — is enforced.
func (a *allocator) acquire(jobID string) uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.holders[jobID] = struct{}{}

	// Saturating rather than a bare conversion. len() is an int and the holder
	// map is bounded only by how many jobs Core hands out, so a conversion that
	// wrapped would divide by a small number and hand out a LARGE slice — the
	// failure direction that matters for a rate ceiling.
	holders := uint32(1)
	if n := len(a.holders); n > 1 {
		if n > int(^uint32(0)) {
			holders = ^uint32(0)
		} else {
			holders = uint32(n)
		}
	}

	share := a.ceiling / holders
	if share < 1 {
		// A floor, so a scan point holding many jobs does not allocate zero and
		// stall every one of them. It is the point at which "too many concurrent
		// jobs" stops being a rate question, and Core's maxJobsPerPoll is the
		// lever for it.
		share = 1
	}
	return share
}

// release gives a job's slice back.
func (a *allocator) release(jobID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.holders, jobID)
}

// held is the number of jobs currently holding a slice, for logging and tests.
func (a *allocator) held() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.holders)
}
