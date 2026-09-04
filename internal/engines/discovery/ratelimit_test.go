package discovery

import (
	"context"
	"testing"
	"time"
)

// Mutations, declared beside the tests that must kill them.
//
// mutate:subject internal/engines/discovery/ratelimit.go
// mutate:test    ./internal/engines/discovery/ -run TestTheBucket|TestBackOff|TestTakeHonours|TestAnIdlePeriod
//
// The -run regex is part of the declaration and gets stale the same way an
// anchor does: two mutations survived because TestAnIdlePeriod — written in the
// same commit to kill one of them — was not in this list. `make mutate` caught
// it, which is the argument for running the gate before pushing rather than
// after.
//
// mutate:case    the bucket starts full, bursting at the rate ceiling
// mutate:old     tokens:   1,
// mutate:new     tokens:   ratePPS,
//
// `tokens: burstFor(ratePPS)` was the first form of this mutation and it
// SURVIVED — at the 10 pps the test uses, burstFor is 1, so the mutant was
// byte-for-byte the original behaviour. A mutation that changes nothing is a
// mutation that proves nothing. `ratePPS` is the original defect.
//
// mutate:case    an idle period re-banks a full second of burst
// mutate:old     burst := ratePPS / 10
// mutate:new     burst := ratePPS
//
// mutate:case    backing off leaves the burst ceiling where it was
// mutate:old     b.capacity = burstFor(b.rate)
// mutate:new     _ = burstFor(b.rate)
//
// mutate:case    back-off raises the rate instead of lowering it
// mutate:old     b.rate /= 2
// mutate:new     b.rate *= 2
//
// mutate:case    a token wait ignores cancellation
// mutate:old     case <-ctx.Done():
// mutate:new     case <-time.After(time.Hour):
//
// TestTheBucketStartsWithOneTokenNotAFullOne.
//
// ============================================================================
// A full bucket honours the ceiling on average and violates it exactly when it
// matters.
// ============================================================================
//
// A fragile target is allocated 10 pps. A bucket starting with ten tokens lets
// the first ten packets leave back to back — a burst of ten at a device whose
// whole reason for being capped is that it cannot take ten at once.
//
// Found by measuring, not by reading: a lab target holding one connection slot
// answered a single paced port and dropped six that arrived together, and the
// six arrived together because the bucket was pre-filled. With the fix the same
// target yields six banners at the cap and none at 500 pps, repeatably.
func TestTheBucketStartsWithOneTokenNotAFullOne(t *testing.T) {
	var now time.Time
	b := newBucket(10, func() time.Time { return now })

	// The first take is immediate: a scan should not wait to send its first
	// packet.
	if err := b.take(context.Background()); err != nil {
		t.Fatalf("first take: %v", err)
	}

	// The second must NOT be. With a pre-filled bucket it would be, nine times
	// over.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.take(ctx) }()

	select {
	case err := <-done:
		cancel()
		t.Fatalf("the second packet left immediately (%v); the bucket is pre-filled and the "+
			"rate ceiling is not being applied to the start of a scan", err)
	case <-time.After(50 * time.Millisecond):
		// Correct: it is waiting for a token.
	}
	cancel()

	// Bounded, not a bare receive.
	//
	// A bare `<-done` hangs forever against a take() that ignores cancellation —
	// which is exactly what one of this file's own mutations produces. That hung
	// the whole package's test binary until the 10-minute default timeout, so
	// `go test` printed no result lines at all and `make mutate` reported the
	// mutant as "ran no tests" rather than as killed. CI found it; running the
	// one test locally did not, because the hang was in a different test in the
	// same binary.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("take did not return after cancellation")
	}
}

// TestBackOffOnlyEverLowers.
//
// "Adaptive rate limiting" is adaptive in one direction. An adaptive limiter
// that could climb would be the engine deciding its own budget, which is what
// ADR-027's allocation model exists to prevent.
func TestBackOffOnlyEverLowers(t *testing.T) {
	b := newBucket(100, nil)
	start := b.currentRate()

	for range 5 {
		b.backOff()
	}
	if got := b.currentRate(); got >= start {
		t.Errorf("rate is %v after five back-offs, started at %v", got, start)
	}

	// And it has a floor, so a run of timeouts against a firewalled host cannot
	// drive the rate to zero and hang the task.
	for range 100 {
		b.backOff()
	}
	if got := b.currentRate(); got < minRatePPS {
		t.Errorf("rate fell to %v, below the floor %v", got, minRatePPS)
	}
	if b.currentRate() > b.ceiling {
		t.Error("back-off raised the rate above its allocation")
	}
}

// TestTakeHonoursCancellation. ADR-024 bounds kill propagation at 10 seconds and
// a token wait must not eat into it.
func TestTakeHonoursCancellation(t *testing.T) {
	b := newBucket(0.5, nil) // one token every two seconds
	if err := b.take(context.Background()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- b.take(ctx) }()
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Error("take returned nil after cancellation")
		}
	case <-time.After(2 * time.Second):
		t.Error("take did not return within 2s of cancellation; a kill switch would be " +
			"delayed by the rate limiter")
	}
}

// TestAnIdlePeriodDoesNotRebankAFullBurst.
//
// ============================================================================
// The half of the burst fix that the first attempt missed entirely.
// ============================================================================
//
// Starting the bucket at one token stopped the burst at t=0 and did nothing
// about refill: capacity stayed at the full per-second allocation, so any stall
// of capacity/rate seconds restored the whole burst. A packet-capture audit
// measured ten connects inside one millisecond at a device capped at ten per
// second — 500 pps against a 10 pps ceiling — after a 4.5 second stall.
//
// And the stall is the NORMAL path: probeAlive dials the discovery ports
// serially and blocks a full connect timeout on every silent one, so a quiet
// host banks a burst before the port scan even starts.
func TestAnIdlePeriodDoesNotRebankAFullBurst(t *testing.T) {
	now := time.Now()
	b := newBucket(10, func() time.Time { return now })

	// Spend the first token, then stall for far longer than the bucket could
	// ever need to refill.
	if err := b.take(context.Background()); err != nil {
		t.Fatal(err)
	}
	now = now.Add(10 * time.Second)

	// How many tokens are available without waiting? Each take that returns
	// immediately is a packet that leaves in the same instant as the last.
	immediate := 0
	for range 20 {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- b.take(ctx) }()
		select {
		case err := <-done:
			cancel()
			if err != nil {
				t.Fatalf("take: %v", err)
			}
			immediate++
		case <-time.After(30 * time.Millisecond):
			cancel()
			<-done
			goto counted
		}
	}
counted:
	// At 10 pps the burst ceiling is a tenth of a second's worth: one.
	if immediate > 2 {
		t.Errorf("after a 10s idle period, %d packets could leave in the same instant at a "+
			"10 pps cap. A device capped at ten per second cannot take ten at once, which "+
			"is the entire reason the cap exists.", immediate)
	}
}

// TestBackOffLowersTheBurstCeilingToo.
//
// Halving the rate and leaving capacity alone means a scan adaptively slowed to
// 3 pps against a struggling host still banks a burst sized for its original
// allocation, and spends it the moment the host pauses long enough to look idle.
func TestBackOffLowersTheBurstCeilingToo(t *testing.T) {
	now := time.Now()
	b := newBucket(100, func() time.Time { return now })

	before := b.capacity
	for range 5 {
		b.backOff()
	}
	if b.capacity >= before {
		t.Errorf("capacity is %v after five back-offs, started at %v — backing off is a "+
			"statement about how hard this host may be pushed, and a burst ceiling is "+
			"part of that statement", b.capacity, before)
	}
	if b.capacity > burstFor(b.rate) {
		t.Errorf("capacity %v exceeds the burst for the current rate %v", b.capacity, b.rate)
	}
}
