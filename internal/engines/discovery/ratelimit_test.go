package discovery

import (
	"context"
	"testing"
	"time"
)

// Mutations, declared beside the tests that must kill them.
//
// mutate:subject internal/engines/discovery/ratelimit.go
// mutate:test    ./internal/engines/discovery/ -run TestTheBucket|TestBackOff|TestTakeHonours
//
// mutate:case    the bucket starts full, bursting at the rate ceiling
// mutate:old     capacity: cap, tokens: 1,
// mutate:new     capacity: cap, tokens: cap,
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
