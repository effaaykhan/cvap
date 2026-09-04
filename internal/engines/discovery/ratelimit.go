package discovery

import (
	"context"
	"sync"
	"time"
)

// Rate limiting, and what "adaptive" is allowed to mean.
//
// ============================================================================
// It only ever goes DOWN. The allocation is a ceiling, never a starting point.
// ============================================================================
//
// ADR-027 gives the engine a slice of the runtime's budget and the aggregate is
// bounded by construction — the engine cannot exceed what it was never given.
// "Adaptive rate limiting" in the MVP scope is therefore adaptive in one
// direction: a target showing signs of distress lowers the rate, and nothing
// raises it above the allocation. An adaptive limiter that could climb would be
// the engine deciding its own budget, which is precisely what the allocation
// model exists to prevent.

// bucket is a token bucket, one per scope.
//
// A bucket rather than a sleep-between-sends, because the ceiling is a RATE and
// a fixed inter-packet delay makes it a rate only when nothing else is
// happening. Under concurrency, a delay per goroutine multiplies by the number
// of goroutines; a shared bucket does not.
type bucket struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	rate     float64 // tokens per second, the CURRENT rate
	ceiling  float64 // the allocation; rate may never exceed this
	last     time.Time
	now      func() time.Time
}

func newBucket(ratePPS float64, now func() time.Time) *bucket {
	if now == nil {
		now = time.Now
	}
	return &bucket{
		capacity: burstFor(ratePPS),
		tokens:   1,
		rate:     ratePPS, ceiling: ratePPS,
		last: now(), now: now,
	}
}

// burstFor is how many tokens may accumulate at a given rate.
//
// ============================================================================
// A TENTH of a second, not a whole one — and this is the second half of a fix
// whose first half only moved the problem three seconds later.
// ============================================================================
//
// Starting the bucket at one token stopped the burst at t=0. It did nothing
// about refill: capacity stayed at the full per-second allocation, so any idle
// period of capacity/rate seconds restored the entire burst. A packet-capture
// audit measured ten connects inside one millisecond at a device capped at ten
// per second — 500 pps against a 10 pps ceiling — after a 4.5 second stall.
//
// And the stall is the NORMAL path, not an edge case: probeAlive dials the
// discovery ports serially and blocks a full connect timeout on every silent
// one, so a quiet host banks a full burst before the port scan even starts.
//
// A sub-second burst is what makes the ceiling true at the timescale a device
// experiences. Ten per second means at most one per hundred milliseconds' worth
// of accumulation, which for a 10 pps fragile cap is a burst of one.
func burstFor(ratePPS float64) float64 {
	burst := ratePPS / 10
	if burst < 1 {
		burst = 1
	}
	return burst
}

// take blocks until one token is available or ctx ends.
//
// Returns ctx.Err() on cancellation so a kill switch is not delayed by the rate
// limiter — ADR-024 bounds propagation at 10 seconds and a token wait must not
// eat into that.
func (b *bucket) take(ctx context.Context) error {
	for {
		b.mu.Lock()
		now := b.now()
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.rate
			if b.tokens > b.capacity {
				b.tokens = b.capacity
			}
			b.last = now
		}
		if b.tokens >= 1 {
			b.tokens--
			b.mu.Unlock()
			return nil
		}
		// How long until one token exists at the current rate.
		wait := time.Duration((1 - b.tokens) / b.rate * float64(time.Second))
		b.mu.Unlock()

		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C:
		}
	}
}

// backOff halves the rate, down to a floor.
//
// Called when a target looks distressed — timeouts rather than refusals, which
// is what a host struggling to answer looks like as opposed to one that simply
// has the port closed. It never raises, so a scan that has slowed against a
// fragile host stays slow for the rest of that host's scan.
//
// The floor exists so a run of timeouts against a firewalled host cannot drive
// the rate to zero and hang the task; the connect timeout bounds each attempt
// anyway, so the slow case is slow rather than stuck.
func (b *bucket) backOff() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rate /= 2
	if b.rate < minRatePPS {
		b.rate = minRatePPS
	}
	// CAPACITY comes down with the rate, or backing off is decorative.
	//
	// The first version halved rate and left capacity alone, so a scan adaptively
	// slowed to 3 pps against a struggling host still banked a burst sized for
	// the original allocation — and spent it the moment the host paused long
	// enough to look idle. Backing off is a statement about how hard this host
	// may be pushed, and a burst ceiling is part of that statement.
	b.capacity = burstFor(b.rate)
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}

// currentRate is for reporting and for tests.
func (b *bucket) currentRate() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rate
}

// minRatePPS is the floor back-off will not go below.
const minRatePPS = 0.5
