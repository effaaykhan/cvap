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
	// A one-second burst ceiling: larger lets a quiet period bank capacity and
	// then spend it at once at a host, which is the shape that tips a fragile
	// device over.
	cap := ratePPS
	if cap < 1 {
		cap = 1
	}

	// ========================================================================
	// It starts with ONE token, not a full bucket.
	// ========================================================================
	//
	// Starting full was the obvious thing and it is wrong at exactly the moment
	// the cap matters most. A fragile target is allocated 10 pps; a bucket
	// starting with 10 tokens lets the first ten connects go out back to back
	// with no pacing at all — a burst of ten at a device whose whole reason for
	// being capped is that it cannot take ten at once. The ceiling was honoured
	// on average and violated exactly when it counted.
	//
	// Found by measuring: a lab target holding one connection slot answered a
	// single paced port and dropped six that arrived together, and the six
	// arrived together because the bucket was pre-filled.
	//
	// One token, so the first packet leaves immediately and the second waits its
	// interval. The burst ceiling still applies once the scan has been running.
	return &bucket{
		capacity: cap, tokens: 1,
		rate: ratePPS, ceiling: ratePPS,
		last: now(), now: now,
	}
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
}

// currentRate is for reporting and for tests.
func (b *bucket) currentRate() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rate
}

// minRatePPS is the floor back-off will not go below.
const minRatePPS = 0.5
