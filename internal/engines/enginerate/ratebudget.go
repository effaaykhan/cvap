// Package enginerate is the packet budget every engine that sends packets
// spends from.
//
// ============================================================================
// ONE implementation, because the safety gate asserts against ONE model.
// ============================================================================
//
// It started inside the discovery engine, which was right while discovery was
// the only thing with a socket. A second engine that sends packets makes it
// shared or duplicated, and duplicated is not an option here: `make safety`
// measures a wire-to-charged ratio against this model, and two copies means the
// gate binds whichever one the test happens to exercise while the other drifts.
//
// The three numbers that took a packet capture to get right — a sub-second
// burst, the SYN retransmit train, and three packets beyond the SYN for a
// connection that opens — are exactly the kind that get copied wrong.
package enginerate

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
type Bucket struct {
	mu       sync.Mutex
	capacity float64
	tokens   float64
	rate     float64 // tokens per second, the CURRENT rate
	ceiling  float64 // the allocation; rate may never exceed this
	last     time.Time
	now      func() time.Time
}

func New(ratePPS float64, now func() time.Time) *Bucket {
	if now == nil {
		now = time.Now
	}
	return &Bucket{
		capacity: BurstFor(ratePPS),
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
func BurstFor(ratePPS float64) float64 {
	burst := ratePPS / 10
	if burst < 1 {
		burst = 1
	}
	return burst
}

// takeN blocks until n tokens have been taken, or ctx ends.
//
// ============================================================================
// The budget is in PACKETS. A connect attempt is not one packet.
// ============================================================================
//
// ADR-024's table is packets per second and this bucket charged one token per
// connect ATTEMPT, which a packet-capture audit measured as 2.94 SYNs per
// attempt against a filtered host — so the 10 pps fragile cap was really about
// 29, and the looseness was worst exactly where the ceiling matters most, since
// retransmissions are what a slow or filtered embedded device produces.
//
// Amending ADR-024 to say "attempts" was the other repair and it is the wrong
// direction: the number that protects a device is packets it has to process,
// and a ceiling defined by whatever the implementation happened to count is not
// a ceiling.
//
// Charged one at a time rather than as a lump, so a multi-packet attempt is
// paced across the interval rather than draining a burst allowance at once.
func (b *Bucket) TakeN(ctx context.Context, n uint32) error {
	for range n {
		if err := b.Take(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Settle reconciles what an attempt was PRE-CHARGED with what it actually cost.
//
// ============================================================================
// Without this the bucket paces on SYNs alone, and everything after the
// handshake is free.
// ============================================================================
//
// A safety audit measured it: the caller took SynCost tokens before dialling and
// then reported a larger number — the ACK and FIN pair for a connection that
// opened, a TLS handshake, a probe payload — to the runtime's reclaim path,
// which does not pace anything. At ADR-024's 50 pps per target the fingerprint
// engine put 112 packets into a one-second window, 2.24x the ceiling, while the
// gate's wire-to-charged ratio read 1.01 because that ratio compares the wire
// against the REPORTED count and never against the tokens taken.
//
// Settling after the fact is the only order available — whether a port answers
// is not knowable before the attempt — so this does not prevent the first
// overshoot. What it does is make the overshoot cost the next attempts, which is
// what a token bucket is for and what keeps the sustained rate at the ceiling
// instead of a multiple of it.
//
// It also REFUNDS. A refused connection costs one packet against a SynCost of
// three, and a bucket that kept the difference would run a scan of mostly-closed
// ports at a third of the rate its operator asked for. The refund is capped at
// capacity, so it cannot bank a burst.
func (b *Bucket) Settle(ctx context.Context, prepaid, actual uint32) error {
	if actual > prepaid {
		return b.TakeN(ctx, actual-prepaid)
	}
	if actual < prepaid {
		b.refund(prepaid - actual)
	}
	return nil
}

func (b *Bucket) refund(n uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.tokens += float64(n)
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}

// synCost is how many SYNs the kernel sends before a connect times out.
//
// Linux retransmits a SYN on an exponential backoff from an initial RTO of one
// second, so the attempts land at t=0, 1, 3, 7, 15… A three-second connect
// timeout therefore costs three SYNs, which is what the audit measured (2.94,
// the shortfall being attempts that resolved before the last retransmit).
//
// A MODEL, not a count: the socket API does not report retransmissions, and
// reaching the number that did happen needs a raw socket this engine
// deliberately does not have (ADR-047). It errs high — the boundary case counts
// the retransmit that races the timeout — because a ceiling that guesses low is
// not a ceiling.
func SynCost(timeout time.Duration) uint32 {
	if timeout <= 0 {
		return 1
	}
	syns := uint32(1)
	// Cumulative delay before the i-th retransmit: 2^i - 1 seconds.
	for i := 1; i <= 6; i++ {
		delay := time.Duration((1<<uint(i))-1) * time.Second
		if delay > timeout {
			break
		}
		syns++
	}
	return syns
}

// EstablishedCost is what a connection that actually opens costs BEYOND its
// SYN: the ACK completing the handshake, the FIN closing it, and the ACK of the
// peer's FIN.
//
// Three, arrived at by MEASURING rather than by counting the diagram. Two was
// the first value and the safety gate reported a wire-to-charged ratio of 1.18
// — an eighteen percent undercount, which is the direction a ceiling must never
// lean. At three the model and the wire agree.
//
// Charged after the fact, because whether a port answers is not knowable before
// the attempt. The peer's own packets are not charged: the ceiling is about what
// this scan point sends.
const EstablishedCost = 3

// take blocks until one token is available or ctx ends.
//
// Returns ctx.Err() on cancellation so a kill switch is not delayed by the rate
// limiter — ADR-024 bounds propagation at 10 seconds and a token wait must not
// eat into that.
func (b *Bucket) Take(ctx context.Context) error {
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
func (b *Bucket) BackOff() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.rate /= 2
	if b.rate < MinRatePPS {
		b.rate = MinRatePPS
	}
	// CAPACITY comes down with the rate, or backing off is decorative.
	//
	// The first version halved rate and left capacity alone, so a scan adaptively
	// slowed to 3 pps against a struggling host still banked a burst sized for
	// the original allocation — and spent it the moment the host paused long
	// enough to look idle. Backing off is a statement about how hard this host
	// may be pushed, and a burst ceiling is part of that statement.
	b.capacity = BurstFor(b.rate)
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
}

// currentRate is for reporting and for tests.
func (b *Bucket) CurrentRate() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.rate
}

// MinRatePPS is the floor back-off will not go below.
const MinRatePPS = 0.5
