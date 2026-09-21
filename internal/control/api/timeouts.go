package api

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/effaaykhan/cvap/internal/store"
)

// timeoutMeter counts budget timeouts per tenant, for the Health surface
// (ADR-101, B50).
//
// Per-tenant, not process-wide, and that is the whole reason this type exists
// rather than two atomic counters. A process-wide count is a cross-tenant
// signal: tenant A reading its own Health would learn that tenant B is running
// something slow. Every other number on HealthResponse is tenant-scoped by an
// RLS-protected query, and this one has to earn the same property in Go, since
// it is held in memory rather than in a table.
//
// What it does NOT claim:
//
//   - It is NOT durable. The counts live in this process and start at zero on
//     restart. A count of zero therefore means "none since this Core started",
//     not "none ever", and the Health field says so in its own doc string.
//   - It is NOT fleet-wide. Two Cores against one database each report their
//     own.
//
// Both limits are deliberate for this change: the bound is what B50 asks for,
// and a durable per-tenant timeout LEDGER is a table, a migration and a
// retention policy, which belongs in its own change rather than smuggled into
// this one. Recorded in ADR-101 as the part that is knowingly unfinished.
//
// The map is keyed by TenantID and grows with the number of tenants that have
// actually timed out, which is bounded by the tenant count and is zero in the
// healthy case.
type timeoutMeter struct {
	mu   sync.Mutex
	seen map[store.TenantID]timeoutTally
}

type timeoutTally struct {
	n    int
	last time.Time
	// anon counts timeouts on requests that never reached a session. Kept in
	// its OWN number because an anonymous caller can drive it at will — a
	// security review measured an unauthenticated login request moving a
	// tenant's count from 0 to 1, repeatable without limit (ADR-102). Mixing it
	// into `n` would let a stranger decide what an operator investigates.
	anon int
}

func newTimeoutMeter() *timeoutMeter {
	return &timeoutMeter{seen: map[store.TenantID]timeoutTally{}}
}

// note records one timeout against a tenant, in the bucket its trust level
// earns.
func (m *timeoutMeter) note(tenant store.TenantID, authenticated bool) {
	if m == nil || tenant.IsZero() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.seen[tenant]
	if authenticated {
		t.n++
		t.last = time.Now().UTC()
	} else {
		t.anon++
	}
	m.seen[tenant] = t
}

// read returns the authenticated count, the most recent authenticated timeout,
// and the anonymous count, for one tenant.
func (m *timeoutMeter) read(tenant store.TenantID) (int, *time.Time, int) {
	if m == nil || tenant.IsZero() {
		return 0, nil, 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.seen[tenant]
	if !ok {
		return 0, nil, 0
	}
	if t.n == 0 {
		return 0, nil, t.anon
	}
	last := t.last
	return t.n, &last, t.anon
}

// noteTimeout meters a budget timeout without changing the response.
//
// For the surfaces that must answer ONE status for every fault — login above
// all, where the status code is what an attacker reads (ADR-102) — the operator
// still needs to know the bound fired. This records it and logs it; the caller
// writes whatever response its own anti-oracle rules demand.
//
// A non-timeout error is ignored, so call sites can hand it whatever they have.
func (s *Server) noteTimeout(r *http.Request, err error) {
	if !errors.Is(err, store.ErrStatementTimeout) {
		return
	}
	s.log.Error("a transaction exceeded its time budget",
		"request_id", requestIDFrom(r.Context()),
		"method", r.Method, "path", r.URL.Path, "err", err)
	if tenant, ok := tenantFrom(r.Context()); ok {
		s.timeouts.note(tenant, authenticatedFrom(r.Context()))
	}
}

// authenticatedFrom reports whether this request reached a real session.
//
// The meter keys on it because an ANONYMOUS caller must not be able to move the
// number an operator reads to decide a query needs profiling. A security review
// measured an unauthenticated login request driving a tenant's
// timed_out_requests from 0 to 1, unbounded by repetition and poisoning
// last_timeout_at with it (ADR-102).
func authenticatedFrom(ctx context.Context) bool {
	_, ok := sessionFrom(ctx)
	return ok
}
