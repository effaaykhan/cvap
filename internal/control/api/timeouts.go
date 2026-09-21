package api

import (
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
}

func newTimeoutMeter() *timeoutMeter {
	return &timeoutMeter{seen: map[store.TenantID]timeoutTally{}}
}

// note records one timeout against a tenant.
func (m *timeoutMeter) note(tenant store.TenantID) {
	if m == nil || tenant.IsZero() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.seen[tenant]
	t.n++
	t.last = time.Now().UTC()
	m.seen[tenant] = t
}

// read returns the count and the most recent timeout for one tenant.
func (m *timeoutMeter) read(tenant store.TenantID) (int, *time.Time) {
	if m == nil || tenant.IsZero() {
		return 0, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.seen[tenant]
	if !ok || t.n == 0 {
		return 0, nil
	}
	last := t.last
	return t.n, &last
}
