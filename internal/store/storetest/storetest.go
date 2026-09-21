// Package storetest is what a database-backed test needs and the store must
// not offer production: cleaning up the tenant a test created.
//
// Every fixture in the tree creates a tenant and, until S43, left it behind:
// 20 000 of them accumulated in the dev database in five days, every
// correlation sweep aged each of them, and the correlate suite went from
// nineteen seconds to forty minutes — which is how a gate stops being run
// (phase-session-map §5.14). A fixture that leaves its tenant behind is the same
// shape as the instrument that left .146's findings closed and made an
// acceptance vacuous (§5.13): state left by a previous run, read by the next.
package storetest

import (
	"context"
	"testing"

	"github.com/effaaykhan/cvap/internal/store"
)

// CleanupTenant deletes the tenant — and, through the schema's ON DELETE
// CASCADE, everything the test wrote under it — when the test ends. Register it
// as soon as the tenant id exists: a delete of a tenant that was never created
// is a no-op, and a fixture that fails half-way still cleans up. The write runs
// under the tenant's own context, which the tenants policy permits, so no
// unscoped path is needed.
//
// BulkBudget, not the 30 s default (ADR-101): this DELETE cascades across 50
// foreign keys over 64 tables and was measured at 173 s cold on a fresh
// database. On the operator budget the cleanup timed out and, because the
// failure was only logged, the suite stayed green while the tenant stayed
// behind — which is exactly how the dev database reached 20 051 tenants and
// took the correlate suite from 19 seconds to 40 minutes.
//
// And the failure is now an ERROR, not a log line. A leftover is not a
// cosmetic problem: it is silently paid back by every later run, and a gate
// that passes while leaving the mess is the kind that gets trusted. The test's
// own verdict has already been recorded by the time Cleanup runs, so this
// cannot mask a real result — it can only add a failure that names the tenant.
func CleanupTenant(t testing.TB, db *store.DB, tenant store.TenantID) {
	t.Helper()
	t.Cleanup(func() {
		err := db.WriteWithin(context.Background(), tenant, store.BulkBudget, func(ctx context.Context, c *store.Conn) error {
			_, err := c.Exec(ctx, `DELETE FROM tenants WHERE tenant_id = $1`, tenant.UUID())
			return err
		})
		if err != nil {
			t.Errorf("storetest: tenant %s was NOT cleaned up and is now a permanent "+
				"fixture of this database: %v", tenant, err)
		}
	})
}
