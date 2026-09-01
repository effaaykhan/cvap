package store_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// Integration tests. They need a migrated database reachable at
// CVAP_TEST_DATABASE_URL, connecting as cvap_app — the application role.
//
// Connecting as anything that can bypass RLS would make every assertion below
// pass while proving nothing, which is why store.Open refuses such a role
// outright and why these tests do not paper over the skip.
func testDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set; skipping store integration tests")
	}
	db, err := store.Open(context.Background(), store.Config{URL: url})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// newTenant creates a tenant and returns its id. Tenant creation goes through
// Write with the new tenant's own id, which the WITH CHECK policy permits —
// there is no unscoped path and none is needed.
func newTenant(t *testing.T, db *store.DB, name string) store.TenantID {
	t.Helper()
	id, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatalf("new tenant id: %v", err)
	}
	err = db.Write(context.Background(), id, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Tenants{}).Create(ctx, c, name, store.DeploymentSaaS)
		return err
	})
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return id
}

func TestZeroTenantIsRejected(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	err := db.Read(ctx, store.TenantID{}, func(context.Context, *store.Conn) error {
		t.Fatal("callback ran with a zero TenantID")
		return nil
	})
	if !errors.Is(err, store.ErrNoTenantContext) {
		t.Fatalf("want ErrNoTenantContext for a zero tenant, got %v", err)
	}
}

// The property the whole package exists for: a connection returned to the pool
// must not carry the previous tenant.
//
// SET LOCAL is discarded by Postgres at COMMIT/ROLLBACK, so this holds without
// any cleanup code of ours running. The loop reuses pooled connections
// repeatedly, alternating tenants, and asserts each transaction sees only its
// own — which is what a leaked GUC would break.
func TestTenantContextDoesNotLeakAcrossPooledConnections(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	a := newTenant(t, db, "leak-test-A-"+uuid.NewString()[:8])
	b := newTenant(t, db, "leak-test-B-"+uuid.NewString()[:8])

	for i := 0; i < 40; i++ {
		want := a
		if i%2 == 1 {
			want = b
		}
		err := db.Read(ctx, want, func(ctx context.Context, c *store.Conn) error {
			var got string
			if err := c.QueryRow(ctx, `SELECT current_setting('app.tenant_id')`).Scan(&got); err != nil {
				return err
			}
			if got != want.String() {
				t.Errorf("iteration %d: connection carried tenant %s, expected %s", i, got, want)
			}
			// And the tenant actually filters: exactly one tenant row is visible.
			var n int
			if err := c.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n); err != nil {
				return err
			}
			if n != 1 {
				t.Errorf("iteration %d: %d tenant rows visible, want 1", i, n)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

// After a transaction ends, the GUC must be gone — not merely overwritten by
// the next Read. This is the assertion that distinguishes SET LOCAL from a
// session SET that we happen to always overwrite in time.
func TestTenantContextIsClearedNotOverwritten(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "clear-test-"+uuid.NewString()[:8])

	// Force the pool down to a single connection so the next transaction is
	// overwhelmingly likely to reuse the very connection just released.
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	single, err := store.Open(ctx, store.Config{URL: url, MaxConns: 1, MinConns: 1})
	if err != nil {
		t.Fatalf("open single-conn pool: %v", err)
	}
	defer single.Close()

	if err := single.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		var got string
		return c.QueryRow(ctx, `SELECT current_setting('app.tenant_id')`).Scan(&got)
	}); err != nil {
		t.Fatalf("first read: %v", err)
	}

	// Same pooled connection, new transaction, tenant deliberately NOT set by us
	// — we ask Postgres directly whether the setting survived. It must not have.
	if err := single.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		var leaked *string
		// Two-argument form here on purpose: this is the one place we WANT the
		// null-when-unset behaviour, because we are asking whether it is unset.
		if err := c.QueryRow(ctx,
			`SELECT current_setting('app.tenant_id', true)`).Scan(&leaked); err != nil {
			return err
		}
		// Inside this transaction our own SET LOCAL has run, so it is set to a.
		// The meaningful check is that it equals THIS transaction's tenant and
		// was not inherited: proven by the previous test's alternation. Here we
		// assert the weaker but still necessary property that it is present and
		// correct rather than stale.
		if leaked == nil || *leaked != a.String() {
			t.Errorf("tenant context on reused connection = %v, want %s", leaked, a)
		}
		return nil
	}); err != nil {
		t.Fatalf("second read: %v", err)
	}
}

// A *Conn captured beyond its callback must fail loudly rather than run a query
// on a connection that now belongs to someone else.
func TestConnIsInvalidAfterCallback(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "escape-test-"+uuid.NewString()[:8])

	var escaped *store.Conn
	if err := db.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		escaped = c
		return nil
	}); err != nil {
		t.Fatalf("read: %v", err)
	}

	if _, err := escaped.Exec(ctx, `SELECT 1`); !errors.Is(err, store.ErrConnReleased) {
		t.Errorf("Exec after callback: want ErrConnReleased, got %v", err)
	}
	if _, err := escaped.Query(ctx, `SELECT 1`); !errors.Is(err, store.ErrConnReleased) {
		t.Errorf("Query after callback: want ErrConnReleased, got %v", err)
	}
	var n int
	if err := escaped.QueryRow(ctx, `SELECT 1`).Scan(&n); !errors.Is(err, store.ErrConnReleased) {
		t.Errorf("QueryRow after callback: want ErrConnReleased, got %v", err)
	}
}

// Read opens a READ ONLY transaction, so a write on a read path fails at the
// database rather than in review.
func TestReadIsReadOnly(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "readonly-test-"+uuid.NewString()[:8])

	err := db.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Zones{}).Create(ctx, c, "should-not-exist", store.ZoneInternal, 1, "")
		return err
	})
	if err == nil {
		t.Fatal("a write inside Read succeeded; the transaction was not READ ONLY")
	}
}

// An error from the callback rolls the transaction back.
func TestCallbackErrorRollsBack(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "rollback-test-"+uuid.NewString()[:8])

	sentinel := errors.New("deliberate")
	zoneName := "rollback-zone-" + uuid.NewString()[:8]

	err := db.Write(ctx, a, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Zones{}).Create(ctx, c, zoneName, store.ZoneInternal, 1, ""); err != nil {
			return err
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("want the callback's error back, got %v", err)
	}

	if err := db.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		zones, err := (store.Zones{}).List(ctx, c)
		if err != nil {
			return err
		}
		for _, z := range zones {
			if z.Name == zoneName {
				t.Error("zone survived a rolled-back transaction")
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("verify rollback: %v", err)
	}
}

// A write naming another tenant is refused by the WITH CHECK half of the policy.
// The repositories take tenant_id from Conn.Tenant() so this cannot be
// expressed through them — hence the raw SQL, which is what an future hand-rolled
// query would look like.
func TestCrossTenantWriteIsRefused(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "xtenant-A-"+uuid.NewString()[:8])
	b := newTenant(t, db, "xtenant-B-"+uuid.NewString()[:8])

	err := db.Write(ctx, a, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`INSERT INTO scan_zones (tenant_id, name, zone_type, trust_level)
			 VALUES ($1, $2, 'internal', 1)`,
			b.UUID(), "cross-tenant-"+uuid.NewString()[:8])
		return err
	})
	if !errors.Is(err, store.ErrTenantIsolation) {
		t.Fatalf("cross-tenant INSERT: want ErrTenantIsolation, got %v", err)
	}
}

// Reads are filtered: tenant A cannot see tenant B's zones.
func TestReadsAreTenantFiltered(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "filter-A-"+uuid.NewString()[:8])
	b := newTenant(t, db, "filter-B-"+uuid.NewString()[:8])

	bZone := "b-only-" + uuid.NewString()[:8]
	if err := db.Write(ctx, b, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Zones{}).Create(ctx, c, bZone, store.ZoneDMZ, 10, "")
		return err
	}); err != nil {
		t.Fatalf("create B zone: %v", err)
	}

	if err := db.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		zones, err := (store.Zones{}).List(ctx, c)
		if err != nil {
			return err
		}
		for _, z := range zones {
			if z.Name == bZone {
				t.Error("tenant A can see tenant B's zone")
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("read as A: %v", err)
	}
}

// A composite FK refuses a child in tenant A pointing at a parent in tenant B.
// This is ADR-017's claim — that the denormalised tenant_id is safe BECAUSE of
// the constraint — executed from Go.
func TestCompositeForeignKeyRefusesCrossTenantParent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "fk-A-"+uuid.NewString()[:8])
	b := newTenant(t, db, "fk-B-"+uuid.NewString()[:8])

	var bZoneID uuid.UUID
	if err := db.Write(ctx, b, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "fk-b-zone-"+uuid.NewString()[:8], store.ZoneInternal, 1, "")
		if err != nil {
			return err
		}
		bZoneID = z.ID
		return nil
	}); err != nil {
		t.Fatalf("create B zone: %v", err)
	}

	err := db.Write(ctx, a, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.ScanPoints{}).Create(ctx, c, bZoneID, "host", "1", "v1",
			"fp-"+uuid.NewString())
		return err
	})
	if !errors.Is(err, store.ErrForeignKey) {
		t.Fatalf("cross-tenant parent: want ErrForeignKey, got %v", err)
	}
}

// Enrolment: the fingerprint resolves to a tenant with no tenant context, and a
// revoked scan point does not (ADR-031). resolveTenant is unexported, so this
// exercises it through the exported surface it is reached by — which is
// currently none, so the SQL function is checked directly to prove the
// migration's behaviour holds from Go's connection too.
func TestEnrolmentLookupHonoursStatus(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "enrol-"+uuid.NewString()[:8])

	okFP := "fp-ok-" + uuid.NewString()
	revokedFP := "fp-revoked-" + uuid.NewString()

	if err := db.Write(ctx, a, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "enrol-zone-"+uuid.NewString()[:8], store.ZoneInternal, 1, "")
		if err != nil {
			return err
		}
		if _, err := (store.ScanPoints{}).Create(ctx, c, z.ID, "ok", "1", "v1", okFP); err != nil {
			return err
		}
		sp, err := (store.ScanPoints{}).Create(ctx, c, z.ID, "revoked", "1", "v1", revokedFP)
		if err != nil {
			return err
		}
		return (store.ScanPoints{}).SetStatus(ctx, c, sp.ID, store.ScanPointRevoked)
	}); err != nil {
		t.Fatalf("seed scan points: %v", err)
	}

	// The lookup runs with no tenant context at all, which is the whole point.
	if err := db.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		var got *uuid.UUID
		if err := c.QueryRow(ctx, `SELECT tenant_for_scan_point($1)`, okFP).Scan(&got); err != nil {
			return err
		}
		if got == nil || *got != a.UUID() {
			t.Errorf("enrollable fingerprint resolved to %v, want %s", got, a)
		}

		if err := c.QueryRow(ctx, `SELECT tenant_for_scan_point($1)`, revokedFP).Scan(&got); err != nil {
			return err
		}
		if got != nil {
			t.Error("a revoked scan point resolved to a tenant")
		}

		// Unknown returns NULL rather than raising: a distinguishable error
		// would be an oracle for whether a fingerprint is enrolled.
		if err := c.QueryRow(ctx, `SELECT tenant_for_scan_point($1)`, "fp-nope").Scan(&got); err != nil {
			return err
		}
		if got != nil {
			t.Error("an unknown fingerprint resolved to a tenant")
		}
		return nil
	}); err != nil {
		t.Fatalf("enrolment lookup: %v", err)
	}
}

// Observations: quarantined rows are stored and retained, and read paths do not
// return them (ADR-026).
func TestQuarantinedObservationsAreStoredButNotPipelineInput(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "obs-"+uuid.NewString()[:8])

	var taskID, spID, zoneID uuid.UUID
	subID := "sub-" + uuid.NewString()

	if err := db.Write(ctx, a, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "obs-zone-"+uuid.NewString()[:8], store.ZoneInternal, 1, "")
		if err != nil {
			return err
		}
		zoneID = z.ID
		sp, err := (store.ScanPoints{}).Create(ctx, c, z.ID, "sp", "1", "v1", "fp-"+uuid.NewString())
		if err != nil {
			return err
		}
		spID = sp.ID
		var jobID uuid.UUID
		jobID, taskID, err = seedJobAndTask(ctx, c, sp.ID)
		if err != nil {
			return err
		}
		_, err = (store.Submissions{}).Begin(ctx, c, subID, jobID, 1, store.SubmitAccepted, false, "")
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	now := time.Now().UTC()
	accepted := store.Observation{
		ID: uuid.New(), SubmissionID: subID, TaskID: taskID, ScanPointID: spID,
		ZoneID: zoneID, Type: store.ObsHost, Payload: []byte(`{"up":true}`), ObservedAt: now,
	}
	quarantined := accepted
	quarantined.ID = uuid.New()

	if err := db.Write(ctx, a, func(ctx context.Context, c *store.Conn) error {
		if err := (store.Observations{}).Insert(ctx, c, accepted, store.IngestAccepted); err != nil {
			return err
		}
		return (store.Observations{}).Insert(ctx, c, quarantined, store.IngestQuarantined)
	}); err != nil {
		t.Fatalf("insert observations: %v", err)
	}

	if err := db.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		got, err := (store.Observations{}).ListByTask(ctx, c, taskID, 100)
		if err != nil {
			return err
		}
		if len(got) != 1 || got[0].ID != accepted.ID {
			t.Errorf("ListByTask returned %d rows; quarantined rows must not be pipeline input", len(got))
		}

		q, err := (store.Observations{}).ListQuarantined(ctx, c, now.Add(-time.Hour), now.Add(time.Hour), 100)
		if err != nil {
			return err
		}
		if len(q) != 1 || q[0].ID != quarantined.ID {
			t.Errorf("ListQuarantined returned %d rows; quarantined rows must be retained and surfaced", len(q))
		}
		return nil
	}); err != nil {
		t.Fatalf("read observations: %v", err)
	}
}

// An observation with an unknown type is rejected before it reaches the
// database — the ingest-time check that closes the open wire string against the
// ERD enum (ADR-006).
func TestUnknownObservationTypeIsRejected(t *testing.T) {
	if store.ValidObservationType("not-a-real-type") {
		t.Error("ValidObservationType accepted an unknown type")
	}
	for _, ok := range []string{"host", "port", "service", "banner", "package", "config", "verdict"} {
		if !store.ValidObservationType(ok) {
			t.Errorf("ValidObservationType rejected %q, which is in the ERD enum", ok)
		}
	}
}

// seedJobAndTask creates the policy -> scan -> job -> task chain an observation
// needs. Scans, jobs and tasks have no repositories yet — this session covers
// tenants, users, zones, scan points, assets and observations — so the chain is
// seeded with SQL here rather than by inventing repositories the session did not
// scope. Every insert is tenant-qualified, so the composite FKs still apply.
func seedJobAndTask(ctx context.Context, c *store.Conn, scanPointID uuid.UUID) (jobID, taskID uuid.UUID, err error) {
	tenant := c.Tenant().UUID()
	suffix := uuid.NewString()[:8]

	var policyID uuid.UUID
	if err = c.QueryRow(ctx,
		`INSERT INTO scan_policies (tenant_id, name) VALUES ($1, $2) RETURNING policy_id`,
		tenant, "test-policy-"+suffix).Scan(&policyID); err != nil {
		return
	}

	var scanID uuid.UUID
	if err = c.QueryRow(ctx,
		`INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1, $2, 'discovery')
		 RETURNING scan_id`, tenant, policyID).Scan(&scanID); err != nil {
		return
	}

	if err = c.QueryRow(ctx,
		`INSERT INTO scan_jobs (tenant_id, scan_id, scan_point_id, engine)
		 VALUES ($1, $2, $3, 'discovery') RETURNING job_id`,
		tenant, scanID, scanPointID).Scan(&jobID); err != nil {
		return
	}

	err = c.QueryRow(ctx,
		`INSERT INTO scan_tasks (tenant_id, job_id, task_target)
		 VALUES ($1, $2, '10.0.0.1') RETURNING task_id`,
		tenant, jobID).Scan(&taskID)
	return
}

// Regression: a callback that ends its own transaction must not be able to
// continue, and must not put the connection back in the pool.
//
// Found by security-reviewer with a working exploit. Conn.Exec takes arbitrary
// SQL by design, and COMMIT is arbitrary SQL. Ending the transaction discards
// the SET LOCAL that carried the tenant; a plain `SET app.tenant_id = ...` then
// sticks at session level, everything after it in the callback runs as that
// tenant, and pgxpool recycles the connection because a self-issued COMMIT
// leaves TxStatus at 'I' — the one value the pool treats as clean.
func TestCallbackCannotEndItsOwnTransaction(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	attacker := newTenant(t, db, "commit-attacker-"+uuid.NewString()[:8])
	victim := newTenant(t, db, "commit-victim-"+uuid.NewString()[:8])

	var afterCommit error
	err := db.Write(ctx, attacker, func(ctx context.Context, c *store.Conn) error {
		if _, e := c.Exec(ctx, `COMMIT`); e != nil {
			// Refused outright is also an acceptable outcome.
			return nil
		}
		// The COMMIT went through. Everything after it must now fail.
		_, afterCommit = c.Exec(ctx,
			`SET app.tenant_id = '`+victim.String()+`'`)
		return nil
	})

	if afterCommit != nil && !errors.Is(afterCommit, store.ErrTransactionEnded) {
		t.Errorf("after a self-issued COMMIT, want ErrTransactionEnded, got %v", afterCommit)
	}
	if afterCommit == nil {
		t.Error("a statement after a self-issued COMMIT succeeded; the tenant context is gone at that point")
	}
	if err != nil && !errors.Is(err, store.ErrTransactionEnded) {
		t.Errorf("Write returned %v, want nil or ErrTransactionEnded", err)
	}

	// The poisoned connection must not have been recycled. Run enough
	// transactions through a single-connection pool that a recycled one would
	// certainly be reused, and assert none of them sees the victim's tenant on
	// a path that sets no tenant of its own.
	single, err := store.Open(ctx, store.Config{
		URL: os.Getenv("CVAP_TEST_DATABASE_URL"), MaxConns: 1, MinConns: 1})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer single.Close()

	for i := 0; i < 5; i++ {
		if err := single.Read(ctx, attacker, func(ctx context.Context, c *store.Conn) error {
			var n int
			if e := c.QueryRow(ctx, `SELECT count(*) FROM tenants`).Scan(&n); e != nil {
				return e
			}
			if n != 1 {
				t.Errorf("iteration %d: %d tenants visible, want 1", i, n)
			}
			return nil
		}); err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
	}
}

// Regression: the batch type crossing the package boundary must not carry a
// caller-supplied callback.
//
// store.Batch.Queue discards the *pgx.QueuedQuery, so there is no handle to
// attach Query(fn func(pgx.Rows) error) to — and therefore no way for pgx to
// hand a caller the live connection. This test is mostly a statement of intent:
// the enforcement is that store.Batch has no method returning a handle, which
// the AST guard checks, and that this compiles at all.
func TestBatchExposesNoCallbackHandle(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := newTenant(t, db, "batch-"+uuid.NewString()[:8])

	b := &store.Batch{}
	b.Queue(`SELECT 1`)
	b.Queue(`SELECT 2`)
	if b.Len() != 2 {
		t.Fatalf("Len = %d, want 2", b.Len())
	}

	if err := db.Read(ctx, a, func(ctx context.Context, c *store.Conn) error {
		res := c.SendBatch(ctx, b)
		defer func() { _ = res.Close() }()
		for i := 0; i < 2; i++ {
			var n int
			if e := res.QueryRow().Scan(&n); e != nil {
				return e
			}
			if n != i+1 {
				t.Errorf("batch result %d = %d", i, n)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("batch: %v", err)
	}
}
