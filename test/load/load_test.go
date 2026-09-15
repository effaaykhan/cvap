package load

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/api"
	"github.com/effaaykhan/cvap/internal/control/credential"
	"github.com/effaaykhan/cvap/internal/store"
)

const loadPassword = "correct horse battery staple"

// hashLoadPassword hashes the seeded operator's password with the SAME encoder
// the login endpoint verifies against — credential.Hash, not a copy. This test
// once carried its own argon2id encoder because the api hasher was test-only;
// extracting internal/control/credential removed the reason for the copy, so the
// copy is gone. If the parameters change, they change in one place and this
// still verifies.
func hashLoadPassword(t *testing.T, password string) string {
	t.Helper()
	phc, err := credential.Hash(password)
	if err != nil {
		t.Fatalf("credential.Hash: %v", err)
	}
	return phc
}

// Published SLOs (execution-plan §5). Coarse = 2x (or /2 for throughput):
// order-of-magnitude, because a regression that matters — a dropped index, a
// lost partition prune, an N+1 from a new join — is order-of-magnitude, while a
// gate at 1.2x catches nothing extra and fires on runner noise (ADR).
const (
	assetListSLOms   = 300
	findingListSLOms = 500
	ingestSLOops     = 5000
)

// loadFix is a tenant with a loginnable operator and an in-process API server,
// so list latency is measured through the real handler chain (RLS, the keyset
// query, JSON serialization) — the "API" the SLO names — without a socket.
type loadFix struct {
	db     *store.DB
	tenant store.TenantID
	domain string
	email  string
	srv    *api.Server
}

func newLoadFix(t *testing.T, db *store.DB) *loadFix {
	t.Helper()
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	domain := "t" + strings.ReplaceAll(uuid.NewString(), "-", "")[:20] + ".test"
	f := &loadFix{db: db, tenant: tenant, domain: domain, email: "op@" + domain}

	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		if _, err := (store.Tenants{}).Create(ctx, c, "load-"+domain, domain, store.DeploymentOnPrem); err != nil {
			return err
		}
		role, err := (store.Roles{}).Create(ctx, c, "operator", []byte(`{"asset.read":true,"finding.read":true}`))
		if err != nil {
			return err
		}
		user, err := (store.Users{}).Create(ctx, c, role.ID, f.email, "local")
		if err != nil {
			return err
		}
		if err := (store.Users{}).SetStatus(ctx, c, user.ID, store.UserActive); err != nil {
			return err
		}
		if err := (store.AuthConfigs{}).Upsert(ctx, c, store.AuthConfig{Method: store.AuthLocal}, nil); err != nil {
			return err
		}
		return (store.Credentials{}).Set(ctx, c, user.ID, hashLoadPassword(t, loadPassword), false)
	}); err != nil {
		t.Fatalf("set up load tenant: %v", err)
	}

	srv, err := api.New(db, discardLogger(), api.Config{
		Version: "test", LocalAuthEnabled: true, Insecure: true,
		ListenAddr: "127.0.0.1:0", SessionTTL: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.srv = srv
	return f
}

func (f *loadFix) login(t *testing.T) []*http.Cookie {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(
		fmt.Sprintf(`{"email":%q,"password":%q}`, f.email, loadPassword)))
	r.Host = f.domain
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.srv.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	return w.Result().Cookies()
}

// getMS runs one GET through the handler and returns its latency in ms.
func (f *loadFix) getMS(t *testing.T, path string, cookies []*http.Cookie) float64 {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = f.domain
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	start := time.Now()
	f.srv.Handler().ServeHTTP(w, r)
	d := time.Since(start)
	if w.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
	}
	return float64(d.Microseconds()) / 1000
}

// sample is one measurement's outcome: the p95 of the requests that completed,
// how many did, and whether the budget cut the measurement short.
type sample struct {
	p95ms     float64
	completed int
	truncated bool
}

const (
	warmupRequests = 20
	sampleRequests = 300
)

// measurementBudget is the wall-clock budget ONE measurement gets: every request
// at the coarse ceiling. A measurement that cannot finish inside it has already
// failed the coarse ceiling on average, so stopping early loses nothing the gate
// would have said — and it is what keeps the first slow path from spending the
// whole job's timeout and silencing every measurement behind it (B47: one
// 15-minute budget across four measurements meant the exposure-2.4 variant, the
// exposure trend and ingest throughput reported nothing when the exposure-1.0
// finding list was slow; ADR-098).
func measurementBudget(coarseMs int) time.Duration {
	return time.Duration(warmupRequests+sampleRequests) * time.Duration(coarseMs) * time.Millisecond
}

// sampleP95 runs fn warmupRequests+sampleRequests times, discards the warmup and
// returns the p95 of what completed. It stops once budget is spent and says so.
func sampleP95(fn func() float64, budget time.Duration) sample {
	start := time.Now()
	lat := make([]float64, 0, sampleRequests)
	for i := 0; i < warmupRequests+sampleRequests; i++ {
		if time.Since(start) > budget {
			return sample{p95ms: p95(lat), completed: len(lat), truncated: true}
		}
		ms := fn()
		if i >= warmupRequests {
			lat = append(lat, ms)
		}
	}
	return sample{p95ms: p95(lat), completed: len(lat)}
}

// p95 of a sample; 0 for an empty one (a measurement truncated inside its warmup
// has no sample, and the gate reports that rather than a number).
func p95(lat []float64) float64 {
	if len(lat) == 0 {
		return 0
	}
	sorted := append([]float64(nil), lat...)
	sort.Float64s(sorted)
	return sorted[int(0.95*float64(len(sorted)))]
}

// p95ms measures steady-state p95 latency of a path (warmup discarded) within
// its own budget.
func (f *loadFix) p95ms(t *testing.T, path string, cookies []*http.Cookie, budget time.Duration) sample {
	t.Helper()
	return sampleP95(func() float64 { return f.getMS(t, path, cookies) }, budget)
}

// TestLoadSLOs seeds to capacity and measures each §5 SLO. The coarse ceiling is
// enforced always (including CI); the precise SLO only when CVAP_RUN_LOADTEST is
// set, because a p95 gate at the exact threshold flakes on shared CI runners and
// a gate people mute catches nothing. Every measured number is printed each run
// so the trend is visible before it crosses anything.
func TestLoadSLOs(t *testing.T) {
	db := testDB(t)
	precise := os.Getenv("CVAP_RUN_LOADTEST") != ""
	t.Logf("loadtest: precise SLO %s", map[bool]string{true: "ENFORCED (CVAP_RUN_LOADTEST set)", false: "NOT ENFORCED (CVAP_RUN_LOADTEST unset) — coarse ceiling only"}[precise])

	// Each measurement runs as its own subtest with its own budget, so a slow
	// path fails ITS gate and the ones after it still report (ADR-098). The
	// budgets are the per-measurement half of what the Makefile's -timeout is
	// the sum of; see the loadtest target.
	//
	// Tenant A: production-reality exposure (1.0 per finding). Carries the asset
	// and finding SLOs and the ingest measurement.
	a := newLoadFix(t, db)
	seedSynthetic(t, db, a.tenant, seedOpts{assets: 10000, findings: 50000, avgExposure: 1.0})
	ca := a.login(t)

	t.Run("asset list p95 @10k", func(t *testing.T) {
		gateLatency(t, precise, "asset list p95 @10k", a.p95ms(t, "/v1/assets?limit=50", ca, measurementBudget(2*assetListSLOms)), assetListSLOms)
	})
	t.Run("finding list p95 @50k, exposure 1.0", func(t *testing.T) {
		gateLatency(t, precise, "finding list p95 @50k, exposure 1.0", a.p95ms(t, "/v1/findings?limit=50", ca, measurementBudget(2*findingListSLOms)), findingListSLOms)
	})

	// Tenant B: the multi-vantage exposure (~2.4 per finding) the pipeline has
	// never produced but ADR-010's aggregation must survive. Since ADR-098 the
	// finding list computes its exposure count for the page only and joins the
	// external-zone set once, so exposure depth should no longer be visible in it —
	// this variant is what says whether that holds.
	b := newLoadFix(t, db)
	seedSynthetic(t, db, b.tenant, seedOpts{assets: 10000, findings: 50000, avgExposure: 2.4})
	cb := b.login(t)
	t.Run("finding list p95 @50k, exposure 2.4", func(t *testing.T) {
		gateLatency(t, precise, "finding list p95 @50k, exposure 2.4", b.p95ms(t, "/v1/findings?limit=50", cb, measurementBudget(2*findingListSLOms)), findingListSLOms)
	})

	// The exposure-by-zone endpoint is the UNPAGINATED ADR-010 aggregation — it
	// groups every finding_exposure row by zone, so unlike the finding LIST its
	// cost scales with exposure depth. There is no published SLO for it, so these
	// are reported for the trend and to answer "does the 2.4 distribution the
	// pipeline has never produced overshoot the aggregation?" — measured at both
	// variants rather than assumed. They borrow the finding list's coarse ceiling
	// as a budget: a truncated trend is reported as ">1 s per request", not failed,
	// because no SLO is published for it (ADR-058).
	t.Run("exposure-by-zone p95 @50k, exposure 1.0", func(t *testing.T) {
		reportTrend(t, "exposure-by-zone p95 @50k, exposure 1.0", a.p95ms(t, "/v1/exposure", ca, measurementBudget(2*findingListSLOms)))
	})
	t.Run("exposure-by-zone p95 @50k, exposure 2.4", func(t *testing.T) {
		reportTrend(t, "exposure-by-zone p95 @50k, exposure 2.4", b.p95ms(t, "/v1/exposure", cb, measurementBudget(2*findingListSLOms)))
	})

	t.Run("observation insert throughput", func(t *testing.T) {
		gateThroughput(t, precise, "observation insert throughput", measureIngestOps(t, db, a.tenant), ingestSLOops)
	})
}

// measureIngestOps measures observation store-insert throughput (obs/sec) — the
// ingest service's per-observation cost. The service's per-chunk epoch/task
// checks are amortised at 5000 obs/chunk and are covered for correctness by the
// dispatch ingest tests, so the per-obs throughput lives in InsertBatch.
func measureIngestOps(t *testing.T, db *store.DB, tenant store.TenantID) float64 {
	t.Helper()
	const chunk = 5000
	// A submission + task to hang observations from.
	var subID = "ingest-" + uuid.NewString()
	var taskID, spID, zoneID uuid.UUID
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "iz-"+uuid.NewString()[:8], store.ZoneInternal, 1, "")
		if err != nil {
			return err
		}
		zoneID = z.ID
		sp, err := (store.ScanPoints{}).Create(ctx, c, z.ID, "isp", "1", "v1", "fp-"+uuid.NewString())
		if err != nil {
			return err
		}
		spID = sp.ID
		jobID, tID, err := seedJobAndTask(ctx, c, sp.ID)
		if err != nil {
			return err
		}
		taskID = tID
		_, err = (store.Submissions{}).Begin(ctx, c, subID, jobID, 1, store.SubmitAccepted, false, "")
		return err
	}); err != nil {
		t.Fatalf("ingest setup: %v", err)
	}

	batch := make([]store.Observation, chunk)
	conf := 0.5
	for i := range batch {
		batch[i] = store.Observation{
			ID: uuid.New(), SubmissionID: subID, TaskID: taskID, ScanPointID: spID, ZoneID: zoneID,
			Type: store.ObsHost, Payload: []byte(`{"probed":false}`), Confidence: &conf, ObservedAt: time.Now(),
		}
	}
	const rounds = 4
	start := time.Now()
	for r := 0; r < rounds; r++ {
		for i := range batch {
			batch[i].ID = uuid.New() // unique per insert
		}
		if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
			return (store.Observations{}).InsertBatch(ctx, c, batch, store.IngestPending)
		}); err != nil {
			t.Fatalf("insert batch: %v", err)
		}
	}
	return float64(chunk*rounds) / time.Since(start).Seconds()
}

// gateVerdict is the decision a gate reaches, separated from reporting it so the
// decision is a pure function a fast DB-free test can sabotage. Exactly one of
// the failed fields is ever true.
type gateVerdict struct {
	coarseFailed  bool
	preciseFailed bool
}

// checkLatency is the LATENCY gate's decision. The coarse ceiling (2x the SLO) is
// enforced always; the precise SLO only when precise is set. The two are separate
// comparisons on purpose, so a change to one cannot silently move the other —
// gate_test.go sabotages each independently.
func checkLatency(measuredMs float64, sloMs int, precise bool) gateVerdict {
	coarseMs := 2 * sloMs
	if measuredMs > float64(coarseMs) {
		return gateVerdict{coarseFailed: true}
	}
	if precise && measuredMs > float64(sloMs) {
		return gateVerdict{preciseFailed: true}
	}
	return gateVerdict{}
}

// checkThroughput is the THROUGHPUT gate's decision — a floor rather than a
// ceiling, so the coarse bound is SLO/2 and the comparison is <.
func checkThroughput(measured float64, slo int, precise bool) gateVerdict {
	coarse := slo / 2
	if measured < float64(coarse) {
		return gateVerdict{coarseFailed: true}
	}
	if precise && measured < float64(slo) {
		return gateVerdict{preciseFailed: true}
	}
	return gateVerdict{}
}

func gateLatency(t *testing.T, precise bool, name string, s sample, sloMs int) {
	t.Helper()
	coarse := 2 * sloMs
	if s.truncated {
		// The measurement could not finish inside warmup+sample requests at the
		// coarse ceiling each: it has failed the coarse ceiling on average, and
		// the sample it did complete is printed so the reader sees the number
		// rather than a timeout. The gates after this one still run.
		t.Errorf("%s: measurement exceeded its budget (%d requests at the %dms coarse ceiling) after %d completed — "+
			"p95 of the completed sample %.0fms — order-of-magnitude regression",
			name, warmupRequests+sampleRequests, coarse, s.completed, s.p95ms)
		return
	}
	measuredMs := s.p95ms
	t.Logf("loadtest: %s = %.0fms", name, measuredMs)
	switch v := checkLatency(measuredMs, sloMs, precise); {
	case v.coarseFailed:
		t.Errorf("%s: coarse ceiling FAILED (p95 %.0fms > %dms) — order-of-magnitude regression", name, measuredMs, coarse)
	case v.preciseFailed:
		t.Errorf("%s: precise SLO FAILED (p95 %.0fms > %dms)", name, measuredMs, sloMs)
	case precise:
		t.Logf("loadtest: %s coarse PASSED (%.0fms < %dms), precise SLO PASSED (%.0fms < %dms)",
			name, measuredMs, coarse, measuredMs, sloMs)
	default:
		t.Logf("loadtest: %s coarse ceiling PASSED (p95 %.0fms < %dms), precise SLO NOT ENFORCED (CVAP_RUN_LOADTEST unset)",
			name, measuredMs, coarse)
	}
}

// reportTrend prints a measurement that has no published SLO. A truncated one is
// printed as such — the number a reader would otherwise infer from a timeout.
func reportTrend(t *testing.T, name string, s sample) {
	t.Helper()
	if s.truncated {
		t.Logf("loadtest: %s TRUNCATED after %d completed requests (budget %d at %dms each); p95 of the sample %.0fms (no published SLO)",
			name, s.completed, warmupRequests+sampleRequests, 2*findingListSLOms, s.p95ms)
		return
	}
	t.Logf("loadtest: %s = %.0fms (no published SLO)", name, s.p95ms)
}

func gateThroughput(t *testing.T, precise bool, name string, measured float64, slo int) {
	t.Helper()
	coarse := slo / 2
	t.Logf("loadtest: %s = %.0f/sec", name, measured)
	switch v := checkThroughput(measured, slo, precise); {
	case v.coarseFailed:
		t.Errorf("%s: coarse floor FAILED (%.0f/sec < %d/sec) — order-of-magnitude regression", name, measured, coarse)
	case v.preciseFailed:
		t.Errorf("%s: precise SLO FAILED (%.0f/sec < %d/sec)", name, measured, slo)
	case precise:
		t.Logf("loadtest: %s coarse PASSED (%.0f/sec > %d/sec), precise SLO PASSED (%.0f/sec > %d/sec)",
			name, measured, coarse, measured, slo)
	default:
		t.Logf("loadtest: %s coarse floor PASSED (%.0f/sec > %d/sec), precise SLO NOT ENFORCED (CVAP_RUN_LOADTEST unset)",
			name, measured, coarse)
	}
}
