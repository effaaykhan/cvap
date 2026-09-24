package correlate_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// An open port is durable evidence (ADR-103).
//
// Before this, a discovery scan of two real /24s produced 110 `port`
// observations across 25 assets and left `services` EMPTY, because correlation
// dropped every observation that was not type "service". The console showed
// assets it knew nothing about, the rules had no input, and the port data was
// pruned with the observation.

// observePort inserts a discovery `port` observation, which the shared observe
// helper cannot do — it hardcodes ObsService.
func (s seeded) observePort(t *testing.T, db *store.DB, at time.Time, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	conf := 0.95
	o := store.Observation{
		ID: uuid.New(), SubmissionID: s.subID, TaskID: s.taskID, ScanPointID: s.spID,
		ZoneID: s.zoneID, Type: store.ObsPort, Payload: body,
		Confidence: &conf, ObservedAt: at,
	}
	if err := db.Write(context.Background(), s.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Observations{}).Insert(ctx, c, o, store.IngestAccepted)
	}); err != nil {
		t.Fatalf("insert port observation: %v", err)
	}
}

// httpService is an identified service on an arbitrary port, for the upgrade
// half of the merge test.
func httpService(address string, port int) map[string]any {
	return map[string]any{
		"address": address, "port": port, "protocol": "tcp",
		"service": "http", "product": "nginx", "version": "1.24.0",
		"method": "banner", "solicited": true, "safety_mode": "safe",
	}
}

func portObs(address string, port int, state string) map[string]any {
	return map[string]any{
		"address": address, "port": port, "protocol": "tcp",
		"state": state, "safety_mode": "safe",
	}
}

type svcRow struct {
	port      int
	protocol  string
	product   *string
	method    *string
	softmatch bool
	solicited bool
}

func servicesOf(t *testing.T, db *store.DB, tenant store.TenantID) map[int]svcRow {
	t.Helper()
	out := map[int]svcRow{}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		rows, err := c.Query(ctx, `SELECT port, protocol, product, identification_method,
		                                  softmatch, solicited
		                             FROM services WHERE tenant_id = $1 ORDER BY port`,
			tenant.UUID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r svcRow
			if err := rows.Scan(&r.port, &r.protocol, &r.product, &r.method, &r.softmatch, &r.solicited); err != nil {
				return err
			}
			out[r.port] = r
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("read services: %v", err)
	}
	return out
}

func findingCount(t *testing.T, db *store.DB, tenant store.TenantID) int {
	t.Helper()
	var n int
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM findings`).Scan(&n)
	}); err != nil {
		t.Fatalf("count findings: %v", err)
	}
	return n
}

// Decision 1: an open port becomes a service row; closed and filtered do not.
func TestAnOpenPortBecomesAServiceAndAClosedOneDoesNot(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "seen-port")
	c := correlate.New(db, quietLogger())
	at := time.Now().UTC().Add(-time.Hour)

	// TWO moderate keys, which is what resolves a host to one asset (ADR-007);
	// one alone does not, and the port observations hang off that asset.
	s.observe(t, db, at, sshService("10.10.0.21", 22, "SHA256:mtNzHqIMHK7YlUATGiTfBWUazP2nP6HemtSTyyviQS8"))
	s.observe(t, db, at, tlsService("10.10.0.21", 443, "SHA256:0GStyOAlmZaZfSDF0eL0z8BAMYcnp0dmJVIcAiEZK1M"))
	s.observePort(t, db, at, portObs("10.10.0.21", 3389, "open"))
	s.observePort(t, db, at, portObs("10.10.0.21", 445, "closed"))
	s.observePort(t, db, at, portObs("10.10.0.21", 139, "filtered"))

	if err := c.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// The asset must exist at all. This is not ceremony: deriveServices runs
	// INSIDE resolveHost's transaction, so a service row the database refuses
	// rolls the host resolution back with it — the first cut of this change
	// wrote an identification_method the CHECK did not allow and turned
	// "assets=1" into "assets=0" (ADR-104).
	if got := assetCount(t, db, s.tenant); got != 1 {
		t.Fatalf("%d assets after the sweep, want 1 — a refused service row takes "+
			"the whole host with it", got)
	}
	svcs := servicesOf(t, db, s.tenant)
	if _, ok := svcs[3389]; !ok {
		t.Fatalf("the open port did not become a service row; got ports %v", keysOf(svcs))
	}
	// A closed or filtered port is the scan saying nothing is there. Writing it
	// would put an endpoint on the asset that does not exist.
	for _, p := range []int{445, 139} {
		if _, ok := svcs[p]; ok {
			t.Errorf("port %d was not open and must not be a service row", p)
		}
	}

	seen := svcs[3389]
	if seen.product != nil && *seen.product != "" {
		t.Errorf("a seen-only port claims a product %q; it identified nothing", *seen.product)
	}
	if seen.method == nil || *seen.method != store.IdentificationDiscovery {
		t.Errorf("identification_method = %v, want %q", seen.method, store.IdentificationDiscovery)
	}
}

// Decision 2 end to end: promoting ports manufactures no findings.
//
// Read what this does and does not assert. It pins the OUTCOME, and the outcome
// is over-determined — a discovery payload carries no product or service, so
// the rules match nothing even if handed one. Removing the type filter leaves
// this test green. The MECHANISM is pinned separately, by
// TestPortObservationsNeverReachTheRuleEngine, which feeds the filter a
// rule-shaped payload so only the filter itself can stop it. Both are kept: one
// says the pipeline behaves, the other says why.
func TestASeenOnlyPortRaisesNoFinding(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "seen-port-rules")
	c := correlate.New(db, quietLogger())
	at := time.Now().UTC().Add(-time.Hour)

	s.observe(t, db, at, sshService("10.10.0.22", 22, "SHA256:bbNzHqIMHK7YlUATGiTfBWUazP2nP6HemtSTyyviQS8"))
	s.observe(t, db, at, tlsService("10.10.0.22", 443, "SHA256:ccStyOAlmZaZfSDF0eL0z8BAMYcnp0dmJVIcAiEZK1M"))
	if err := c.SweepOnce(context.Background()); err != nil {
		t.Fatalf("anchor sweep: %v", err)
	}
	before := findingCount(t, db, s.tenant)

	for _, p := range []int{2000, 5060, 3389, 23} {
		s.observePort(t, db, at, portObs("10.10.0.22", p, "open"))
	}
	if err := c.SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	// The control: the ports really did land, so this is not passing because
	// nothing happened.
	svcs := servicesOf(t, db, s.tenant)
	for _, p := range []int{2000, 5060, 3389, 23} {
		if _, ok := svcs[p]; !ok {
			t.Fatalf("port %d never became a service row, so this test asserts nothing", p)
		}
	}
	if after := findingCount(t, db, s.tenant); after != before {
		t.Errorf("findings went %d -> %d: a seen-only port reached the rule engine (ADR-103 decision 2)",
			before, after)
	}
}

// The merge, both directions. A fingerprint pass must upgrade a seen-only row
// in place, and a discovery pass afterwards must not undo it — including
// softmatch and solicited, which are assignments rather than coalesces and are
// the one clobber path the existing merge does not close.
func TestFingerprintUpgradesASeenPortAndLaterDiscoveryDoesNotUndoIt(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "seen-port-merge")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	first := time.Now().UTC().Add(-2 * time.Hour)

	// 1. discovery alone: port 8080 answers, nothing identified.
	s.observe(t, db, first, sshService("10.10.0.23", 22, "SHA256:aaNzHqIMHK7YlUATGiTfBWUazP2nP6HemtSTyyviQS8"))
	s.observe(t, db, first, tlsService("10.10.0.23", 443, "SHA256:ddStyOAlmZaZfSDF0eL0z8BAMYcnp0dmJVIcAiEZK1M"))
	s.observePort(t, db, first, portObs("10.10.0.23", 8080, "open"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep 1: %v", err)
	}
	if got, ok := servicesOf(t, db, s.tenant)[8080]; !ok {
		t.Fatalf("the seen-only port never landed, so the merge is untested")
	} else if got.product != nil && *got.product != "" {
		t.Fatalf("discovery invented a product: %q", *got.product)
	}

	// 2. a fingerprint pass identifies it.
	s.nextScan(t, db)
	second := first.Add(30 * time.Minute)
	s.observe(t, db, second, sshService("10.10.0.23", 22, "SHA256:aaNzHqIMHK7YlUATGiTfBWUazP2nP6HemtSTyyviQS8"))
	s.observe(t, db, second, httpService("10.10.0.23", 8080))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep 2: %v", err)
	}
	upgraded := servicesOf(t, db, s.tenant)[8080]
	if upgraded.product == nil || *upgraded.product != "nginx" {
		t.Fatalf("fingerprint did not upgrade the seen-only row in place: product = %v", upgraded.product)
	}
	if !upgraded.solicited {
		t.Fatalf("the identified row should be solicited; got false")
	}

	// 3. a LATER discovery pass sees the same port. It must change nothing.
	s.nextScan(t, db)
	third := second.Add(30 * time.Minute)
	s.observePort(t, db, third, portObs("10.10.0.23", 8080, "open"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep 3: %v", err)
	}
	after := servicesOf(t, db, s.tenant)[8080]
	if after.product == nil || *after.product != "nginx" {
		t.Errorf("a later discovery pass erased the product: %v", after.product)
	}
	if after.solicited != upgraded.solicited {
		t.Errorf("solicited reset by a seen-only write: %v -> %v (ADR-103's named clobber path)",
			upgraded.solicited, after.solicited)
	}
	if after.softmatch != upgraded.softmatch {
		t.Errorf("softmatch reset by a seen-only write: %v -> %v",
			upgraded.softmatch, after.softmatch)
	}
}

func keysOf(m map[int]svcRow) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
