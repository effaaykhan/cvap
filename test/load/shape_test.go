// Package load holds the 10k-asset load test (execution-plan §5 SLOs).
//
// This file is the SHAPE VALIDATION that the synthetic 10k-asset seed is built
// against (session 21). A load test that measures an unrealistic distribution
// produces a number people trust and should not, so before seeding 10k assets
// directly we seed a few hundred through the REAL correlation pipeline, measure
// the shape it produces, and require the synthetic seed to match that shape —
// not the values, the shape. This test measures and reports it; shape_match_test
// asserts the synthetic seed reproduces it.
package load

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set")
	}
	db, err := store.Open(context.Background(), store.Config{URL: url})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// shape is the distribution the load-test seed must reproduce.
type shape struct {
	assets   int
	findings int

	keysPerAsset       map[int]int // count of keys -> number of assets
	strengths          map[int]int // key strength -> count
	exposurePerFind    map[int]int // exposure rows -> number of findings
	findingsPerEndpt   map[int]int // findings sharing (asset,port,proto) -> endpoints
	currentAddrs       map[int]int // current address rows -> number of assets
	assetsNullOptional int         // assets with all optional columns NULL
	findingsNullVuln   int         // findings with vuln_def_id NULL
}

// vantage is one zone's scan point plus the job/task/submission an observation
// needs to hang from.
type vantage struct {
	zoneID uuid.UUID
	spID   uuid.UUID
	taskID uuid.UUID
	subID  string
}

func newTenant(t *testing.T, db *store.DB) store.TenantID {
	t.Helper()
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Tenants{}).Create(ctx, c, "load",
			"t"+strings.ReplaceAll(tenant.String(), "-", "")[:20]+".test", store.DeploymentSaaS)
		return err
	}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tenant
}

func newVantage(t *testing.T, db *store.DB, tenant store.TenantID) vantage {
	t.Helper()
	v := vantage{subID: "sub-" + uuid.NewString()}
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "z-"+uuid.NewString()[:8], store.ZoneInternal, 1, "")
		if err != nil {
			return err
		}
		v.zoneID = z.ID
		sp, err := (store.ScanPoints{}).Create(ctx, c, z.ID, "sp", "1", "v1", "fp-"+uuid.NewString())
		if err != nil {
			return err
		}
		v.spID = sp.ID
		jobID, taskID, err := seedJobAndTask(ctx, c, sp.ID)
		if err != nil {
			return err
		}
		v.taskID = taskID
		_, err = (store.Submissions{}).Begin(ctx, c, v.subID, jobID, 1, store.SubmitAccepted, false, "")
		return err
	}); err != nil {
		t.Fatalf("seed vantage: %v", err)
	}
	return v
}

func seedJobAndTask(ctx context.Context, c *store.Conn, scanPointID uuid.UUID) (jobID, taskID uuid.UUID, err error) {
	tenant := c.Tenant().UUID()
	suffix := uuid.NewString()[:8]
	var policyID, scanID uuid.UUID
	if err = c.QueryRow(ctx, `INSERT INTO scan_policies (tenant_id, name) VALUES ($1,$2) RETURNING policy_id`,
		tenant, "load-"+suffix).Scan(&policyID); err != nil {
		return
	}
	if err = c.QueryRow(ctx, `INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1,$2,'discovery') RETURNING scan_id`,
		tenant, policyID).Scan(&scanID); err != nil {
		return
	}
	if err = c.QueryRow(ctx, `INSERT INTO scan_jobs (tenant_id, scan_id, scan_point_id, engine) VALUES ($1,$2,$3,'fingerprint') RETURNING job_id`,
		tenant, scanID, scanPointID).Scan(&jobID); err != nil {
		return
	}
	err = c.QueryRow(ctx, `INSERT INTO scan_tasks (tenant_id, job_id, task_target) VALUES ($1,$2,'192.0.2.1') RETURNING task_id`,
		tenant, jobID).Scan(&taskID)
	return
}

func observe(t *testing.T, db *store.DB, tenant store.TenantID, v vantage, at time.Time, payload map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	conf := 0.95
	o := store.Observation{
		ID: uuid.New(), SubmissionID: v.subID, TaskID: v.taskID, ScanPointID: v.spID,
		ZoneID: v.zoneID, Type: store.ObsService, Payload: body, Confidence: &conf, ObservedAt: at,
	}
	if err := db.Write(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Observations{}).Insert(ctx, c, o, store.IngestAccepted)
	}); err != nil {
		t.Fatalf("observe: %v", err)
	}
}

// --- service payload profiles that fire a realistic spread of rules ---------

func sshClean(addr, fp string) map[string]any {
	return map[string]any{"address": addr, "port": 22, "protocol": "tcp", "service": "ssh",
		"product": "OpenSSH", "version": "10.3", "method": "banner",
		"ssh": map[string]any{"host_key_type": "ssh-ed25519", "fingerprint": fp}}
}

func tlsClean(addr, fp string) map[string]any {
	return map[string]any{"address": addr, "port": 443, "protocol": "tcp", "service": "http",
		"product": "nginx", "version": "1.27", "method": "tls-probe",
		"tls": map[string]any{"version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256",
			"chain_length": 2, "chain": []any{
				map[string]any{"fingerprint": fp, "subject": "CN=host", "issuer": "CN=ca",
					"not_after":   time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339),
					"self_signed": false, "key_bits": 2048, "public_key_algorithm": "RSA"}}}}
}

// tlsBad fires tls.expired + tls.self_signed + tls.legacy_negotiated + tls.weak_key
// on one endpoint — the dedup-prefix-sharing case.
func tlsBad(addr, fp string) map[string]any {
	return map[string]any{"address": addr, "port": 443, "protocol": "tcp", "service": "http",
		"product": "nginx", "version": "1.20", "method": "tls-probe",
		"tls": map[string]any{"version": "TLSv1.0", "cipher_suite": "TLS_AES_128_GCM_SHA256",
			"chain_length": 1, "chain": []any{
				map[string]any{"fingerprint": fp, "subject": "CN=self", "issuer": "CN=self",
					"not_after":   time.Now().Add(-30 * 24 * time.Hour).Format(time.RFC3339),
					"self_signed": true, "key_bits": 1024, "public_key_algorithm": "RSA"}}}}
}

func plaintext(addr string) map[string]any {
	return map[string]any{"address": addr, "port": 23, "protocol": "tcp", "service": "telnet",
		"product": "", "version": "", "method": "banner"}
}

// TestMeasureRealShape seeds ~300 assets through the real pipeline with a mix of
// profiles and vantage counts, then reports the shape. Read the log to see the
// distribution the synthetic seed must reproduce.
func TestMeasureRealShape(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db)
	// Three zones, so a finding-producing endpoint can be seen from one, two or
	// three vantages — the multi-exposure case ADR-010 exists for.
	vs := []vantage{newVantage(t, db, tenant), newVantage(t, db, tenant), newVantage(t, db, tenant)}

	at := time.Now().Add(-time.Hour)
	// observeFrom sends the same payload from the first n vantages, so the
	// endpoint's findings get n exposure rows.
	observeFrom := func(n int, payload map[string]any) {
		for z := 0; z < n; z++ {
			observe(t, db, tenant, vs[z], at, payload)
		}
	}

	const hosts = 300
	for i := 0; i < hosts; i++ {
		addr := fmt.Sprintf("198.51.100.%d", i%254+1)
		if i >= 254 {
			addr = fmt.Sprintf("203.0.113.%d", i%254+1)
		}
		fp := fmt.Sprintf("SHA256:%s", uuid.NewString())
		fp2 := fmt.Sprintf("SHA256:%s", uuid.NewString())
		// How many vantages see this host: most one, some two, a few three.
		nZones := 1
		if i%3 == 0 {
			nZones = 2
		}
		if i%9 == 0 {
			nZones = 3
		}

		switch i % 5 {
		case 0: // ssh only -> one moderate key, no finding
			observeFrom(nZones, sshClean(addr, fp))
		case 1: // tls clean -> one moderate key, no finding
			observeFrom(nZones, tlsClean(addr, fp))
		case 2: // tls bad -> several findings on one endpoint, from nZones vantages
			observeFrom(nZones, tlsBad(addr, fp))
		case 3: // ssh + tls -> two moderate keys, one asset; the tls endpoint fires
			observeFrom(nZones, sshClean(addr, fp))
			observeFrom(nZones, tlsBad(addr, fp2))
		case 4: // plaintext -> no stored key, one finding, from nZones vantages
			observeFrom(nZones, plaintext(addr))
		}
	}

	if err := correlate.New(db, discardLogger()).SweepOnce(context.Background()); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	sh := measureShape(t, db, tenant)
	reportShape(t, "REAL pipeline", sh)
}
