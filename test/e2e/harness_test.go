// Package e2e runs the real binaries against a real Core over real TLS.
//
// Two OS processes, not two goroutines. Everything below the process boundary —
// certificate loading, gRPC keepalive, the mTLS handshake, SIGTERM reaching an
// engine's process group, a subprocess dying and the runtime noticing — is
// exactly what an in-process test cannot exercise, and all of it is where a
// scan point actually fails.
//
// Gated on CVAP_TEST_DATABASE_URL like internal/store's tests: no database, no
// run, and it says so rather than passing vacuously.
package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/ca"
	"github.com/effaaykhan/cvap/internal/control/enrollment"
	"github.com/effaaykhan/cvap/internal/store"
)

const (
	// Two engine builds, because the happy path and the failure tests want
	// opposite things from the clock.
	//
	// A BUILD FLAG, not an environment variable: a knob that changes scanning
	// speed must not be reachable in a shipped binary, and -ldflags cannot be
	// set by anything running one.
	//
	// slowPerTarget is sized against LeaseRenewInterval rather than guessed.
	// The runtime renews every 20 s, and a job that finishes before its first
	// renewal never learns its lease was severed: it completes, submits late,
	// and Core quarantines the stale epoch. That is correct behaviour and it is
	// not self-abort, so a job under test has to outlive a renewal.
	// 60 x 500ms = 30 s, comfortably past it.
	slowPerTarget = "500ms"

	taskCount = 60
)

type harness struct {
	t      *testing.T
	dir    string
	engine string // which of the two engine builds this test runs

	db     *store.DB
	tenant store.TenantID
	zoneID uuid.UUID
	scanID uuid.UUID
	jobID  uuid.UUID

	caCert string
	caKey  string

	enrollAddr string
	mtlsAddr   string
	apiAddr    string

	coreCmd *exec.Cmd
	spCmd   *exec.Cmd
	spData  string
}

// newHarness builds a harness running the engine with no delay.
func newHarness(t *testing.T) *harness { return harnessWith(t, "cvap-engine-noop") }

// newSlowHarness builds one whose engine takes long enough to interrupt.
func newSlowHarness(t *testing.T) *harness { return harnessWith(t, "cvap-engine-noop-slow") }

func harnessWith(t *testing.T, engine string) *harness {
	t.Helper()

	url := os.Getenv("CVAP_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set; skipping the end-to-end suite")
	}
	db, err := store.Open(context.Background(), store.Config{URL: url})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(db.Close)

	h := &harness{t: t, dir: t.TempDir(), db: db, engine: engine}
	h.buildBinaries()
	h.makeCA()
	h.seed()
	return h
}

// buildBinaries compiles what the test runs. Building here rather than assuming
// a prior `make build` keeps the test honest about which source it exercised.
func (h *harness) buildBinaries() {
	h.t.Helper()
	root, err := filepath.Abs("../..")
	if err != nil {
		h.t.Fatal(err)
	}
	for _, b := range []struct{ pkg, out, ldflags string }{
		{"./cmd/cvap-core", "cvap-core", ""},
		{"./cmd/cvap-scanpoint", "cvap-scanpoint", ""},
		{"./cmd/cvap-engine-noop", "cvap-engine-noop", ""},
		{"./cmd/cvap-engine-noop", "cvap-engine-noop-slow",
			"-X main.perTargetDelay=" + slowPerTarget},
		// The credentialed-host engine (ADR-086/091), for the suite that runs
		// the grant over the real stream against the lab's Debian sshd.
		{"./cmd/cvap-engine-credhost", "cvap-engine-credhost", ""},
	} {
		args := []string{"build", "-o", filepath.Join(h.dir, b.out)}
		if b.ldflags != "" {
			args = append(args, "-ldflags", b.ldflags)
		}
		args = append(args, b.pkg)
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		if out, err := cmd.CombinedOutput(); err != nil {
			h.t.Fatalf("build %s: %v\n%s", b.pkg, err, out)
		}
	}
}

func (h *harness) makeCA() {
	h.t.Helper()
	certPath, keyPath, err := ca.GenerateSelfSigned(h.dir, "cvap e2e CA", 24*time.Hour)
	if err != nil {
		h.t.Fatalf("generate CA: %v", err)
	}
	h.caCert, h.caKey = certPath, keyPath
}

// seed creates the tenant, zone, policy, scan, target, job and tasks.
func (h *harness) seed() {
	h.t.Helper()
	ctx := context.Background()

	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		h.t.Fatal(err)
	}
	h.tenant = tenant

	if err := h.db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		if _, err := (store.Tenants{}).Create(ctx, c, "e2e-"+uuid.NewString()[:8],
			"e2e"+strings.ReplaceAll(uuid.NewString(), "-", "")[:20]+".test", store.DeploymentOnPrem); err != nil {
			return err
		}
		z, err := (store.Zones{}).Create(ctx, c, "e2e-zone", store.ZoneInternal, 50, "")
		if err != nil {
			return err
		}
		h.zoneID = z.ID

		var policyID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_policies (tenant_id, name, max_rate_pps)
			 VALUES ($1,$2,120) RETURNING policy_id`,
			tid, "e2e-"+uuid.NewString()[:8]).Scan(&policyID); err != nil {
			return err
		}
		// An allow rule, because allowed_targets empty means DENY ALL at both
		// enforcement sites (ADR-037) — the runtime would refuse every target.
		// 192.0.2.0/24 is TEST-NET-1: reserved for documentation, never routed,
		// and already in lab/scope.txt.
		if _, err := c.Exec(ctx,
			`INSERT INTO policy_scope_rules (tenant_id, policy_id, effect, match_type, match_value)
			 VALUES ($1,$2,'allow','cidr','192.0.2.0/24')`, tid, policyID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type) VALUES ($1,$2,'discovery')
			 RETURNING scan_id`, tid, policyID).Scan(&h.scanID); err != nil {
			return err
		}
		var targetID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value,
			                           authorization_verified, verified_at)
			 VALUES ($1,$2,'cidr','192.0.2.0/24',true,now()) RETURNING target_id`,
			tid, h.scanID).Scan(&targetID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'discovery',true) RETURNING job_id`,
			tid, h.scanID).Scan(&h.jobID); err != nil {
			return err
		}
		for i := 0; i < taskCount; i++ {
			if _, err := c.Exec(ctx,
				`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target)
				 VALUES ($1,$2,$3,$4)`,
				tid, h.jobID, targetID, fmt.Sprintf("192.0.2.%d", i+1)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		h.t.Fatalf("seed: %v", err)
	}
}

// token issues an enrollment token and writes it where the scan point expects.
func (h *harness) token() string {
	h.t.Helper()
	issuer := enrollment.NewIssuer(h.db)
	issued, err := issuer.Issue(context.Background(), h.tenant, h.zoneID, nil, 0, "e2e")
	if err != nil {
		h.t.Fatalf("issue token: %v", err)
	}
	path := filepath.Join(h.dir, "enrollment-token")
	if err := os.WriteFile(path, []byte(issued.Token.Reveal()), 0o600); err != nil {
		h.t.Fatal(err)
	}
	return path
}

// freePort returns an address nothing is listening on.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func (h *harness) startCore(extraEnv ...string) {
	h.t.Helper()
	h.enrollAddr = freePort(h.t)
	h.mtlsAddr = freePort(h.t)
	h.apiAddr = freePort(h.t)

	cmd := exec.Command(filepath.Join(h.dir, "cvap-core"))
	cmd.Env = append(os.Environ(), extraEnv...)
	cmd.Env = append(cmd.Env,
		"APP_DATABASE_URL="+os.Getenv("CVAP_TEST_DATABASE_URL"),
		"CVAP_CORE_ENROLL_LISTEN="+h.enrollAddr,
		"CVAP_CORE_MTLS_LISTEN="+h.mtlsAddr,
		// The operator API listener. Not exercised by this suite, and Core
		// refuses to start without it — which is the point of requiring it
		// rather than defaulting: a deployment that forgot gets a startup
		// failure instead of a control surface nobody can reach.
		"CVAP_CORE_API_LISTEN="+h.apiAddr,
		"CVAP_CORE_CA_CERT="+h.caCert,
		"CVAP_CORE_CA_KEY="+h.caKey,
		"CVAP_CORE_SERVER_HOSTS=localhost,127.0.0.1",
		"CVAP_CORE_DISPATCH_ENDPOINT="+h.mtlsAddr,
		"CVAP_CORE_INGEST_ENDPOINT="+h.mtlsAddr,
		"CVAP_CORE_RULEPACKS_ENDPOINT="+h.mtlsAddr,
		"LOG_LEVEL=debug",
	)
	cmd.Stdout = prefixWriter{h.t, "core"}
	cmd.Stderr = prefixWriter{h.t, "core!"}
	if err := cmd.Start(); err != nil {
		h.t.Fatalf("start core: %v", err)
	}
	h.coreCmd = cmd
	h.t.Cleanup(func() { stopProcess(cmd) })

	waitListening(h.t, h.enrollAddr)
	waitListening(h.t, h.mtlsAddr)
}

func (h *harness) startScanPoint() {
	h.t.Helper()
	h.spData = filepath.Join(h.dir, "sp-data")

	cmd := exec.Command(filepath.Join(h.dir, "cvap-scanpoint"))
	cmd.Env = append(os.Environ(),
		"CVAP_SP_ENROLL_ENDPOINT="+h.enrollAddr,
		"CVAP_SP_CA_BUNDLE="+h.caCert,
		"CVAP_SP_ENROLLMENT_TOKEN_FILE="+h.token(),
		"CVAP_SP_DATA_DIR="+h.spData,
		"CVAP_SP_ENGINE_BINARIES="+filepath.Join(h.dir, h.engine),
		"CVAP_SP_HOSTNAME=e2e-scanpoint",
		"LOG_LEVEL=debug",
	)
	cmd.Stdout = prefixWriter{h.t, "sp"}
	cmd.Stderr = prefixWriter{h.t, "sp!"}
	// Its own process group, so stopProcess takes the engine subprocess with it
	// and a failed test does not leave one running.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		h.t.Fatalf("start scan point: %v", err)
	}
	h.spCmd = cmd
	h.t.Cleanup(func() { stopProcess(cmd) })
}

func stopProcess(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}

func waitListening(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

// prefixWriter routes a child's output into the test log, so a failure shows
// what both processes were doing rather than only what the assertion saw.
type prefixWriter struct {
	t      *testing.T
	prefix string
}

func (w prefixWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line != "" {
			w.t.Logf("[%s] %s", w.prefix, line)
		}
	}
	return len(p), nil
}

// eventually polls until cond holds or the deadline passes.
func eventually(t *testing.T, what string, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// --- database queries the assertions use ------------------------------------

func (h *harness) observationCount() int {
	var n int
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT count(*) FROM observations o
			   JOIN scan_tasks t ON t.tenant_id = o.tenant_id AND t.task_id = o.task_id
			  WHERE o.tenant_id = $1 AND t.job_id = $2`,
			c.Tenant().UUID(), h.jobID).Scan(&n)
	}); err != nil {
		h.t.Fatalf("count observations: %v", err)
	}
	return n
}

type submissionRow struct {
	Status           string
	Incomplete       bool
	Reason           *string
	QuarantineReason *string
}

func (h *harness) submissions() []submissionRow {
	var out []submissionRow
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		rows, err := c.Query(ctx,
			`SELECT status, incomplete, termination_reason, quarantine_reason
			   FROM result_submissions
			  WHERE tenant_id = $1 AND job_id = $2
			  ORDER BY received_at`, c.Tenant().UUID(), h.jobID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r submissionRow
			if err := rows.Scan(&r.Status, &r.Incomplete, &r.Reason, &r.QuarantineReason); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	}); err != nil {
		h.t.Fatalf("read submissions: %v", err)
	}
	return out
}

func (h *harness) jobStatus() (string, *string) {
	var status string
	var reason *string
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT status, termination_reason FROM scan_jobs WHERE tenant_id = $1 AND job_id = $2`,
			c.Tenant().UUID(), h.jobID).Scan(&status, &reason)
	}); err != nil {
		h.t.Fatalf("read job: %v", err)
	}
	return status, reason
}

func (h *harness) currentLease() (int64, error) {
	var epoch int64
	err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		l, err := (store.Leases{}).Current(ctx, c, h.jobID)
		if err != nil {
			return err
		}
		epoch = l.Epoch
		return nil
	})
	return epoch, err
}

func (h *harness) enrolledScanPoint() uuid.UUID {
	var id uuid.UUID
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT scan_point_id FROM scan_points WHERE tenant_id = $1 LIMIT 1`,
			c.Tenant().UUID()).Scan(&id)
	}); err != nil {
		h.t.Fatalf("read scan point: %v", err)
	}
	return id
}

// setReassignSafe overrides the seeded job's reassign_safe. seed() defaults it to
// true (passive discovery, safe to duplicate); F1b needs false — the job whose
// duplication ADR-012 says must never happen silently.
func (h *harness) setReassignSafe(v bool) {
	h.t.Helper()
	if err := h.db.Write(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := c.Exec(ctx,
			`UPDATE scan_jobs SET reassign_safe = $3 WHERE tenant_id = $1 AND job_id = $2`,
			c.Tenant().UUID(), h.jobID, v)
		return err
	}); err != nil {
		h.t.Fatalf("set reassign_safe: %v", err)
	}
}

// observationStates returns how many of the job's observations are accepted
// (visible to the finding pipeline) versus quarantined (stored, withheld). The
// read paths filter ingest_state='accepted', so accepted==0 is "not processed".
func (h *harness) observationStates() (accepted, quarantined int) {
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT
			   count(*) FILTER (WHERE o.ingest_state = 'accepted'),
			   count(*) FILTER (WHERE o.ingest_state = 'quarantined')
			 FROM observations o
			 JOIN scan_tasks t ON t.tenant_id = o.tenant_id AND t.task_id = o.task_id
			 WHERE o.tenant_id = $1 AND t.job_id = $2`,
			c.Tenant().UUID(), h.jobID).Scan(&accepted, &quarantined)
	}); err != nil {
		h.t.Fatalf("count observation states: %v", err)
	}
	return accepted, quarantined
}

// quarantineAuditCount counts submission.quarantined audit events for the job's
// tenant. ADR-026's quarantine is not silent — the operator investigating a
// fencing event needs a record of it.
func (h *harness) quarantineAuditCount() int {
	var n int
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT count(*) FROM audit_events
			  WHERE tenant_id = $1 AND action = 'submission.quarantined'`,
			c.Tenant().UUID()).Scan(&n)
	}); err != nil {
		h.t.Fatalf("count quarantine audit events: %v", err)
	}
	return n
}

// submissionEpochs returns the distinct lease epochs that produced a submission
// for the job, ascending. A target scanned twice can only submit under a second
// epoch, so this counts how many times the job was actually worked.
func (h *harness) submissionEpochs() []int64 {
	var out []int64
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		rows, err := c.Query(ctx,
			`SELECT DISTINCT lease_epoch FROM result_submissions
			  WHERE tenant_id = $1 AND job_id = $2 ORDER BY lease_epoch`,
			c.Tenant().UUID(), h.jobID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e int64
			if err := rows.Scan(&e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	}); err != nil {
		h.t.Fatalf("read submission epochs: %v", err)
	}
	return out
}
