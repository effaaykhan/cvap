package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/effaaykhan/cvap/internal/store"
)

// The credentialed-host route, end to end, on real processes (ADR-091): Core
// resolves the profile's secret from its file root, records the release, sends
// the grant behind the assignment over real mTLS; the scan point validates the
// assignment, builds the ADR-086 signing agent and spawns cvap-engine-credhost
// with the socket on fd 3; the engine authenticates to the lab's Debian sshd
// with signatures alone, reads the inventory, and submits `package`
// observations to Ingest. The assertions are rows in Postgres and the
// container's own account of itself — never the scanner agreeing with itself.
//
// The target is lab/targets/ssh-plain (10.20.0.12), whose build generates the
// `lab` account's ed25519 key. The test takes the key and the host key from the
// container the way ground-truth.sh asks a container about itself: docker cp
// and docker exec. Nothing is committed and nothing is captured by scanning.
//
// Gated like corpus-check's scan half: the lab must be reachable, and
// CVAP_REQUIRE_LAB=1 makes an absent lab fatal rather than a skip. A gate that
// silently passes is worse than one that fails.
const (
	labSSHContainer = "cvap-lab-target-b-ssh-1"
	labSSHAddr      = "10.20.0.12"
)

func TestCredentialedInventoryOverTheWire(t *testing.T) {
	requireLab(t)
	h := harnessWith(t, "cvap-engine-credhost")

	// The secret root Core resolves file:// refs under, and the key inside it.
	credsDir := filepath.Join(h.dir, "creds")
	if err := os.MkdirAll(credsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(credsDir, "lab.key")
	dockerCp(t, labSSHContainer+":/lab/id_ed25519", keyPath)
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}

	// What discovery would have observed for this host: the SHA256 fingerprint
	// of the key sshd presents. Taken from the container's own host key file, so
	// the observed-trust path is exercised without an intrusive scan first.
	fingerprint := labHostKeyFingerprint(t)
	expected := labInventory(t)

	h.seedCredentialed(keyPath, fingerprint)
	h.startCore("CVAP_CORE_SECRET_FILE_ROOT=" + credsDir)
	h.startScanPoint()

	eventually(t, "the scan point to enrol", 30*time.Second, func() bool {
		_, err := os.Stat(filepath.Join(h.spData, "cert.pem"))
		return err == nil
	})

	eventually(t, "a package observation to reach the database", 90*time.Second, func() bool {
		return h.packageObservations() >= 1
	})

	// The key never touched the scan point's disk (ADR-020): only the identity
	// files are there.
	assertDataDir(t, h.spData)

	// Rung 1 for the credentialed read: the engine reported what the container
	// says about itself. Release and the openssh source package version, both
	// exact; a fully-patched host reading as anything else is the ADR-078
	// failure this whole path exists to remove.
	payload := h.packagePayload()
	if payload.Family != "debian" || payload.Release == "" {
		t.Errorf("package payload family/release = %q/%q, want debian and a release", payload.Family, payload.Release)
	}
	got := map[string]string{}
	for _, p := range payload.Installed {
		got[p.Name] = p.Version
	}
	for name, version := range expected {
		if got[name] != version {
			t.Errorf("package %s: engine reported %q, the container reports %q", name, got[name], version)
		}
	}
	if len(got) < len(expected) {
		t.Errorf("engine reported %d packages, container has at least %d", len(got), len(expected))
	}

	subs := h.submissions()
	if len(subs) != 1 || subs[0].Status != string(store.SubmitAccepted) || subs[0].Incomplete {
		t.Fatalf("submissions = %+v, want one accepted, complete", subs)
	}
	eventually(t, "the job to be marked completed", 20*time.Second, func() bool {
		status, _ := h.jobStatus()
		return status == string(store.JobCompleted)
	})

	// The release record (migration 0006) and the claim it carried.
	eventually(t, "the grant record to close on the attestation", 20*time.Second, func() bool {
		return h.grantZeroised()
	})
	if src := h.auditDetail("credential.granted", "trust_source"); src != "observed" {
		t.Errorf("credential.granted trust_source = %q, want observed", src)
	}
	if n := h.auditCount("scan_point.credentials_not_attested"); n != 0 {
		t.Errorf("%d credentials_not_attested event(s); the runtime attested over creds and agents", n)
	}
}

// requireLab skips unless the lab's sshd answers, and fails under
// CVAP_REQUIRE_LAB=1 — the skip names what it skipped.
func requireLab(t *testing.T) {
	t.Helper()
	if os.Getenv("CVAP_TEST_DATABASE_URL") == "" {
		t.Skip("CVAP_TEST_DATABASE_URL not set; skipping the end-to-end suite")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(labSSHAddr, "22"), 2*time.Second)
	if err != nil {
		if os.Getenv("CVAP_REQUIRE_LAB") == "1" {
			t.Fatalf("CVAP_REQUIRE_LAB=1 and the lab sshd at %s is not reachable: %v", labSSHAddr, err)
		}
		t.Skipf("lab not reachable (%s:22: %v); skipping the credentialed end-to-end test — run make lab-up", labSSHAddr, err)
	}
	_ = conn.Close()
}

func dockerCp(t *testing.T, from, to string) {
	t.Helper()
	if out, err := exec.Command("docker", "cp", from, to).CombinedOutput(); err != nil {
		t.Fatalf("docker cp %s: %v\n%s", from, err, out)
	}
}

func dockerExec(t *testing.T, container string, args ...string) string {
	t.Helper()
	out, err := exec.Command("docker", append([]string{"exec", container}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker exec %s %v: %v\n%s", container, args, err, out)
	}
	return string(out)
}

func labHostKeyFingerprint(t *testing.T) string {
	t.Helper()
	pub := dockerExec(t, labSSHContainer, "cat", "/etc/ssh/ssh_host_ed25519_key.pub")
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pub))
	if err != nil {
		t.Fatalf("parse lab host key: %v", err)
	}
	return ssh.FingerprintSHA256(key)
}

// labInventory is the container's own account of a few source packages, read
// with the same dpkg-query the engine runs — the independent-labelling
// boundary the corpus draws.
func labInventory(t *testing.T) map[string]string {
	t.Helper()
	out := dockerExec(t, labSSHContainer, "dpkg-query", "-W", "-f=${source:Package}\t${Version}\n", "openssh-server", "libc6", "dpkg")
	m := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if len(f) == 2 {
			m[f[0]] = f[1]
		}
	}
	if len(m) == 0 {
		t.Fatal("dpkg-query in the lab container returned nothing")
	}
	return m
}

// seedCredentialed adds, under the seeded tenant and policy: an allow rule for
// the lab segment, an ssh credential profile with the lab user and the file://
// ref, its authorisation on the policy, a host scan with one task at the lab
// sshd, and an asset at that address carrying the observed host-key fingerprint.
func (h *harness) seedCredentialed(keyPath, fingerprint string) {
	h.t.Helper()
	ctx := context.Background()
	if err := h.db.Write(ctx, h.tenant, func(ctx context.Context, c *store.Conn) error {
		tid := c.Tenant().UUID()
		var policyID uuid.UUID
		if err := c.QueryRow(ctx,
			`SELECT policy_id FROM scan_policies WHERE tenant_id = $1 LIMIT 1`, tid).Scan(&policyID); err != nil {
			return err
		}
		if _, err := c.Exec(ctx,
			`INSERT INTO policy_scope_rules (tenant_id, policy_id, effect, match_type, match_value)
			 VALUES ($1,$2,'allow','cidr','10.20.0.0/16')`, tid, policyID); err != nil {
			return err
		}
		var profileID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO credential_profiles (tenant_id, name, cred_type, secret_ref, username)
			 VALUES ($1,'lab-ssh','ssh',$2,'lab') RETURNING credential_profile_id`,
			tid, "file://"+keyPath).Scan(&profileID); err != nil {
			return err
		}
		if _, err := c.Exec(ctx,
			`INSERT INTO scan_policy_credential_profiles (tenant_id, policy_id, credential_profile_id)
			 VALUES ($1,$2,$3)`, tid, policyID, profileID); err != nil {
			return err
		}
		// Seeded as running with its one job below, so the planner does not
		// plan it a second time (PlanPending takes pending scans only).
		if err := c.QueryRow(ctx,
			`INSERT INTO scans (tenant_id, policy_id, scan_type, status) VALUES ($1,$2,'host','running') RETURNING scan_id`,
			tid, policyID).Scan(&h.scanID); err != nil {
			return err
		}
		var targetID uuid.UUID
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_targets (tenant_id, scan_id, target_type, target_value, authorization_verified, verified_at)
			 VALUES ($1,$2,'host',$3,true,now()) RETURNING target_id`,
			tid, h.scanID, labSSHAddr).Scan(&targetID); err != nil {
			return err
		}
		if err := c.QueryRow(ctx,
			`INSERT INTO scan_jobs (tenant_id, scan_id, engine, reassign_safe)
			 VALUES ($1,$2,'host',false) RETURNING job_id`, tid, h.scanID).Scan(&h.jobID); err != nil {
			return err
		}
		if _, err := c.Exec(ctx,
			`INSERT INTO scan_tasks (tenant_id, job_id, target_id, task_target) VALUES ($1,$2,$3,$4)`,
			tid, h.jobID, targetID, labSSHAddr); err != nil {
			return err
		}
		var assetID uuid.UUID
		if err := c.QueryRow(ctx, `INSERT INTO assets (tenant_id, primary_hostname) VALUES ($1,'target-b-ssh') RETURNING asset_id`, tid).
			Scan(&assetID); err != nil {
			return err
		}
		if _, err := c.Exec(ctx,
			`INSERT INTO asset_addresses (tenant_id, asset_id, ip_address) VALUES ($1,$2,$3::inet)`,
			tid, assetID, labSSHAddr); err != nil {
			return err
		}
		_, err := c.Exec(ctx,
			`WITH k AS (
			   INSERT INTO asset_identity_keys (tenant_id, asset_id, key_type, key_value, strength, provenance,
			                                    merge_evidence_observation, merge_evidence_payload)
			   VALUES ($1,$2,'ssh_hostkey',$3,2,'new_asset',gen_random_uuid(),'{"port":22,"protocol":"tcp"}'::jsonb)
			   RETURNING identity_key_id)
			 INSERT INTO asset_identity_key_sightings (tenant_id, identity_key_id, address, port, scans_seen, last_seen_scan, last_seen_at)
			 SELECT $1, identity_key_id, $4::inet, 22, 2, gen_random_uuid(), now() FROM k`, tid, assetID, fingerprint, labSSHAddr)
		return err
	}); err != nil {
		h.t.Fatalf("seed credentialed: %v", err)
	}
}

type packagePayload struct {
	Address   string `json:"address"`
	Release   string `json:"release"`
	Family    string `json:"family"`
	Installed []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"installed"`
}

func (h *harness) packageObservations() int {
	var n int
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT count(*) FROM observations o
			   JOIN scan_tasks t ON t.tenant_id = o.tenant_id AND t.task_id = o.task_id
			  WHERE o.tenant_id = $1 AND t.job_id = $2 AND o.observation_type = 'package'`,
			c.Tenant().UUID(), h.jobID).Scan(&n)
	}); err != nil {
		h.t.Fatalf("count package observations: %v", err)
	}
	return n
}

func (h *harness) packagePayload() packagePayload {
	var raw []byte
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT o.payload FROM observations o
			   JOIN scan_tasks t ON t.tenant_id = o.tenant_id AND t.task_id = o.task_id
			  WHERE o.tenant_id = $1 AND t.job_id = $2 AND o.observation_type = 'package'
			  LIMIT 1`, c.Tenant().UUID(), h.jobID).Scan(&raw)
	}); err != nil {
		h.t.Fatalf("read package payload: %v", err)
	}
	var p packagePayload
	if err := json.Unmarshal(raw, &p); err != nil {
		h.t.Fatalf("decode package payload: %v: %s", err, raw)
	}
	return p
}

func (h *harness) grantZeroised() bool {
	var closed bool
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT coalesce(bool_and(zeroised_at IS NOT NULL), false) FROM credential_grants
			  WHERE tenant_id = $1 AND job_id = $2`, c.Tenant().UUID(), h.jobID).Scan(&closed)
	}); err != nil {
		h.t.Fatalf("read grants: %v", err)
	}
	return closed
}

func (h *harness) auditDetail(action, key string) string {
	var v string
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx,
			`SELECT coalesce(detail->>$3, '') FROM audit_events
			  WHERE tenant_id = $1 AND action = $2 ORDER BY occurred_at DESC LIMIT 1`,
			c.Tenant().UUID(), action, key).Scan(&v)
	}); err != nil {
		h.t.Fatalf("read audit %s: %v", action, err)
	}
	return v
}

func (h *harness) auditCount(action string) int {
	var n int
	if err := h.db.Read(context.Background(), h.tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE tenant_id = $1 AND action = $2`,
			c.Tenant().UUID(), action).Scan(&n)
	}); err != nil {
		h.t.Fatalf("count audit %s: %v", action, err)
	}
	return n
}

var _ = fmt.Sprintf
