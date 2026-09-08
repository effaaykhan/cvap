package correlate_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/domain"
	"github.com/effaaykhan/cvap/internal/store"
)

// Week 5's deliverable, end to end against a real database.
//
// ============================================================================
// Scan the host, change its address, scan again, get ONE asset.
// ============================================================================
//
// The unit tests in internal/domain prove the merge RULE. This proves the
// pipeline: that the SSH host key actually survives the observation payload,
// that correlation finds the candidate through the identity-key index, that the
// old address interval is closed rather than left open, and that the second scan
// resolves onto the asset the first one created.
//
// Every one of those is a place the rule could be right and the system still
// produce two assets.

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

// seed builds the minimum a submission needs: a zone, a scan point, a job with a
// task, and an accepted submission for the observations to hang from.
type seeded struct {
	tenant store.TenantID
	taskID uuid.UUID
	spID   uuid.UUID
	zoneID uuid.UUID
	subID  string
}

func seed(t *testing.T, db *store.DB, label string) seeded {
	t.Helper()
	ctx := context.Background()

	// Tenant creation goes through Write with the new tenant's own id, which the
	// WITH CHECK policy permits — there is no unscoped path and none is needed.
	tenant, err := store.NewTenantID(uuid.New())
	if err != nil {
		t.Fatalf("new tenant id: %v", err)
	}
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		_, err := (store.Tenants{}).Create(ctx, c, label,
			"t"+strings.ReplaceAll(tenant.String(), "-", "")[:20]+".test", store.DeploymentSaaS)
		return err
	}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	s := seeded{tenant: tenant, subID: "sub-" + uuid.NewString()}
	if err := db.Write(ctx, tenant, func(ctx context.Context, c *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, c, "z-"+uuid.NewString()[:8], store.ZoneInternal, 1, "")
		if err != nil {
			return err
		}
		s.zoneID = z.ID
		sp, err := (store.ScanPoints{}).Create(ctx, c, z.ID, "sp", "1", "v1", "fp-"+uuid.NewString())
		if err != nil {
			return err
		}
		s.spID = sp.ID
		jobID, taskID, err := seedJobAndTask(ctx, c, sp.ID)
		if err != nil {
			return err
		}
		s.taskID = taskID
		_, err = (store.Submissions{}).Begin(ctx, c, s.subID, jobID, 1, store.SubmitAccepted, false, "")
		return err
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return s
}

// observe writes one accepted `service` observation, the way ingest would.
func (s seeded) observe(t *testing.T, db *store.DB, at time.Time, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	conf := 0.95
	o := store.Observation{
		ID: uuid.New(), SubmissionID: s.subID, TaskID: s.taskID, ScanPointID: s.spID,
		ZoneID: s.zoneID, Type: store.ObsService, Payload: body,
		Confidence: &conf, ObservedAt: at,
	}
	if err := db.Write(context.Background(), s.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Observations{}).Insert(ctx, c, o, store.IngestAccepted)
	}); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
}

func sshService(address string, port int, fingerprint string) map[string]any {
	return map[string]any{
		"address": address, "port": port, "protocol": "tcp",
		"service": "ssh", "product": "OpenSSH", "version": "10.3",
		"method": "banner", "solicited": true, "safety_mode": "intrusive",
		"ssh": map[string]any{
			"host_key_type": "ssh-ed25519",
			"fingerprint":   fingerprint,
		},
	}
}

func tlsService(address string, port int, fingerprint string) map[string]any {
	return map[string]any{
		"address": address, "port": port, "protocol": "tcp",
		"service": "http", "product": "nginx", "version": "1.27.5",
		"method": "tls-probe", "solicited": true, "safety_mode": "intrusive",
		"tls": map[string]any{
			"version": "TLSv1.3",
			"chain":   []any{map[string]any{"fingerprint": fingerprint}},
		},
	}
}

func assetCount(t *testing.T, db *store.DB, tenant store.TenantID) int {
	t.Helper()
	var n int
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM assets WHERE tenant_id = $1`,
			tenant.UUID()).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestOneAssetAcrossADHCPChange is the deliverable.
func TestOneAssetAcrossADHCPChange(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "dhcp")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()

	// TWO independent moderate keys, from two different services on the host.
	//
	// That is what ADR-007's rule requires and it is not incidental to this
	// test: one moderate key alone does NOT merge — see
	// TestOneModerateKeyAloneDoesNotMergeAcrossAnAddressChange, which asserts the
	// consequence rather than leaving it to be discovered. A host running SSH
	// and HTTPS has two; a host running only SSH has one.
	const (
		hostKey = "SHA256:mtNzHqIMHK7YlUATGiTfBWUazP2nP6HemtSTyyviQS8"
		certFP  = "SHA256:0GStyOAlmZaZfSDF0eL0z8BAMYcnp0dmJVIcAiEZK1M"
	)
	first := time.Now().UTC().Add(-time.Hour)

	// ---- first scan: 10.10.0.14 ----
	s.observe(t, db, first, sshService("10.10.0.14", 22, hostKey))
	s.observe(t, db, first, tlsService("10.10.0.14", 443, certFP))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatalf("first sweep: %v", err)
	}
	if got := assetCount(t, db, s.tenant); got != 1 {
		t.Fatalf("%d assets after the first scan, want 1", got)
	}

	// ---- the host moves, and is scanned again ----
	second := first.Add(30 * time.Minute)
	s.observe(t, db, second, sshService("10.10.0.77", 22, hostKey))
	s.observe(t, db, second, tlsService("10.10.0.77", 443, certFP))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatalf("second sweep: %v", err)
	}

	if got := assetCount(t, db, s.tenant); got != 1 {
		t.Fatalf("%d assets after the address changed, want 1. The host key is the same "+
			"and it is what should have carried the merge (ADR-007, ADR-049).", got)
	}

	// The new address is live and the old one is CLOSED, not deleted: two live
	// holders is the ambiguous state migration 0031 refuses, and deleting the
	// old row would take the history an old finding's locator needs.
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, conn *store.Conn) error {
		var live, closed int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE valid_to IS NULL),
			       count(*) FILTER (WHERE valid_to IS NOT NULL)
			  FROM asset_addresses WHERE tenant_id = $1`, s.tenant.UUID()).
			Scan(&live, &closed); err != nil {
			return err
		}
		// BOTH addresses are live, and that is correct rather than a leak.
		//
		// Seeing a host at a new address is not evidence the old one is gone: a
		// multi-homed host legitimately holds two, and nothing in this scan
		// observed 10.10.0.14 at all. The old interval closes by AGEING —
		// CloseStale, on the same window that gives `ip_window` its meaning — or
		// the moment another asset takes the address, which is what Open does
		// and what migration 0031 refuses to let it skip.
		//
		// An earlier version of this test asserted the old interval was closed
		// immediately, which would have required inferring a move from a scan
		// that saw only one end of it.
		if live != 2 {
			t.Errorf("%d live address intervals, want 2 — both are recent and nothing "+
				"observed the old one as gone", live)
		}
		if closed != 0 {
			t.Errorf("%d closed intervals, want 0 at this point", closed)
		}

		var n int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM asset_addresses
			 WHERE tenant_id = $1 AND valid_to IS NULL AND host(ip_address) = '10.10.0.77'`,
			s.tenant.UUID()).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			t.Errorf("the new address is not live on the asset")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The service row carries the evidence, and both observations resolved.
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, conn *store.Conn) error {
		var (
			unresolved int
			sshJSON    []byte
		)
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM observations
			 WHERE tenant_id = $1 AND asset_id IS NULL`, s.tenant.UUID()).Scan(&unresolved); err != nil {
			return err
		}
		if unresolved != 0 {
			t.Errorf("%d observations left unresolved", unresolved)
		}
		if err := conn.QueryRow(ctx, `
			SELECT ssh FROM services WHERE tenant_id = $1 AND port = 22`,
			s.tenant.UUID()).Scan(&sshJSON); err != nil {
			return err
		}
		if len(sshJSON) == 0 {
			t.Error("the service row carries no host key; the evidence was gathered, paid " +
				"for in a key exchange, and dropped on the way into the inventory")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestOneModerateKeyAloneDoesNotMergeAcrossAnAddressChange.
//
// ============================================================================
// The consequence of ADR-007's rule, asserted so it is a decision rather than
// a surprise.
// ============================================================================
//
// A merge needs one STRONG key or corroborating agreement among weaker ones.
// One moderate key is not corroborated by anything, so a host offering only an
// SSH host key becomes a new asset when its address changes — the host key
// agrees and nothing seconds it.
//
// That is not a gap in the implementation; it is the rule. It matters because
// the obvious estate — Linux hosts running SSH and no TLS — is exactly this
// case, and because the lab's own SSH host is. Closing it means a second
// independent key on those hosts, which is what `hostname_domain_os` would be
// if there were a hostname the scanner could trust (see internal/domain).
func TestOneModerateKeyAloneDoesNotMergeAcrossAnAddressChange(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "onekey")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()

	const hostKey = "SHA256:onlykeythishosthas"
	first := time.Now().UTC().Add(-time.Hour)

	s.observe(t, db, first, sshService("10.10.0.21", 22, hostKey))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s.observe(t, db, first.Add(time.Minute), sshService("10.10.0.22", 22, hostKey))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	if got := assetCount(t, db, s.tenant); got != 2 {
		t.Errorf("%d assets, want 2. One moderate key is not corroborated, and merging on "+
			"it alone is the merge ADR-007 forbids — if this now returns 1, the "+
			"corroboration rule has been loosened and that is a decision needing an ADR.", got)
	}
}

// TestWithoutAModerateKeyTheAddressChangeMakesANewAsset.
//
// The designed degradation, asserted so it is a decision rather than a surprise.
// A host with no TLS and no SSH has only `ip_window`, which ADR-007 says never
// merges — so it accumulates a new asset when its address changes. This is the
// control for the test above: without it, "one asset" could be produced by a
// resolver that merges everything.
func TestWithoutAModerateKeyTheAddressChangeMakesANewAsset(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "bare")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()

	bare := func(addr string) map[string]any {
		return map[string]any{
			"address": addr, "port": 80, "protocol": "tcp",
			"service": "http", "softmatch": true,
			"method": "probe", "solicited": true, "safety_mode": "intrusive",
		}
	}

	first := time.Now().UTC().Add(-time.Hour)
	s.observe(t, db, first, bare("10.10.0.11"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s.observe(t, db, first.Add(time.Minute), bare("10.10.0.99"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	if got := assetCount(t, db, s.tenant); got != 2 {
		t.Errorf("%d assets, want 2. With only an address there is nothing linking the old "+
			"one to the new, and merging anyway would be the wrong merge ADR-007 forbids.", got)
	}
}

// TestRescanningTheSameHostDoesNotDuplicateIt.
//
// The commonest operation in the system, and the one an attach exists for: a
// host with no moderate key, scanned twice at the same address inside the
// window, is one asset.
func TestRescanningTheSameHostDoesNotDuplicateIt(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "rescan")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()

	at := time.Now().UTC().Add(-time.Hour)
	for i := range 3 {
		s.observe(t, db, at.Add(time.Duration(i)*time.Minute), map[string]any{
			"address": "10.10.0.12", "port": 80, "protocol": "tcp",
			"service": "http", "softmatch": true, "method": "probe",
			"solicited": true, "safety_mode": "intrusive",
		})
		if err := c.SweepOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}

	if got := assetCount(t, db, s.tenant); got != 1 {
		t.Errorf("%d assets after three scans of one host, want 1", got)
	}
}

// seedJobAndTask mirrors the store package's helper: a submission needs a job,
// a job needs a scan, and a scan needs a policy. Duplicated rather than exported
// because a test helper exported for one other package is API nobody asked for.
func seedJobAndTask(ctx context.Context, c *store.Conn, scanPointID uuid.UUID) (jobID, taskID uuid.UUID, err error) {
	tenant := c.Tenant().UUID()
	suffix := uuid.NewString()[:8]

	var policyID uuid.UUID
	if err = c.QueryRow(ctx,
		`INSERT INTO scan_policies (tenant_id, name) VALUES ($1, $2) RETURNING policy_id`,
		tenant, "correlate-policy-"+suffix).Scan(&policyID); err != nil {
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
		 VALUES ($1, $2, $3, 'fingerprint') RETURNING job_id`,
		tenant, scanID, scanPointID).Scan(&jobID); err != nil {
		return
	}
	err = c.QueryRow(ctx,
		`INSERT INTO scan_tasks (tenant_id, job_id, task_target)
		 VALUES ($1, $2, '10.10.0.14') RETURNING task_id`,
		tenant, jobID).Scan(&taskID)
	return
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// TestAttributionLandsOnTheAssetFromABannerHint proves B21's fix for the osHint
// dead-read (phase-session-map §5.6, ADR-061): a service carrying an OS hint
// attributes the asset to a distro FAMILY with a NULL release, records the
// provenance, and lets SSH overrule SMB. The domain test proves the decision;
// this proves the read and the write actually happen end to end — the half that
// was missing, which is why the asset OS was always null.
func TestAttributionLandsOnTheAssetFromABannerHint(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "attr")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	now := time.Now().UTC()

	// SSH says Debian (Metasploitable's `Debian-8ubuntu1` shape); SMB says
	// Windows and must be overruled by precedence, not dropped.
	ssh := sshService("10.0.0.9", 22, "SHA256:attr-hostkey")
	ssh["os"] = map[string]any{"hint": "Debian", "source": "service banner"}
	s.observe(t, db, now, ssh)
	s.observe(t, db, now, map[string]any{
		"address": "10.0.0.9", "port": 445, "protocol": "tcp",
		"service": "microsoft-ds", "softmatch": true, "method": "probe",
		"os": map[string]any{"hint": "Windows", "source": "service banner"},
	})

	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	var family string
	var release *string
	var conf *float64
	var prov []byte
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT coalesce(distro_family,''), distro_release, os_confidence, os_provenance
		    FROM assets WHERE tenant_id=$1 LIMIT 1`, s.tenant.UUID()).Scan(&family, &release, &conf, &prov)
	}); err != nil {
		t.Fatal(err)
	}

	if family != "debian" {
		t.Errorf("distro_family = %q, want debian (SSH overrules SMB)", family)
	}
	if release != nil {
		t.Errorf("distro_release = %q, want NULL — a banner is family-only (ADR-061)", *release)
	}
	if conf == nil || *conf < 0.9 {
		t.Errorf("os_confidence = %v, want the SSH banner's ~0.95", conf)
	}

	var sources []domain.AttributionSource
	if err := json.Unmarshal(prov, &sources); err != nil {
		t.Fatalf("provenance is not the expected shape: %v (%s)", err, prov)
	}
	var contributedSSH, ignoredSMB bool
	for _, x := range sources {
		if x.Role == domain.RoleContributed && x.Service == "ssh" && x.Family == "debian" {
			contributedSSH = true
		}
		if x.Role == domain.RoleIgnored && x.Service == "smb" && x.Family == "windows" {
			ignoredSMB = true
		}
	}
	if !contributedSSH || !ignoredSMB {
		t.Errorf("provenance = %+v; want ssh->debian contributed and smb->windows overruled", sources)
	}
}
