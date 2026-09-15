package correlate_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// seedKernelKeyspace adds one resolute kernel USN to the keyspace: `linux` fixed
// at 7.0.0-31.31, one CVE. Through the knowledge role like seedJammyOpenSSH.
func seedKernelKeyspace(t *testing.T) {
	t.Helper()
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()
	for _, q := range []string{
		`INSERT INTO vendor_advisories (advisory_ref, vendor) VALUES ('TEST-KERNEL-RESOLUTE','ubuntu') ON CONFLICT (advisory_ref) DO NOTHING`,
		`INSERT INTO vulnerability_defs (cve_id, title) VALUES ('CVE-2026-0001','CVE-2026-0001') ON CONFLICT (cve_id) DO NOTHING`,
		`INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
		 SELECT va.advisory_id, vd.vuln_def_id FROM vendor_advisories va, vulnerability_defs vd
		  WHERE va.advisory_ref='TEST-KERNEL-RESOLUTE' AND vd.cve_id='CVE-2026-0001' ON CONFLICT DO NOTHING`,
		`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
		 SELECT va.advisory_id, 'resolute', 'linux', '7.0.0-31.31', 'dpkg'::version_comparator
		   FROM vendor_advisories va WHERE va.advisory_ref='TEST-KERNEL-RESOLUTE'
		 ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed kernel keyspace: %v", err)
		}
	}
}

// The inventory .146 carries (ADR-093): the running ABI-31 kernel, the leftover
// ABI-30 packages that never "upgrade", and the ordinary linux-libc-dev that does.
func kernelInventory() []map[string]any {
	return []map[string]any{
		{"name": "linux", "binary": "linux-modules-7.0.0-31-generic", "version": "7.0.0-31.31"},
		{"name": "linux-signed", "binary": "linux-image-7.0.0-31-generic", "version": "7.0.0-31.31"},
		{"name": "linux", "binary": "linux-modules-7.0.0-30-generic", "version": "7.0.0-30.30"},
		{"name": "linux", "binary": "linux-image-unsigned-7.0.0-30-generic", "version": "7.0.0-30.30"},
		{"name": "linux", "binary": "linux-libc-dev", "version": "7.0.0-31.31"},
		{"name": "openssh", "binary": "openssh-server", "version": "1:9.6p1-3ubuntu13"},
	}
}

func kernelPayload(kernelRelease string) map[string]any {
	p := map[string]any{
		"address": "10.0.0.36", "family": "ubuntu", "release": "resolute", "release_source": "os-release",
		"installed": kernelInventory(),
	}
	if kernelRelease != "" {
		p["kernel_release"] = kernelRelease
	}
	return p
}

// credentialedKernelFindings returns the credentialed `linux` findings on the
// tenant's asset as status -> count.
func credentialedKernelFindings(t *testing.T, db *store.DB, s seeded) map[string]int {
	t.Helper()
	out := map[string]int{}
	if err := db.Read(context.Background(), s.tenant, func(ctx context.Context, cn *store.Conn) error {
		rows, err := cn.Query(ctx, `SELECT status::text, count(*) FROM findings
		   WHERE tenant_id = $1 AND source = 'credentialed' AND instance_locator = 'linux' GROUP BY status`, s.tenant.UUID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var st string
			var n int
			if err := rows.Scan(&st, &n); err != nil {
				return err
			}
			out[st] = n
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TestALeftoverKernelABIIsInventoryNotAFinding is B36's acceptance, in the shape
// ADR-093 measured it: a host at the fix (running 7.0.0-31) still carries its
// ABI-30 packages, and the source-collapsed inventory reads as `linux 7.0.0-30.30`
// — below the USN — so the matcher raised 551 findings on .146, all false. With
// `uname -r` on the read, the leftover ABI is inventory and raises nothing; the
// reboot-pending host (running ABI-30 with ABI-31 installed) still raises, because
// that is the real exposure; and a finding raised while the old kernel ran closes
// when a later read shows the fix booted. Integration, not unit, because the
// decision is pure (domain.ClassifyKernelPackage) and the question is whether
// the correlator REACHES it on the observation shape the engine emits (§5.12).
func TestALeftoverKernelABIIsInventoryNotAFinding(t *testing.T) {
	db := testDB(t)
	seedKernelKeyspace(t)
	s := seed(t, db, "kernabi")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-3 * time.Hour)

	// 1. At the fix: running ABI-31, ABI-30 left behind. No kernel finding.
	s.observe(t, db, t0, sshService("10.0.0.36", 22, "SHA256:kernabi-hostkey"))
	s.observePackage(t, db, t0, kernelPayload("7.0.0-31-generic"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); len(got) != 0 {
		t.Fatalf("host running the fixed kernel: credentialed linux findings = %v, want none (the ABI-30 leftovers are inventory)", got)
	}

	// 2. Reboot pending: the same inventory, running ABI-30. The finding is real.
	s.nextScan(t, db)
	s.observePackage(t, db, t0.Add(time.Hour), kernelPayload("7.0.0-30-generic"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 {
		t.Fatalf("host running the OLD kernel with the fix installed: credentialed linux findings = %v, want 1 open (reboot pending is the real exposure)", got)
	}

	// 3. Rebooted onto ABI-31: the credentialed read no longer matches, and the
	// finding it raised closes as remediated with a transition — a credentialed
	// finding is the read's claim, and the read withdrew it.
	s.nextScan(t, db)
	s.observePackage(t, db, t0.Add(2*time.Hour), kernelPayload("7.0.0-31-generic"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	got := credentialedKernelFindings(t, db, s)
	if got["open"] != 0 || got["remediated"] != 1 {
		t.Fatalf("after the reboot: credentialed linux findings = %v, want the one finding remediated and none open", got)
	}
	var transitions int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT count(*) FROM finding_history ft JOIN findings f ON f.tenant_id = ft.tenant_id AND f.finding_id = ft.finding_id
		   WHERE ft.tenant_id = $1 AND f.instance_locator = 'linux' AND ft.to_status = 'remediated'`, s.tenant.UUID()).Scan(&transitions)
	}); err != nil {
		t.Fatal(err)
	}
	if transitions != 1 {
		t.Errorf("remediation transitions for the kernel finding = %d, want 1 (the close is recorded, not silent)", transitions)
	}
}

// A read without `uname -r` — the pre-ADR-099 payload, or an instrument's shape —
// cannot say which kernel runs, and judges the kernel neither way: no 551, and no
// claim that the host is clean either. Ordinary packages on the same read are
// matched as before.
func TestAReadWithoutTheRunningKernelJudgesNoKernelPackage(t *testing.T) {
	db := testDB(t)
	seedKernelKeyspace(t)
	seedJammyOpenSSH(t)
	s := seed(t, db, "kernnouname")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Hour)

	inv := kernelInventory()
	inv = append(inv, map[string]any{"name": "openssh", "binary": "openssh-server", "version": "1:8.9p1-3"})
	s.observe(t, db, t0, sshService("10.0.0.37", 22, "SHA256:kernnouname-hostkey"))
	s.observePackage(t, db, t0, map[string]any{
		"address": "10.0.0.37", "family": "ubuntu", "release": "jammy", "release_source": "os-release",
		"installed": inv, // no kernel_release
	})
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); len(got) != 0 {
		t.Fatalf("no uname on the read: credentialed linux findings = %v, want none", got)
	}
	var ssh int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND source = 'credentialed' AND instance_locator = 'openssh' AND status = 'open'`, s.tenant.UUID()).Scan(&ssh)
	}); err != nil {
		t.Fatal(err)
	}
	if ssh != 1 {
		t.Errorf("openssh below the jammy fix on the same read: credentialed findings = %d, want 1 (ordinary packages are still judged)", ssh)
	}
}

// The withdrawal direction of the no-uname rule (found by the ADR-compliance
// review of ADR-099, measured): a read that judges the kernel neither way must
// not WITHDRAW a kernel finding either. A reboot-pending host carries a true
// credentialed kernel finding; an older scan point build then reads it without
// `uname -r`. The finding stays open, no transition is written, and a package
// genuinely absent from the read still closes.
func TestAReadWithoutTheRunningKernelWithdrawsNoKernelFinding(t *testing.T) {
	db := testDB(t)
	seedKernelKeyspace(t)
	s := seed(t, db, "kernkeep")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-2 * time.Hour)

	// A new build's read: the host runs the OLD kernel with the fix installed —
	// one true kernel finding — and carries a vulnerable openssh alongside.
	inv := append(kernelInventory(), map[string]any{"name": "openssh", "binary": "openssh-server", "version": "1:8.9p1-3"})
	payload := func(kernel string, installed []map[string]any) map[string]any {
		p := map[string]any{"address": "10.0.0.38", "family": "ubuntu", "release": "resolute", "release_source": "os-release", "installed": installed}
		if kernel != "" {
			p["kernel_release"] = kernel
		}
		return p
	}
	s.observe(t, db, t0, sshService("10.0.0.38", 22, "SHA256:kernkeep-hostkey"))
	seedResoluteOpenSSH(t)
	s.observePackage(t, db, t0, payload("7.0.0-30-generic", inv))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 {
		t.Fatalf("reboot-pending host: credentialed linux findings = %v, want 1 open", got)
	}

	// An old build reads the same host: no uname, and openssh has been REMOVED.
	s.nextScan(t, db)
	s.observePackage(t, db, t0.Add(time.Hour), payload("", kernelInventory()))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 || got["remediated"] != 0 {
		t.Fatalf("after a read with no uname: credentialed linux findings = %v, want the one finding still open (the read judged the kernel neither way)", got)
	}
	var kernelTransitions, sshOpen, sshRemediated int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		if err := cn.QueryRow(ctx, `SELECT count(*) FROM finding_history ft JOIN findings f ON f.tenant_id = ft.tenant_id AND f.finding_id = ft.finding_id
		   WHERE ft.tenant_id = $1 AND f.instance_locator = 'linux'`, s.tenant.UUID()).Scan(&kernelTransitions); err != nil {
			return err
		}
		return cn.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'open'), count(*) FILTER (WHERE status = 'remediated')
		   FROM findings WHERE tenant_id = $1 AND source = 'credentialed' AND instance_locator = 'openssh'`, s.tenant.UUID()).Scan(&sshOpen, &sshRemediated)
	}); err != nil {
		t.Fatal(err)
	}
	if kernelTransitions != 0 {
		t.Errorf("kernel finding transitions = %d, want 0 (nothing changed, nothing recorded — no flap)", kernelTransitions)
	}
	if sshOpen != 0 || sshRemediated != 1 {
		t.Errorf("openssh, absent from the whole-inventory read: open=%d remediated=%d, want 0/1 (absent means removed)", sshOpen, sshRemediated)
	}
}

// seedResoluteOpenSSH adds one resolute openssh fix above 8.9p1 so a resolute
// host with the jammy-era openssh reads as vulnerable.
func seedResoluteOpenSSH(t *testing.T) {
	t.Helper()
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	defer pool.Close()
	for _, q := range []string{
		`INSERT INTO vendor_advisories (advisory_ref, vendor) VALUES ('TEST-SSH-RESOLUTE','ubuntu') ON CONFLICT (advisory_ref) DO NOTHING`,
		`INSERT INTO vulnerability_defs (cve_id, title) VALUES ('CVE-2026-0002','CVE-2026-0002') ON CONFLICT (cve_id) DO NOTHING`,
		`INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
		 SELECT va.advisory_id, vd.vuln_def_id FROM vendor_advisories va, vulnerability_defs vd
		  WHERE va.advisory_ref='TEST-SSH-RESOLUTE' AND vd.cve_id='CVE-2026-0002' ON CONFLICT DO NOTHING`,
		`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
		 SELECT va.advisory_id, 'resolute', 'openssh', '1:9.0p1-1', 'dpkg'::version_comparator
		   FROM vendor_advisories va WHERE va.advisory_ref='TEST-SSH-RESOLUTE'
		 ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed resolute openssh: %v", err)
		}
	}
}

// The withdrawal is keyed to the PROPERTY — did this read judge the package
// positively — not to the two triggers the first reviews reported. The security
// review measured three more ways "cannot say" was being spelled "remediated";
// each is pinned here on an asset that already carries the finding, counting
// history rows (§5.19).

// A uname that names no installed kernel — a container reporting its host's
// kernel, a custom build, or one token from a rooted host — judges the kernel
// rows installed-not-running and the running kernel not at all. It withdraws
// nothing.
func TestAUnameNamingNoInstalledKernelWithdrawsNothing(t *testing.T) {
	db := testDB(t)
	seedKernelKeyspace(t)
	s := seed(t, db, "kernnone")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-2 * time.Hour)
	payload := func(kernel string) map[string]any {
		return map[string]any{"address": "10.0.0.39", "family": "ubuntu", "release": "resolute", "release_source": "os-release",
			"kernel_release": kernel, "installed": kernelInventory()}
	}
	s.observe(t, db, t0, sshService("10.0.0.39", 22, "SHA256:kernnone-hostkey"))
	s.observePackage(t, db, t0, payload("7.0.0-30-generic"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 {
		t.Fatalf("reboot-pending host: credentialed linux findings = %v, want 1 open", got)
	}
	s.nextScan(t, db)
	s.observePackage(t, db, t0.Add(time.Hour), payload("9.9.9-99-generic"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 || got["remediated"] != 0 {
		t.Fatalf("uname naming no installed kernel: credentialed linux findings = %v, want the finding still open (no running row was judged)", got)
	}
	if n := kernelHistoryRows(t, db, s); n != 0 {
		t.Errorf("kernel finding history rows = %d, want 0", n)
	}
}

// A release key whose keyspace has no rows for the package — an upgrade whose
// advisories are not imported yet, or a host that renamed its release — has no
// data, and no data is never a clean verdict (ADR-068). The kernel finding
// survives a resolute→jammy read (jammy has no `linux` row here); openssh, which
// jammy DOES know and which is still below jammy's fix, stays matched.
func TestAReleaseChangeWithdrawsNothingTheNewKeyspaceCannotJudge(t *testing.T) {
	db := testDB(t)
	seedKernelKeyspace(t)
	seedResoluteOpenSSH(t)
	seedJammyOpenSSH(t)
	s := seed(t, db, "kernrel")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-2 * time.Hour)
	inv := append(kernelInventory(), map[string]any{"name": "openssh", "binary": "openssh-server", "version": "1:8.9p1-3"})
	payload := func(release string) map[string]any {
		return map[string]any{"address": "10.0.0.40", "family": "ubuntu", "release": release, "release_source": "os-release",
			"kernel_release": "7.0.0-30-generic", "installed": inv}
	}
	s.observe(t, db, t0, sshService("10.0.0.40", 22, "SHA256:kernrel-hostkey"))
	s.observePackage(t, db, t0, payload("resolute"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 {
		t.Fatalf("resolute read: credentialed linux findings = %v, want 1 open", got)
	}
	s.nextScan(t, db)
	s.observePackage(t, db, t0.Add(time.Hour), payload("jammy"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 || got["remediated"] != 0 {
		t.Fatalf("after a release change to a keyspace with no linux rows: linux findings = %v, want still open", got)
	}
	var sshOpen int
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT count(*) FROM findings WHERE tenant_id = $1 AND source = 'credentialed' AND instance_locator = 'openssh' AND status = 'open'`, s.tenant.UUID()).Scan(&sshOpen)
	}); err != nil {
		t.Fatal(err)
	}
	if sshOpen == 0 {
		t.Errorf("openssh below jammy's fix: no open credentialed finding; the new keyspace knows the package and still matches it")
	}
}

// Two package observations for one host in one sweep: the NEWEST decides. The
// older says the host runs the fix, the newer says reboot pending; the finding
// is raised, whichever was inserted first.
func TestTheNewestPackageObservationDecides(t *testing.T) {
	db := testDB(t)
	seedKernelKeyspace(t)
	s := seed(t, db, "kernnewest")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-2 * time.Hour)
	payload := func(kernel string) map[string]any {
		return map[string]any{"address": "10.0.0.41", "family": "ubuntu", "release": "resolute", "release_source": "os-release",
			"kernel_release": kernel, "installed": kernelInventory()}
	}
	s.observe(t, db, t0, sshService("10.0.0.41", 22, "SHA256:kernnewest-hostkey"))
	s.observePackage(t, db, t0.Add(time.Hour), payload("7.0.0-30-generic")) // newer, inserted first
	s.observePackage(t, db, t0, payload("7.0.0-31-generic"))                // older, inserted second
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 {
		t.Fatalf("two reads in one sweep, newest says reboot pending: linux findings = %v, want 1 open (the newest read decides)", got)
	}
}

// A close and a later re-detection are BOTH in the history: open→remediated,
// then remediated→open, so the timeline never ends on a remediation the host
// undid.
func TestACredentialedReopenIsRecorded(t *testing.T) {
	db := testDB(t)
	seedKernelKeyspace(t)
	s := seed(t, db, "kernreopen")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-3 * time.Hour)
	payload := func(kernel string) map[string]any {
		return map[string]any{"address": "10.0.0.42", "family": "ubuntu", "release": "resolute", "release_source": "os-release",
			"kernel_release": kernel, "installed": kernelInventory()}
	}
	s.observe(t, db, t0, sshService("10.0.0.42", 22, "SHA256:kernreopen-hostkey"))
	for i, kernel := range []string{"7.0.0-30-generic", "7.0.0-31-generic", "7.0.0-30-generic"} {
		if i > 0 {
			s.nextScan(t, db)
		}
		s.observePackage(t, db, t0.Add(time.Duration(i)*time.Hour), payload(kernel))
		if err := c.SweepOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 {
		t.Fatalf("booted back into the old kernel: linux findings = %v, want 1 open", got)
	}
	var rows []string
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		r, err := cn.Query(ctx, `SELECT ft.from_status::text || '>' || ft.to_status::text FROM finding_history ft JOIN findings f ON f.tenant_id = ft.tenant_id AND f.finding_id = ft.finding_id
		   WHERE ft.tenant_id = $1 AND f.instance_locator = 'linux' ORDER BY ft.changed_at`, s.tenant.UUID())
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var t string
			if err := r.Scan(&t); err != nil {
				return err
			}
			rows = append(rows, t)
		}
		return r.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0] != "open>remediated" || rows[1] != "remediated>open" {
		t.Errorf("kernel finding history = %v, want [open>remediated remediated>open]", rows)
	}
}

func kernelHistoryRows(t *testing.T, db *store.DB, s seeded) int {
	t.Helper()
	var n int
	if err := db.Read(context.Background(), s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT count(*) FROM finding_history ft JOIN findings f ON f.tenant_id = ft.tenant_id AND f.finding_id = ft.finding_id
		   WHERE ft.tenant_id = $1 AND f.instance_locator = 'linux'`, s.tenant.UUID()).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}
