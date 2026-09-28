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

// The releases these fixtures use are ones the Ubuntu feed cannot name.
//
// `resolute` and `jammy` are real, and the advisory keyspace is GLOBAL and
// untenanted by design (ADR-017 lists VENDOR_ADVISORY and ADVISORY_FIXED_PACKAGE
// among the tables that carry no tenant_id), so seeding a fresh tenant buys no
// isolation from it. These tests were written when the knowledge tables were
// empty and passed only for that reason. Once `make knowledge-usn` had run, the
// dev database held 332 `resolute` rows and 919 `jammy` ones and seven of them
// went red — `credentialedKernelFindings` counts every credentialed `linux`
// finding on the tenant, so real advisories matching the seeded inventory are
// counted too (101 and 653 on two runs; the number moves with the feed).
//
// The counts were the visible half. The worse half is that real data DELETED a
// scenario: TestAReleaseChangeWithdrawsNothingTheNewKeyspaceCannotJudge needs a
// release whose keyspace has no `linux` rows, and real jammy has 17. A test
// cannot demonstrate "no data is not a clean verdict" on a release that has the
// data. So the fixtures move to release names no vendor feed will ever emit,
// which makes the scenarios hold whatever has been ingested.
const (
	kernRelease      = "cvap-test-kern"       // knows `linux` (7.0.0-31.31) and `openssh`
	kernOtherRelease = "cvap-test-kern-other" // knows `openssh`, and never `linux`
)

// assertKeyspaceIsolated fails if any advisory that is not one of this package's
// own TEST- fixtures carries rows for the release.
//
// It exists because the bug it guards was invisible: nothing in the suite stated
// that it needed an empty keyspace, so ingesting a feed moved the results and no
// message said why. Without the guard the coupling returns the moment someone
// picks a release name a vendor later ships, and the failure surfaces as an
// arithmetic mismatch in a kernel test rather than as what it is. A test that
// depends on the absence of data has to say so, or the next reader debugs the
// wrong thing.
func assertKeyspaceIsolated(t *testing.T, pool *pgxpool.Pool, release string) {
	t.Helper()
	var n int
	var refs string
	// Only a handful of refs are named: the count is the finding, and a release
	// a vendor covers has hundreds, which would bury the sentence that says what
	// to do about it.
	if err := pool.QueryRow(context.Background(), `
		SELECT (SELECT count(*) FROM advisory_fixed_packages afp
		          JOIN vendor_advisories va USING (advisory_id)
		         WHERE afp.distro_release = $1 AND va.advisory_ref NOT LIKE 'TEST-%'),
		       coalesce((SELECT string_agg(ref, ', ' ORDER BY ref) FROM (
		           SELECT DISTINCT va.advisory_ref AS ref
		             FROM advisory_fixed_packages afp
		             JOIN vendor_advisories va USING (advisory_id)
		            WHERE afp.distro_release = $1 AND va.advisory_ref NOT LIKE 'TEST-%'
		            ORDER BY ref LIMIT 5) sample), '')`,
		release).Scan(&n, &refs); err != nil {
		t.Fatalf("check keyspace isolation for %s: %v", release, err)
	}
	if n > 0 {
		t.Fatalf("release %q carries %d advisory row(s) this package did not seed (e.g. %s). "+
			"These tests count every credentialed finding on the tenant and the advisory keyspace is "+
			"global and untenanted (ADR-017), so a vendor advisory on this release is counted with the "+
			"fixture's. Pick a release name no feed emits.", release, n, refs)
	}
}

// seedAdvisory writes one fixture USN — advisory, CVE, the map between them, and
// a single fixed package on one release — through the knowledge import role.
// Every ref it writes starts with TEST-, which is what assertKeyspaceIsolated
// uses to tell this package's fixtures from a vendor's.
func seedAdvisory(t *testing.T, pool *pgxpool.Pool, ref, cve, release, pkg, fixed string) {
	t.Helper()
	ctx := context.Background()
	stmts := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO vendor_advisories (advisory_ref, vendor) VALUES ($1,'ubuntu') ON CONFLICT (advisory_ref) DO NOTHING`, []any{ref}},
		{`INSERT INTO vulnerability_defs (cve_id, title) VALUES ($1,$1) ON CONFLICT (cve_id) DO NOTHING`, []any{cve}},
		{`INSERT INTO advisory_vuln_map (advisory_id, vuln_def_id)
		  SELECT va.advisory_id, vd.vuln_def_id FROM vendor_advisories va, vulnerability_defs vd
		   WHERE va.advisory_ref=$1 AND vd.cve_id=$2 ON CONFLICT DO NOTHING`, []any{ref, cve}},
		{`INSERT INTO advisory_fixed_packages (advisory_id, distro_release, package_name, fixed_version, comparator)
		  SELECT va.advisory_id, $2, $3, $4, 'dpkg'::version_comparator
		    FROM vendor_advisories va WHERE va.advisory_ref=$1
		  ON CONFLICT (advisory_id, distro_release, package_name) DO NOTHING`, []any{ref, release, pkg, fixed}},
	}
	for _, st := range stmts {
		if _, err := pool.Exec(ctx, st.q, st.args...); err != nil {
			t.Fatalf("seed advisory %s (%s %s on %s): %v", ref, pkg, fixed, release, err)
		}
	}
}

// seedKernelKeyspace adds one kernel USN to the keyspace: `linux` fixed at
// 7.0.0-31.31, one CVE, on kernRelease. Through the knowledge role like
// seedKernOtherReleaseOpenSSH.
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
	seedAdvisory(t, pool, "TEST-KERNEL", "CVE-2026-0001", kernRelease, "linux", "7.0.0-31.31")
	assertKeyspaceIsolated(t, pool, kernRelease)
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
		"address": "10.0.0.36", "family": "ubuntu", "release": kernRelease, "release_source": "os-release",
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
	seedKernOtherReleaseOpenSSH(t)
	s := seed(t, db, "kernnouname")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	t0 := time.Now().UTC().Add(-time.Hour)

	inv := kernelInventory()
	inv = append(inv, map[string]any{"name": "openssh", "binary": "openssh-server", "version": "1:8.9p1-3"})
	s.observe(t, db, t0, sshService("10.0.0.37", 22, "SHA256:kernnouname-hostkey"))
	s.observePackage(t, db, t0, map[string]any{
		"address": "10.0.0.37", "family": "ubuntu", "release": kernOtherRelease, "release_source": "os-release",
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
		t.Errorf("openssh below the other release's fix on the same read: credentialed findings = %d, want 1 (ordinary packages are still judged)", ssh)
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
		p := map[string]any{"address": "10.0.0.38", "family": "ubuntu", "release": kernRelease, "release_source": "os-release", "installed": installed}
		if kernel != "" {
			p["kernel_release"] = kernel
		}
		return p
	}
	s.observe(t, db, t0, sshService("10.0.0.38", 22, "SHA256:kernkeep-hostkey"))
	seedKernReleaseOpenSSH(t)
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

// seedKernReleaseOpenSSH adds an openssh fix above 8.9p1 on kernRelease, so a
// host there carrying the older openssh reads as vulnerable.
func seedKernReleaseOpenSSH(t *testing.T) {
	t.Helper()
	pool := knowledgePool(t)
	defer pool.Close()
	seedAdvisory(t, pool, "TEST-SSH-KERN", "CVE-2026-0002", kernRelease, "openssh", "1:9.0p1-1")
	assertKeyspaceIsolated(t, pool, kernRelease)
}

// seedKernOtherReleaseOpenSSH gives kernOtherRelease an openssh fix and nothing
// else. That asymmetry IS the fixture: a release whose keyspace knows one of the
// host's packages and has no row at all for `linux`, so a read that moves the
// host onto it judges openssh and cannot judge the kernel either way (ADR-068).
// It stands in for what real `jammy` was before the feed was ingested — jammy now
// carries 17 `linux` rows, which is precisely the scenario this release restores.
func seedKernOtherReleaseOpenSSH(t *testing.T) {
	t.Helper()
	pool := knowledgePool(t)
	defer pool.Close()
	seedAdvisory(t, pool, "TEST-SSH-KERN-OTHER", "CVE-2026-0003", kernOtherRelease, "openssh", "1:8.9p1-3ubuntu0.6")
	assertKeyspaceIsolated(t, pool, kernOtherRelease)
	// The absence is load-bearing, so it is asserted rather than assumed. This
	// catches what assertKeyspaceIsolated cannot: a future TEST- fixture reusing
	// this release for a kernel advisory, which would pass the vendor check and
	// silently turn the release-change scenario back into one that CAN judge.
	var linuxRows int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM advisory_fixed_packages WHERE distro_release = $1 AND package_name = 'linux'`,
		kernOtherRelease).Scan(&linuxRows); err != nil {
		t.Fatalf("check %s has no linux rows: %v", kernOtherRelease, err)
	}
	if linuxRows != 0 {
		t.Fatalf("%s carries %d `linux` advisory row(s); the release-change test needs a keyspace that CANNOT judge the kernel", kernOtherRelease, linuxRows)
	}
}

// knowledgePool dials as the knowledge import role, the only role allowed to
// write the global feed tables.
func knowledgePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("KNOWLEDGE_IMPORT_DATABASE_URL")
	if url == "" {
		t.Skip("KNOWLEDGE_IMPORT_DATABASE_URL not set")
	}
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		t.Fatalf("connect as import role: %v", err)
	}
	return pool
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
		return map[string]any{"address": "10.0.0.39", "family": "ubuntu", "release": kernRelease, "release_source": "os-release",
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
// survives a move from kernRelease to kernOtherRelease, whose keyspace has no
// `linux` row at all; openssh, which that release DOES know and which is still
// below its fix, stays matched. Both releases are synthetic precisely so the
// "has no rows for the package" half stays true — see the note at the top.
func TestAReleaseChangeWithdrawsNothingTheNewKeyspaceCannotJudge(t *testing.T) {
	db := testDB(t)
	seedKernelKeyspace(t)
	seedKernReleaseOpenSSH(t)
	seedKernOtherReleaseOpenSSH(t)
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
	s.observePackage(t, db, t0, payload(kernRelease))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := credentialedKernelFindings(t, db, s); got["open"] != 1 {
		t.Fatalf("first read on kernRelease: credentialed linux findings = %v, want 1 open", got)
	}
	s.nextScan(t, db)
	s.observePackage(t, db, t0.Add(time.Hour), payload(kernOtherRelease))
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
		t.Errorf("openssh below the new release's fix: no open credentialed finding; the new keyspace knows the package and still matches it")
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
		return map[string]any{"address": "10.0.0.41", "family": "ubuntu", "release": kernRelease, "release_source": "os-release",
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
		return map[string]any{"address": "10.0.0.42", "family": "ubuntu", "release": kernRelease, "release_source": "os-release",
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
