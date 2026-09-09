package correlate_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/effaaykhan/cvap/internal/correlate"
	"github.com/effaaykhan/cvap/internal/store"
)

// P3.3 last-link acceptance (ADR-070): the pipeline turns a resolved release plus
// a banner version into a real advisory FINDING carrying its CVE. This is the step
// that was missing — S31 proved the verdict, this proves the finding.
//
// Same real data as the release acceptance and TestAdvisoryMatchInSitu: USN-1467-1
// fixes CVE-2012-2122 in hardy's mysql-dfsg-5.0 at 5.0.96-0ubuntu3 (dpkg), and
// Metasploitable runs 5.0.51a-3ubuntu5 — below the fix. The difference here is that
// nothing in the test does the match: the correlation sweep does, and the finding
// is read back from the findings table with its vuln_def_id resolved to the CVE.
//
// This session STOPS here (ADR-070): it does not order the finding by priority —
// P3.4's ordering acceptance is next session, built on findings this path already
// produces rather than on a matcher written the same hour. If the path works there
// is a real finding; if it does not, that is the session's finding.
func TestAdvisoryFindingProducedOnMetasploitable(t *testing.T) {
	db := testDB(t)
	seedReleaseKeyspace(t) // USN-1467-1 + product_packages (MySQL -> mysql-dfsg-5.0)
	s := seed(t, db, "advfind")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	now := time.Now().UTC()

	// Two version-bearing services that band-vote hardy (the safe-mode pair, ADR-065):
	// OpenSSH carries the Ubuntu family hint so release resolution runs at all, and
	// MySQL is the one the advisory judges.
	ssh := sshService("10.0.0.9", 22, "SHA256:metasploitable-advfind")
	ssh["version"] = "4.7p1"
	ssh["os"] = map[string]any{"hint": "Ubuntu", "source": "service banner"}
	s.observe(t, db, now, ssh)
	s.observe(t, db, now, map[string]any{
		"address": "10.0.0.9", "port": 3306, "protocol": "tcp",
		"service": "mysql", "product": "MySQL", "version": "5.0.51a-3ubuntu5",
		"method": "banner", "solicited": true, "safety_mode": "intrusive",
	})

	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// Read back the advisory finding the PIPELINE produced — vuln_def_id resolved to
	// its CVE. Advisory findings are exactly those with a vuln_def_id (rule findings
	// carry none), so this isolates them without guessing.
	type row struct {
		cve        string
		source     string
		dedup      string
		locator    string
		severity   string
		assetID    string
		confidence float64
		evidence   map[string]any
		vulnCount  int
	}
	var got row
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		// Count all advisory findings — the pipeline raises one per matched CVE, so
		// on a dev DB holding the full USN keyspace this is many (MySQL 5.0.51a on
		// hardy is genuinely below dozens of advisories); on a seed-only CI DB it is
		// one (USN-1467-1). Either way the acceptance is "real advisory findings
		// exist", so this asserts >= 1, and the specific-CVE read below pins CVE-
		// 2012-2122 with the right shape regardless of how many siblings it has.
		if err := cn.QueryRow(ctx,
			`SELECT count(*) FROM findings WHERE tenant_id=$1 AND vuln_def_id IS NOT NULL`,
			s.tenant.UUID()).Scan(&got.vulnCount); err != nil {
			return err
		}
		var ev []byte
		if err := cn.QueryRow(ctx, `
			SELECT vd.cve_id, f.source::text, f.dedup_key, coalesce(f.instance_locator,''),
			       f.severity::text, f.asset_id::text, f.confidence, e.data
			  FROM findings f
			  JOIN vulnerability_defs vd ON vd.vuln_def_id = f.vuln_def_id
			  LEFT JOIN evidence e ON e.tenant_id = f.tenant_id AND e.finding_id = f.finding_id
			 WHERE f.tenant_id=$1 AND vd.cve_id = 'CVE-2012-2122'
			 LIMIT 1`, s.tenant.UUID()).Scan(
			&got.cve, &got.source, &got.dedup, &got.locator, &got.severity, &got.assetID, &got.confidence, &ev); err != nil {
			return err
		}
		return json.Unmarshal(ev, &got.evidence)
	}); err != nil {
		t.Fatalf("read advisory finding: %v", err)
	}

	// Real advisory findings exist on the host — the session's whole deliverable.
	if got.vulnCount < 1 {
		t.Fatalf("no advisory findings produced; the path did not run")
	}
	if got.cve != "CVE-2012-2122" {
		t.Errorf("finding CVE = %q, want CVE-2012-2122", got.cve)
	}
	// Source names how the evidence was obtained (a network banner), ADR-070.
	if got.source != "network" {
		t.Errorf("source = %q, want network (banner-obtained evidence)", got.source)
	}
	// Dedup is the package, not the port (ADR-070): the claim is about the package.
	wantDedup := "advisory|" + got.assetID + "|mysql-dfsg-5.0|CVE-2012-2122"
	if got.dedup != wantDedup {
		t.Errorf("dedup_key = %q, want %q (asset+package+cve, not the port)", got.dedup, wantDedup)
	}
	if got.locator != "mysql-dfsg-5.0" {
		t.Errorf("locator = %q, want the package name", got.locator)
	}
	// Severity is a real band: from the CVE's CVSS where the keyspace scores it,
	// else the rule default 'medium' (unscored -> default, never a fabricated low,
	// ADR-069). Which one depends on whether this DB's vulnerability_defs carry a
	// CVSS for the CVE, so assert it is a valid non-empty band, not a fixed value.
	switch got.severity {
	case "info", "low", "medium", "high", "critical":
	default:
		t.Errorf("severity = %q, not a valid band", got.severity)
	}
	// Confidence is COMPOSED, not a constant (ADR-072/073): min of release resolution
	// (2 unanimous votes -> 0.80), version extraction (1.0 pass-through today), and the
	// package map (1.0 pass-through today). Only release carries a real sub-1.0 value,
	// so the finding is 0.80 — the release confidence alone. Not the old fixed 0.5, not
	// 1.00: an inferred claim reads exactly as trustworthy as the one input we weigh.
	if got.confidence < 0.795 || got.confidence > 0.805 {
		t.Errorf("confidence = %.3f, want ~0.80 (release binds; version/map are 1.0 pass-throughs)", got.confidence)
	}
	// The evidence lets an analyst confirm the match by hand without re-scanning,
	// AND shows the confidence breakdown (ADR-072/073).
	for _, k := range []string{"advisory", "cve", "package", "installed_version", "fixed_version", "comparator", "confidence_inputs"} {
		if got.evidence[k] == nil || got.evidence[k] == "" {
			t.Errorf("evidence missing %q: %+v", k, got.evidence)
		}
	}
	// The breakdown shows release_resolution binding, version/map as 1.0 pass-throughs
	// — the coverage statement visible on the finding: only release is weighed today.
	if ci, ok := got.evidence["confidence_inputs"].(map[string]any); ok {
		rel, _ := ci["release_resolution"].(float64)
		ve, _ := ci["version_extraction"].(float64)
		pm, _ := ci["package_map"].(float64)
		composed, _ := ci["composed"].(float64)
		if ve != 1.0 || pm != 1.0 {
			t.Errorf("version_extraction (%.2f) and package_map (%.2f) should be 1.0 pass-throughs today", ve, pm)
		}
		if composed != rel {
			t.Errorf("composed (%.2f) should equal release_resolution (%.2f) — release is the only weighed input", composed, rel)
		}
	} else {
		t.Errorf("evidence confidence_inputs not a breakdown object: %+v", got.evidence["confidence_inputs"])
	}
	if got.evidence["installed_version"] != "5.0.51a-3ubuntu5" || got.evidence["fixed_version"] != "5.0.96-0ubuntu3" {
		t.Errorf("evidence versions wrong: installed=%v fixed=%v",
			got.evidence["installed_version"], got.evidence["fixed_version"])
	}
	t.Logf("pipeline produced: %s on %s (installed %v < fixed %v [%v]) source=%s severity=%s",
		got.cve, got.locator, got.evidence["installed_version"], got.evidence["fixed_version"],
		got.evidence["comparator"], got.source, got.severity)
}
