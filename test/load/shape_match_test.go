package load

import "testing"

// TestSyntheticSeedMatchesRealShape asserts the direct seed reproduces the
// distributions TestMeasureRealShape measured from the pipeline, so the load
// numbers are measured against a realistic shape rather than a convenient one.
func TestSyntheticSeedMatchesRealShape(t *testing.T) {
	db := testDB(t)
	tenant := newTenant(t, db)
	seedSynthetic(t, db, tenant, seedOpts{assets: 500, findings: 2500, avgExposure: 2.4})
	sh := measureShape(t, db, tenant)
	reportShape(t, "SYNTHETIC (avgExposure 2.4)", sh)

	if sh.assets != 500 {
		t.Errorf("assets = %d, want 500", sh.assets)
	}
	if sh.findings != 2500 {
		t.Errorf("findings = %d, want 2500", sh.findings)
	}
	// keys: moderate only (strength 2), 0/1/2 per asset present.
	if len(sh.strengths) != 1 || sh.strengths[2] == 0 {
		t.Errorf("key strengths = %v, want only moderate (2), as the real pipeline produces", buckets(sh.strengths))
	}
	for _, n := range []int{0, 1, 2} {
		if sh.keysPerAsset[n] == 0 {
			t.Errorf("no assets with %d keys; real shape has 0/1/2", n)
		}
	}
	// findings clustered 1-or-4 per endpoint.
	if sh.findingsPerEndpt[1] == 0 || sh.findingsPerEndpt[4] == 0 {
		t.Errorf("findings/endpoint = %v, want the 1-and-4 clustering real bad certs produce", buckets(sh.findingsPerEndpt))
	}
	// empty assets, null vuln_def_id — reproduced, not "improved".
	if sh.assetsNullOptional != sh.assets {
		t.Errorf("%d/%d assets all-optional-NULL; the real pipeline creates empty assets", sh.assetsNullOptional, sh.assets)
	}
	if sh.findingsNullVuln != sh.findings {
		t.Errorf("%d/%d findings vuln_def_id NULL; the pipeline never sets it", sh.findingsNullVuln, sh.findings)
	}
	// one live address per asset.
	if sh.currentAddrs[1] != sh.assets {
		t.Errorf("current addresses = %v, want 1 per asset", buckets(sh.currentAddrs))
	}
	// multi-exposure variant actually produced >1 exposure rows on some findings.
	if sh.exposurePerFind[2] == 0 && sh.exposurePerFind[3] == 0 {
		t.Errorf("exposure/finding = %v, want a multi-vantage spread at avgExposure 2.4", buckets(sh.exposurePerFind))
	}
}
