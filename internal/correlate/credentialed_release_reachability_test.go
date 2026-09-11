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

// observePackage writes one accepted `package` observation, the way the credentialed
// host engine's ingest would — the type the release-precedence rule reads.
func (s seeded) observePackage(t *testing.T, db *store.DB, at time.Time, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	conf := 1.0
	o := store.Observation{
		ID: uuid.New(), SubmissionID: s.subID, TaskID: s.taskID, ScanPointID: s.spID,
		ZoneID: s.zoneID, Type: store.ObsPackage, Payload: body,
		Confidence: &conf, ObservedAt: at,
	}
	if err := db.Write(context.Background(), s.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Observations{}).Insert(ctx, c, o, store.IngestAccepted)
	}); err != nil {
		t.Fatalf("insert package observation: %v", err)
	}
}

// TestCredentialedReleaseReachesResolutionWithoutInferredFamily is the ADR-089
// reachability proof, and it is deliberately an integration test, not a unit one.
// release_precedence_test.go proves credentialedAttribution READS the payload right;
// this proves the correlator REACHES it — the distinction ADR-089 turns on, and the
// [[dormant-rule-behind-a-gate]] lesson: a passing unit test is not proof the rule
// runs in the system.
//
// The host offers an SSH service (so an asset is created and identified) that yields
// NO OS family hint, plus a credentialed `package` observation. So the service-
// inferred family is "" — under the pre-ADR-089 code, `deriveRelease` sat behind an
// `if family != ""` gate and was skipped entirely, leaving the release NULL. The fix
// resolves family AND release from the exact /etc/os-release read, at confidence 1.0,
// with no dependence on the inferred family. That is the exact live failure measured
// on .146 (release stuck at the band vote because the package-only sweep had no
// family), now pinned so it cannot regress.
func TestCredentialedReleaseReachesResolutionWithoutInferredFamily(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "credreach")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	now := time.Now().UTC()

	// A service that identifies the host but carries no `os` hint: family stays "".
	ssh := sshService("10.0.0.9", 22, "SHA256:credreach-hostkey")
	s.observe(t, db, now, ssh)

	// The credentialed inventory: exact family + release read from /etc/os-release.
	s.observePackage(t, db, now, map[string]any{
		"address":        "10.0.0.9",
		"family":         "ubuntu",
		"release":        "jammy",
		"release_source": "os-release",
		"installed":      []map[string]any{{"name": "openssh-server", "version": "1:8.9p1-3"}},
	})

	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	var family string
	var release *string
	var relConf *float64
	var relProv, osProv []byte
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, cn *store.Conn) error {
		return cn.QueryRow(ctx, `SELECT coalesce(distro_family,''), distro_release, release_confidence,
		        release_provenance, os_provenance
		    FROM assets WHERE tenant_id=$1 LIMIT 1`, s.tenant.UUID()).Scan(&family, &release, &relConf, &relProv, &osProv)
	}); err != nil {
		t.Fatal(err)
	}

	// Family resolved from the exact read, NOT from any service hint (there was none).
	if family != "ubuntu" {
		t.Fatalf("distro_family = %q, want ubuntu (from /etc/os-release, no service hint present)", family)
	}
	// Release resolved even though the service-inferred family was empty — the gate
	// that made ADR-077 unreachable is gone.
	if release == nil || *release != "jammy" {
		t.Fatalf("distro_release = %v, want jammy (exact os-release, reached without inferred family)", release)
	}
	if relConf == nil || *relConf != 1.0 {
		t.Errorf("release_confidence = %v, want 1.0 (ground truth outranks the band vote — ADR-089)", relConf)
	}

	// Provenance names the exact source on both columns, so an operator sees it was
	// read, not inferred.
	assertProvSource(t, "release_provenance", relProv, "package_manager")
	assertProvSource(t, "os_provenance", osProv, "os-release")
}

func assertProvSource(t *testing.T, label string, prov []byte, want string) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(prov, &m); err != nil {
		t.Errorf("%s not an object: %v (%s)", label, err, prov)
		return
	}
	if got, _ := m["source"].(string); got != want {
		t.Errorf("%s source = %q, want %q (%s)", label, got, want, prov)
	}
}
