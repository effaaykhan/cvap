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

// Week 6's deliverable, end to end: a scan produces findings a human can verify
// by hand, with the exposure and evidence that make them verifiable.
//
// The unit tests in internal/rules prove each evaluator. This proves the
// pipeline: that the tls object survives from observation to rule, that the
// finding is keyed the way ADR-010 says, that exposure is one row per vantage
// point, and that the evidence carries enough to confirm the finding without
// re-scanning.

// findingRow is what the assertions read back.
type findingRow struct {
	ruleName string
	severity string
	locator  string
	summary  string
	status   string
}

func findingsFor(t *testing.T, db *store.DB, tenant store.TenantID) map[string]findingRow {
	t.Helper()
	out := map[string]findingRow{}
	if err := db.Read(context.Background(), tenant, func(ctx context.Context, c *store.Conn) error {
		rows, err := c.Query(ctx, `
			SELECT r.name, f.severity, coalesce(f.instance_locator,''), f.status,
			       coalesce((e.data ->> 'summary'), '')
			  FROM findings f
			  JOIN rules r ON r.rule_id = f.rule_id
			  LEFT JOIN evidence e ON e.finding_id = f.finding_id
			 WHERE f.tenant_id = $1`, tenant.UUID())
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var fr findingRow
			if err := rows.Scan(&fr.ruleName, &fr.severity, &fr.locator, &fr.status, &fr.summary); err != nil {
				return err
			}
			out[fr.ruleName] = fr
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// expiredCertService is a TLS service whose certificate expired.
func expiredCertService(address string, notAfter time.Time) map[string]any {
	return map[string]any{
		"address": address, "port": 443, "protocol": "tcp",
		"service": "http", "product": "nginx", "method": "tls-probe",
		"solicited": true, "safety_mode": "intrusive",
		"tls": map[string]any{
			"version": "TLSv1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
			"chain_length": 1,
			"chain": []any{map[string]any{
				"fingerprint": "SHA256:expiredcert",
				"subject":     "CN=old.example.test", "issuer": "CN=old.example.test",
				"not_before":  notAfter.Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339),
				"not_after":   notAfter.UTC().Format(time.RFC3339),
				"self_signed": true, "public_key_algorithm": "RSA", "key_bits": 2048,
			}},
		},
	}
}

func telnetService(address string) map[string]any {
	return map[string]any{
		"address": address, "port": 23, "protocol": "tcp",
		"service": "telnet", "method": "banner", "solicited": false, "safety_mode": "safe",
		"evidence": "Ubuntu 22.04 LTS login:",
	}
}

// TestAScanProducesFindingsWithEvidenceAndExposure.
func TestAScanProducesFindingsWithEvidenceAndExposure(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "findings")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	// Observations are timestamped in the PAST: the sweep reads observed_at <
	// its own clock (a future-dated observation is not yet real), so a test that
	// stamps "now" races that boundary.
	now := time.Now().UTC().Add(-2 * time.Hour)

	// A host with an expired, self-signed certificate on 443 and telnet on 23.
	// The cert expired a day ago; it is also self-signed on an un-tagged (so
	// production) asset; and it presents only its leaf.
	s.observe(t, db, now, expiredCertService("10.10.0.50", now.Add(-24*time.Hour)))
	s.observe(t, db, now, telnetService("10.10.0.50"))
	// A CA-signed certificate presenting only its leaf, for missing-chain: a
	// self-signed cert is correctly EXEMPT from that rule (it is its own chain),
	// so a separate endpoint is needed to exercise it.
	s.observe(t, db, now, leafOnlyCertService("10.10.0.50"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	got := findingsFor(t, db, s.tenant)

	// The self-signed expired cert on 443 raises expired AND self-signed, both
	// on 443/tcp. It does NOT raise missing-chain: a self-signed leaf is its own
	// chain, and that exemption is the correct behaviour.
	for _, want := range []string{"tls-certificate-expired", "tls-self-signed-non-dev"} {
		fr, ok := got[want]
		if !ok {
			t.Errorf("%s did not fire", want)
			continue
		}
		if fr.locator != "443/tcp" {
			t.Errorf("%s locator = %q, want 443/tcp", want, fr.locator)
		}
		if fr.summary == "" {
			t.Errorf("%s has no summary in its evidence; a finding an operator cannot read "+
				"is one they will dispute", want)
		}
	}
	if _, ok := got["tls-missing-chain"]; ok {
		// It fired on 443 — but 443 is self-signed and must be exempt. It should
		// only fire on the CA-signed leaf-only endpoint.
		if got["tls-missing-chain"].locator == "443/tcp" {
			t.Error("missing-chain fired on the self-signed cert; a self-signed leaf is its own chain")
		}
	}
	if got["tls-missing-chain"].locator != "8443/tcp" {
		t.Errorf("missing-chain fired on %q, want 8443/tcp (the CA-signed leaf-only endpoint)",
			got["tls-missing-chain"].locator)
	}
	// Telnet raises the plaintext finding on 23/tcp.
	if fr, ok := got["plaintext-telnet"]; !ok {
		t.Error("plaintext-telnet did not fire")
	} else if fr.locator != "23/tcp" || fr.severity != "high" {
		t.Errorf("plaintext-telnet: locator=%q severity=%q", fr.locator, fr.severity)
	}

	// The expiring-soon rule must NOT also fire — the cert is already expired,
	// and that is one finding, not two.
	if _, ok := got["tls-certificate-expiring-soon"]; ok {
		t.Error("an already-expired certificate also raised the expiring-soon finding")
	}

	// Exposure: one row per finding per vantage point, and the evidence carries
	// the observation link.
	if err := db.Read(ctx, s.tenant, func(ctx context.Context, conn *store.Conn) error {
		var exposures, withObs int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM finding_exposure WHERE tenant_id = $1`,
			s.tenant.UUID()).Scan(&exposures); err != nil {
			return err
		}
		if exposures < 3 {
			t.Errorf("%d exposure rows, want at least one per finding", exposures)
		}
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM evidence
			 WHERE tenant_id = $1 AND observation_id IS NOT NULL`,
			s.tenant.UUID()).Scan(&withObs); err != nil {
			return err
		}
		if withObs == 0 {
			t.Error("no evidence row links to the observation that produced it; the finding " +
				"cannot be traced back to what was seen")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestTheSameIssueFromTwoZonesIsOneFindingWithTwoExposures.
//
// ADR-010: one finding, two exposures — never two findings. This is the number
// an executive reads first, and inflating it by vantage-point count is the
// failure the rule exists against.
func TestTheSameIssueFromTwoZonesIsOneFindingWithTwoExposures(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "twozone")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	now := time.Now().UTC().Add(-2 * time.Hour)

	// A second zone in the same tenant, so the same endpoint can be seen from
	// two vantage points.
	var zone2 uuid.UUID
	if err := db.Write(ctx, s.tenant, func(ctx context.Context, conn *store.Conn) error {
		z, err := (store.Zones{}).Create(ctx, conn, "z2-"+uuid.NewString()[:8], store.ZoneDMZ, 2, "")
		if err != nil {
			return err
		}
		zone2 = z.ID
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// The same telnet endpoint, observed from the seed zone and from zone2. Both
	// carry the same ssh host key so they resolve to one asset — a plaintext
	// finding needs a second observation on the same asset from another zone.
	const hostKey = "SHA256:twozonehostkey"
	obsFrom := func(zoneID uuid.UUID, at time.Time) {
		p := telnetService("10.10.0.51")
		p["ssh"] = map[string]any{"host_key_type": "ssh-ed25519", "fingerprint": hostKey}
		s.observeFromZone(t, db, zoneID, at, p)
		// A second, independent moderate key so the two observations merge to
		// one asset rather than staying separate.
		tp := tlsService("10.10.0.51", 443, "SHA256:twozonecert")
		s.observeFromZone(t, db, zoneID, at, tp)
	}
	obsFrom(s.zoneID, now)
	obsFrom(zone2, now.Add(time.Minute))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	if err := db.Read(ctx, s.tenant, func(ctx context.Context, conn *store.Conn) error {
		var findings, exposures int
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM findings f JOIN rules r ON r.rule_id = f.rule_id
			 WHERE f.tenant_id = $1 AND r.name = 'plaintext-telnet'`,
			s.tenant.UUID()).Scan(&findings); err != nil {
			return err
		}
		if findings != 1 {
			t.Errorf("%d telnet findings, want exactly 1 — two vantage points is two "+
				"exposures, not two findings (ADR-010)", findings)
		}
		if err := conn.QueryRow(ctx, `
			SELECT count(*) FROM finding_exposure fe
			  JOIN findings f ON f.finding_id = fe.finding_id
			  JOIN rules r ON r.rule_id = f.rule_id
			 WHERE fe.tenant_id = $1 AND r.name = 'plaintext-telnet'`,
			s.tenant.UUID()).Scan(&exposures); err != nil {
			return err
		}
		if exposures != 2 {
			t.Errorf("%d exposures on the telnet finding, want 2 (one per zone)", exposures)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// TestARemediatedIssueMovesToRemediatedWhenReObserved.
//
// A finding on an endpoint that was RE-OBSERVED and no longer fires is
// remediated. An endpoint that was simply not scanned is left alone — closing it
// would report a fix nobody made.
func TestARemediatedIssueMovesToRemediatedWhenReObserved(t *testing.T) {
	db := testDB(t)
	s := seed(t, db, "remediate")
	c := correlate.New(db, quietLogger())
	ctx := context.Background()
	now := time.Now().UTC().Add(-3 * time.Hour)

	// First scan: telnet is exposed, plus a cert so the asset has a stable key.
	first := telnetService("10.10.0.52")
	first["ssh"] = map[string]any{"host_key_type": "ssh-ed25519", "fingerprint": "SHA256:remediatehk"}
	s.observe(t, db, now, first)
	s.observe(t, db, now, tlsService("10.10.0.52", 443, "SHA256:remediatecert"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := findingsFor(t, db, s.tenant); got["plaintext-telnet"].status != "open" {
		t.Fatalf("telnet finding status = %q after first scan, want open", got["plaintext-telnet"].status)
	}

	// Second scan: 23/tcp is re-observed as something that is NOT telnet — the
	// admin replaced it with SSH. The telnet finding must move to remediated.
	second := map[string]any{
		"address": "10.10.0.52", "port": 23, "protocol": "tcp",
		"service": "ssh", "method": "banner", "solicited": false, "safety_mode": "safe",
		"evidence": "SSH-2.0-OpenSSH_9.6",
		"ssh":      map[string]any{"host_key_type": "ssh-ed25519", "fingerprint": "SHA256:remediatehk"},
	}
	s.observe(t, db, now.Add(time.Hour), second)
	s.observe(t, db, now.Add(time.Hour), tlsService("10.10.0.52", 443, "SHA256:remediatecert"))
	if err := c.SweepOnce(ctx); err != nil {
		t.Fatal(err)
	}

	got := findingsFor(t, db, s.tenant)
	if got["plaintext-telnet"].status != "remediated" {
		t.Errorf("telnet finding status = %q after the endpoint was re-observed without telnet, "+
			"want remediated", got["plaintext-telnet"].status)
	}
}

// observeFromZone is observe with an explicit zone, for the multi-vantage test.
func (s seeded) observeFromZone(t *testing.T, db *store.DB, zoneID uuid.UUID, at time.Time, payload map[string]any) {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	conf := 0.95
	o := store.Observation{
		ID: uuid.New(), SubmissionID: s.subID, TaskID: s.taskID, ScanPointID: s.spID,
		ZoneID: zoneID, Type: store.ObsService, Payload: body,
		Confidence: &conf, ObservedAt: at,
	}
	if err := db.Write(context.Background(), s.tenant, func(ctx context.Context, c *store.Conn) error {
		return (store.Observations{}).Insert(ctx, c, o, store.IngestAccepted)
	}); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
}

// leafOnlyCertService is a CA-signed certificate presenting only its leaf — the
// missing-chain case, distinct from self-signed. On 8443 so it does not collide
// with the expired self-signed cert on 443.
func leafOnlyCertService(address string) map[string]any {
	return map[string]any{
		"address": address, "port": 8443, "protocol": "tcp",
		"service": "http", "product": "nginx", "method": "tls-probe",
		"solicited": true, "safety_mode": "intrusive",
		"tls": map[string]any{
			"version": "TLSv1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256",
			"chain_length": 1,
			"chain": []any{map[string]any{
				"fingerprint": "SHA256:leafonly",
				"subject":     "CN=host.example.test", "issuer": "CN=Real CA",
				"not_before": "2026-01-01T00:00:00Z", "not_after": "2027-01-01T00:00:00Z",
				"self_signed": false, "public_key_algorithm": "RSA", "key_bits": 2048,
			}},
		},
	}
}
