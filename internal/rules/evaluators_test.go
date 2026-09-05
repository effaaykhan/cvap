package rules

import (
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
)

// The evaluators, each against the case it must fire on and the case it must
// not. A rule that fires when it should not is a false finding, which costs
// more than a missed one (the skill's confidence rule), so the negative cases
// carry as much weight as the positive.
//
// Mutations, declared beside the tests that must kill them.
//
// mutate:subject internal/rules/evaluators.go
// mutate:test    ./internal/rules/ -run TestTLSExpired|TestTLSExpiring|TestTLSSelfSigned|TestTLSMissingChain|TestTLSWeakKey|TestTLSLegacy|TestPlaintext|TestHTTPNoRedirect|TestHTTPMissingHeaders|TestManagementUntrusted|TestSSHWeak|TestKeyBitsUnknown
//
// mutate:case    the expiry comparison is inverted
// mutate:old     if !notAfter.Before(now) {
// mutate:new     if notAfter.Before(now) {
//
// mutate:case    a not-yet-expired certificate also raises the expiry finding
// mutate:old     if remaining > time.Duration(p.WarnDays)*24*time.Hour {
// mutate:new     if remaining > time.Duration(p.WarnDays)*24*time.Hour && false {
//
// mutate:case    a self-signed cert on a dev asset is reported anyway
// mutate:old     if strings.EqualFold(strings.TrimSpace(sub.Environment), e) {
// mutate:new     if strings.EqualFold(strings.TrimSpace(sub.Environment), e) && false {
//
// mutate:case    a key the engine could not size is reported as weak
// mutate:old     if leaf.KeyBits == 0 || leaf.KeyBits >= p.MinRSABits {
// mutate:new     if leaf.KeyBits >= p.MinRSABits {
//
// mutate:case    a management port in a trusted zone is reported
// mutate:old     if !untrusted[zt] {
// mutate:new     if untrusted[zt] {

func mkRule(evaluator string, params map[string]any) Rule {
	b, _ := json.Marshal(params)
	return Rule{
		ID: uuid.New(), Name: evaluator, Evaluator: evaluator,
		Params: b, Severity: "medium", Confidence: 0.9, Version: 1,
	}
}

func svc(port int, proto string) ServiceObservation {
	return ServiceObservation{
		ObservationID: uuid.New(), ZoneID: uuid.New(),
		ObservedAt: time.Now(), Address: "10.10.0.11", Port: port, Protocol: proto,
	}
}

func withCert(s ServiceObservation, notAfter time.Time, selfSigned bool, chainLen, keyBits int) ServiceObservation {
	s.TLS = &TLSEvidence{Version: "TLSv1.3", CipherSuite: "TLS_AES_128_GCM_SHA256", ChainLength: chainLen}
	s.TLS.Chain = append(s.TLS.Chain, struct {
		Fingerprint        string `json:"fingerprint"`
		Subject            string `json:"subject"`
		Issuer             string `json:"issuer"`
		NotAfter           string `json:"not_after"`
		NotBefore          string `json:"not_before"`
		SelfSigned         bool   `json:"self_signed"`
		IsCA               bool   `json:"is_ca"`
		PublicKeyAlgorithm string `json:"public_key_algorithm"`
		KeyBits            int    `json:"key_bits"`
	}{
		Fingerprint: "SHA256:x", Subject: "CN=host", Issuer: "CN=issuer",
		NotAfter:   notAfter.UTC().Format(time.RFC3339),
		NotBefore:  notAfter.Add(-365 * 24 * time.Hour).UTC().Format(time.RFC3339),
		SelfSigned: selfSigned, PublicKeyAlgorithm: "RSA", KeyBits: keyBits,
	})
	return s
}

var now = time.Date(2026, 9, 6, 12, 0, 0, 0, time.UTC)

func run(t *testing.T, r Rule, s ServiceObservation, env string) []Finding {
	t.Helper()
	sub := Subject{AssetID: uuid.New(), Environment: env,
		Services: []ServiceObservation{s}, ZoneType: func(uuid.UUID) string { return "internal" }}
	got, err := Evaluators[r.Evaluator](r, sub, now)
	if err != nil {
		t.Fatalf("%s: %v", r.Evaluator, err)
	}
	return got
}

func TestTLSExpiredFiresOnlyOnAnExpiredCertificate(t *testing.T) {
	r := mkRule("tls.expired", nil)

	past := run(t, r, withCert(svc(443, "tcp"), now.Add(-24*time.Hour), false, 2, 2048), "")
	if len(past) != 1 {
		t.Fatalf("expired certificate raised %d findings, want 1", len(past))
	}

	future := run(t, r, withCert(svc(443, "tcp"), now.Add(24*time.Hour), false, 2, 2048), "")
	if len(future) != 0 {
		t.Errorf("a valid certificate raised %d expiry findings", len(future))
	}

	// No certificate at all: nothing to judge.
	if got := run(t, r, svc(80, "tcp"), ""); len(got) != 0 {
		t.Errorf("a service with no TLS raised %d", len(got))
	}
}

func TestTLSExpiringFiresInsideTheWindowAndNotOnceExpired(t *testing.T) {
	r := mkRule("tls.expiring", map[string]any{"warn_days": 30})

	soon := run(t, r, withCert(svc(443, "tcp"), now.Add(6*24*time.Hour), false, 2, 2048), "")
	if len(soon) != 1 {
		t.Fatalf("a certificate expiring in 6 days raised %d, want 1", len(soon))
	}

	// Already expired is tls.expired's finding, not this one — no double report.
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(-time.Hour), false, 2, 2048), ""); len(got) != 0 {
		t.Errorf("an already-expired certificate raised the EXPIRING finding %d times", len(got))
	}

	// Far out: fine.
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(200*24*time.Hour), false, 2, 2048), ""); len(got) != 0 {
		t.Errorf("a certificate 200 days out raised %d", len(got))
	}
}

func TestTLSSelfSignedExemptsDevByEnvironment(t *testing.T) {
	r := mkRule("tls.self_signed", map[string]any{"exempt_environments": []string{"dev", "lab"}})

	// Production (unset environment counts as production).
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), true, 1, 2048), ""); len(got) != 1 {
		t.Errorf("self-signed on an un-tagged asset raised %d, want 1 — unset is not dev", len(got))
	}
	// Dev: exempt.
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), true, 1, 2048), "dev"); len(got) != 0 {
		t.Errorf("self-signed on a dev asset raised %d, want 0", len(got))
	}
	// CA-signed: not this finding.
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), false, 2, 2048), ""); len(got) != 0 {
		t.Errorf("a CA-signed certificate raised the self-signed finding %d times", len(got))
	}
}

func TestTLSMissingChainNeedsANonSelfSignedLeafAlone(t *testing.T) {
	r := mkRule("tls.missing_chain", nil)

	// Leaf alone, not self-signed: the intermediates were left out.
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), false, 1, 2048), ""); len(got) != 1 {
		t.Errorf("a lone non-self-signed leaf raised %d, want 1", len(got))
	}
	// Self-signed leaf alone: that is the self-signed finding, not this one.
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), true, 1, 2048), ""); len(got) != 0 {
		t.Errorf("a self-signed leaf raised the missing-chain finding %d times", len(got))
	}
	// Full chain: fine.
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), false, 3, 2048), ""); len(got) != 0 {
		t.Errorf("a full chain raised %d", len(got))
	}
}

func TestTLSWeakKeyAndKeyBitsUnknownIsNotWeak(t *testing.T) {
	r := mkRule("tls.weak_key", map[string]any{"min_rsa_bits": 2048})

	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), false, 2, 1024), ""); len(got) != 1 {
		t.Errorf("a 1024-bit key raised %d, want 1", len(got))
	}
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), false, 2, 2048), ""); len(got) != 0 {
		t.Errorf("a 2048-bit key raised %d", len(got))
	}
	// Zero means UNKNOWN, never small (ADR-048 §8): a key the engine could not
	// size must not be reported as weak.
	if got := run(t, r, withCert(svc(443, "tcp"), now.Add(time.Hour), false, 2, 0), ""); len(got) != 0 {
		t.Errorf("an unsized key (0 bits) raised %d, want 0 — 0 is unknown not small", len(got))
	}
}

func TestTLSLegacyNegotiatedFiresOnOldVersionsOnly(t *testing.T) {
	r := mkRule("tls.legacy_negotiated", nil)
	for _, tc := range []struct {
		version string
		want    int
	}{
		{"TLSv1.0", 1}, {"TLSv1.1", 1}, {"TLSv1.2", 0}, {"TLSv1.3", 0},
	} {
		s := withCert(svc(443, "tcp"), now.Add(time.Hour), false, 2, 2048)
		s.TLS.Version = tc.version
		if got := run(t, r, s, ""); len(got) != tc.want {
			t.Errorf("%s raised %d, want %d", tc.version, len(got), tc.want)
		}
	}
}

func TestPlaintextServiceFiresOnNamedProtocolsWithoutTLS(t *testing.T) {
	r := mkRule("plaintext.service", map[string]any{"services": []string{"telnet"}})

	tel := svc(23, "tcp")
	tel.Service = "telnet"
	if got := run(t, r, tel, ""); len(got) != 1 {
		t.Errorf("telnet raised %d, want 1", len(got))
	}

	// A different protocol: not this rule.
	ftp := svc(21, "tcp")
	ftp.Service = "ftp"
	if got := run(t, r, ftp, ""); len(got) != 0 {
		t.Errorf("ftp raised the telnet rule %d times", len(got))
	}

	// Telnet over TLS is not plaintext.
	telTLS := withCert(svc(992, "tcp"), now.Add(time.Hour), false, 2, 2048)
	telTLS.Service = "telnet"
	if got := run(t, r, telTLS, ""); len(got) != 0 {
		t.Errorf("telnet-over-TLS raised %d", len(got))
	}
}

func TestHTTPNoRedirectFiresWhenPlainHTTPDoesNotRedirect(t *testing.T) {
	r := mkRule("http.no_https_redirect", nil)

	plain := svc(80, "tcp")
	plain.Service = "http"
	plain.Evidence = "HTTP/1.1 200 OK Server: nginx Content-Type: text/html"
	if got := run(t, r, plain, ""); len(got) != 1 {
		t.Errorf("a 200 on plain HTTP raised %d, want 1", len(got))
	}

	redir := svc(80, "tcp")
	redir.Service = "http"
	redir.Evidence = "HTTP/1.1 301 Moved Location: https://example.test/ Server: nginx"
	if got := run(t, r, redir, ""); len(got) != 0 {
		t.Errorf("a 301 to https raised %d, want 0", len(got))
	}
}

func TestHTTPMissingHeadersReportsWhatIsAbsent(t *testing.T) {
	r := mkRule("http.missing_headers", map[string]any{
		"required": []string{"Strict-Transport-Security", "X-Content-Type-Options"},
	})

	bare := svc(80, "tcp")
	bare.Service = "http"
	bare.Evidence = "HTTP/1.1 200 OK Server: nginx Content-Type: text/html"
	got := run(t, r, bare, "")
	if len(got) != 1 {
		t.Fatalf("a response with no security headers raised %d, want 1", len(got))
	}
	missing, _ := got[0].Evidence["missing"].([]string)
	if len(missing) != 2 {
		t.Errorf("reported %v missing, want both", got[0].Evidence["missing"])
	}

	full := svc(80, "tcp")
	full.Service = "http"
	full.Evidence = "HTTP/1.1 200 OK strict-transport-security: max-age=63072000 x-content-type-options: nosniff"
	if g := run(t, r, full, ""); len(g) != 0 {
		t.Errorf("a fully-headed response raised %d", len(g))
	}
}

func TestManagementUntrustedFiresOnlyFromAnUntrustedZone(t *testing.T) {
	r := mkRule("exposure.management_untrusted", map[string]any{
		"ports": []int{22, 3389}, "zone_types": []string{"external", "dmz"},
	})

	fire := func(zone string, port int) int {
		s := svc(port, "tcp")
		s.Service = "ssh"
		sub := Subject{AssetID: uuid.New(), Services: []ServiceObservation{s},
			ZoneType: func(uuid.UUID) string { return zone }}
		out, err := Evaluators[r.Evaluator](r, sub, now)
		if err != nil {
			t.Fatal(err)
		}
		return len(out)
	}

	if fire("external", 22) != 1 {
		t.Error("ssh from external raised nothing")
	}
	if fire("dmz", 3389) != 1 {
		t.Error("rdp from dmz raised nothing")
	}
	if fire("internal", 22) != 0 {
		t.Error("ssh from internal was reported — internal is trusted")
	}
	// branch and cloud are deliberately NOT untrusted (see the evaluator).
	if fire("branch", 22) != 0 {
		t.Error("branch was treated as untrusted; it is deliberately left out")
	}
	if fire("cloud", 22) != 0 {
		t.Error("cloud was treated as untrusted; it is deliberately left out")
	}
	// A non-management port from external: not this rule.
	if fire("external", 8080) != 0 {
		t.Error("a non-management port raised the management rule")
	}
}

func TestSSHWeakAlgorithmsReportsOfferedLegacyAlgorithms(t *testing.T) {
	r := mkRule("ssh.weak_algorithms", map[string]any{
		"host_key": []string{"ssh-rsa", "ssh-dss"},
		"kex":      []string{"diffie-hellman-group1-sha1"},
	})

	weak := svc(22, "tcp")
	weak.SSH = &SSHEvidence{
		HostKeyAlgorithms: []string{"ssh-ed25519", "ssh-rsa"},
		KexAlgorithms:     []string{"curve25519-sha256", "diffie-hellman-group1-sha1"},
	}
	got := run(t, r, weak, "")
	if len(got) != 1 {
		t.Fatalf("a server offering ssh-rsa and dh-group1 raised %d, want 1", len(got))
	}

	strong := svc(22, "tcp")
	strong.SSH = &SSHEvidence{
		HostKeyAlgorithms: []string{"ssh-ed25519"},
		KexAlgorithms:     []string{"curve25519-sha256"},
	}
	if g := run(t, r, strong, ""); len(g) != 0 {
		t.Errorf("a modern-only server raised %d", len(g))
	}
}

// TestSetEvaluatorsCarryTheSetTheyMatchedAgainst — the four set-matching
// evaluators must store not just the member they matched but the SET they
// matched against, so the evidence records what the branch actually decided on
// rather than a re-derivation that could disagree (session 19, note on ADR-050's
// evidence rule).
func TestSetEvaluatorsCarryTheSetTheyMatchedAgainst(t *testing.T) {
	nonEmptyStrs := func(t *testing.T, ev map[string]any, key string) {
		t.Helper()
		v, ok := ev[key].([]string)
		if !ok || len(v) == 0 {
			t.Errorf("evidence[%q] = %#v, want a non-empty []string (the set matched against)", key, ev[key])
		}
	}

	// tls.legacy_negotiated
	{
		s := withCert(svc(443, "tcp"), now.Add(time.Hour), false, 2, 2048)
		s.TLS.Version = "TLSv1.0"
		got := run(t, mkRule("tls.legacy_negotiated", nil), s, "")
		if len(got) != 1 {
			t.Fatalf("legacy: raised %d, want 1", len(got))
		}
		nonEmptyStrs(t, got[0].Evidence, "legacy_versions")
	}

	// tls.weak_cipher_negotiated — unfireable at the wire (session 16), but a
	// unit test can present an insecure suite directly.
	{
		insecure := tls.InsecureCipherSuites()
		if len(insecure) == 0 {
			t.Skip("no insecure cipher suites in this Go build")
		}
		s := withCert(svc(443, "tcp"), now.Add(time.Hour), false, 2, 2048)
		s.TLS.CipherSuite = insecure[0].Name
		got := run(t, mkRule("tls.weak_cipher_negotiated", nil), s, "")
		if len(got) != 1 {
			t.Fatalf("weak cipher: raised %d, want 1", len(got))
		}
		nonEmptyStrs(t, got[0].Evidence, "insecure_suites")
	}

	// exposure.management_untrusted
	{
		r := mkRule("exposure.management_untrusted", map[string]any{
			"ports": []int{22}, "zone_types": []string{"external"},
		})
		s := svc(22, "tcp")
		s.Service = "ssh"
		sub := Subject{AssetID: uuid.New(), Services: []ServiceObservation{s},
			ZoneType: func(uuid.UUID) string { return "external" }}
		got, err := Evaluators[r.Evaluator](r, sub, now)
		if err != nil || len(got) != 1 {
			t.Fatalf("management: %d findings, err %v", len(got), err)
		}
		if v, ok := got[0].Evidence["management_ports"].([]int); !ok || len(v) == 0 {
			t.Errorf("evidence[management_ports] = %#v, want non-empty []int", got[0].Evidence["management_ports"])
		}
		nonEmptyStrs(t, got[0].Evidence, "untrusted_zone_types")
	}

	// ssh.weak_algorithms
	{
		r := mkRule("ssh.weak_algorithms", map[string]any{
			"host_key": []string{"ssh-rsa"}, "kex": []string{"diffie-hellman-group1-sha1"},
		})
		s := svc(22, "tcp")
		s.SSH = &SSHEvidence{
			HostKeyAlgorithms: []string{"ssh-ed25519", "ssh-rsa"},
			KexAlgorithms:     []string{"curve25519-sha256", "diffie-hellman-group1-sha1"},
		}
		got := run(t, r, s, "")
		if len(got) != 1 {
			t.Fatalf("ssh: raised %d, want 1", len(got))
		}
		nonEmptyStrs(t, got[0].Evidence, "weak_host_key_set")
		nonEmptyStrs(t, got[0].Evidence, "weak_kex_set")
	}
}
