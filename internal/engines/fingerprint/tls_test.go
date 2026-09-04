package fingerprint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"
)

// TLS tests, against a real handshake with a real certificate.
//
// Not a fixture: the whole argument for the crypto/tls exception is that a
// handshake is a conversation no byte string performs, and a test that fed
// describeTLS a hand-built ConnectionState would prove nothing about whether the
// engine can complete one.

// Mutations, declared beside the tests that must kill them.
//
// mutate:subject internal/engines/fingerprint/tls.go
// mutate:test    ./internal/engines/fingerprint/ -run TestACertificateIsInspected|TestAVerifyingDial|TestTheChainIsBounded|TestKeyBits|TestAServerThatOnlySpeaks|TestALongChainIsTruncated|TestALPNIsOffered|TestAnUnusualExtensionCount
//
// ============================================================================
// mutate:case    the TLS config verifies the certificate like an ordinary client
// mutate:old     InsecureSkipVerify: true,
// mutate:new     InsecureSkipVerify: false,
// ============================================================================
//
// This is the one that makes the deliberateness LOAD-BEARING rather than
// incidental. InsecureSkipVerify is the single most alarming line in this
// repository and it is correct here — a verifying dial fails on exactly the
// certificates worth reporting. The risk with a correct-but-alarming line is
// that someone "fixes" it, the handshake starts failing against every
// self-signed certificate in the estate, and the scan reports nothing rather
// than reporting a problem. A silent loss of coverage.
//
// With this mutation, that repair fails the tests instead.
//
// mutate:case    an obsolete protocol version cannot be negotiated
// mutate:old     MinVersion:         tls.VersionTLS10,
// mutate:new     MinVersion:         tls.VersionTLS13,
//
// A scanner that refuses to speak TLS 1.0 cannot report a server that only
// speaks TLS 1.0, which is a finding week 6 wants. The floor is deliberate for
// the same reason verification is off.
//
// mutate:case    the certificate chain is described without a depth bound
// mutate:old     if len(certs) > MaxChainDepth {
// mutate:new     if len(certs) > 1<<30 {
//
// mutate:case    subject alternative names are lifted without a bound
// mutate:old     if len(out.DNSNames) >= MaxSANs {
// mutate:new     if len(out.DNSNames) >= 1<<30 {
//
// mutate:case    an unusual extension count is not flagged
// mutate:old     out.ExtensionsUnusual = out.ExtensionCount > MaxExtensionsFlagged
// mutate:new     out.ExtensionsUnusual = false
//
// Certificates from a scanned host are attacker-controlled by definition, and
// every name here becomes a JSON payload travelling to Core and into Postgres.
// The bound is the same argument as the banner read bound, one layer up.
//
// mutate:case    an unsized key algorithm reports zero bits as though measured
// mutate:old     return k.N.BitLen()
// mutate:new     return 0
//
// Zero means UNKNOWN, never "small". "RSA below 2048 bits" is a finding, and a
// wrong zero would be a false one.

// tlsServer starts a TLS listener with a certificate the test controls.
func tlsServer(t *testing.T, cert tls.Certificate) uint16 {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 4096)
				if n, _ := c.Read(buf); n > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.27.5\r\n\r\n"))
				}
			}()
		}
	}()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

// selfSigned builds a certificate with the properties week 6's rules ask about.
func selfSigned(t *testing.T, opts func(*x509.Certificate), bits int) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "lab-tls.invalid", Organization: []string{"CVAP Lab"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		DNSNames:     []string{"lab-tls.invalid"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if opts != nil {
		opts(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestACertificateIsInspectedRatherThanTrusted.
//
// The deliverable for week 6: a self-signed certificate that no verifying client
// would accept is fully described — subject, issuer, validity, names, key size —
// and the service behind it is identified through the same connection.
func TestACertificateIsInspectedRatherThanTrusted(t *testing.T) {
	port := tlsServer(t, selfSigned(t, nil, 2048))

	cfg := baseConfig(port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{
		Name: "https-head", Ports: []uint16{port}, TLS: true,
		Payload: []byte("HEAD / HTTP/1.1\r\nHost: {{target}}\r\nConnection: close\r\n\r\n"),
		Matches: []Match{{
			Pattern: `\r\nServer: nginx/(?P<version>[\w.]+)`,
			Service: "http", Product: "nginx", Confidence: 0.95,
		}},
	}}

	got := collect(t, cfg, target())
	if len(got) != 1 {
		t.Fatalf("want one observation, got %d", len(got))
	}
	p := got[0]
	if p.TLS == nil {
		t.Fatal("no tls object: the handshake did not complete, or its result was discarded")
	}
	if p.Product != "nginx" || p.Version != "1.27.5" {
		t.Errorf("the service behind TLS was not identified: product=%q version=%q", p.Product, p.Version)
	}
	if len(p.TLS.Chain) != 1 {
		t.Fatalf("chain length %d, want 1", len(p.TLS.Chain))
	}
	c := p.TLS.Chain[0]
	if !c.SelfSigned {
		t.Error("a certificate whose subject equals its issuer is not marked self-signed")
	}
	if c.KeyBits != 2048 {
		t.Errorf("key_bits = %d, want 2048", c.KeyBits)
	}
	if len(c.DNSNames) != 1 || c.DNSNames[0] != "lab-tls.invalid" {
		t.Errorf("dns_names = %v", c.DNSNames)
	}
	if p.TLS.Version == "" || p.TLS.CipherSuite == "" {
		t.Errorf("negotiated version %q and cipher %q must both be recorded",
			p.TLS.Version, p.TLS.CipherSuite)
	}
	if p.Method != "tls-probe" {
		t.Errorf("method = %q, want tls-probe", p.Method)
	}
	if !p.Solicited {
		t.Error("a handshake is bytes we sent first; solicited must be true")
	}
}

// TestAVerifyingDialCannotSeeTheCertificateAtAll.
//
// The control behind the mutation above, stated as a fact rather than an
// assumption: an ordinary verifying client gets an ERROR where this engine gets
// evidence. That is why InsecureSkipVerify is correct here and why turning it
// off would silently cost coverage rather than loudly breaking something.
func TestAVerifyingDialCannotSeeTheCertificateAtAll(t *testing.T) {
	port := tlsServer(t, selfSigned(t, nil, 2048))
	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	verifying := tls.Client(conn, &tls.Config{ServerName: "lab-tls.invalid", MinVersion: tls.VersionTLS12})
	if err := verifying.Handshake(); err == nil {
		t.Fatal("a verifying handshake SUCCEEDED against a self-signed certificate; " +
			"this test no longer demonstrates why inspectOnlyTLSConfig exists")
	}

	// And the engine's own configuration reaches the certificate.
	conn2, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn2.Close() }()
	inspecting := tls.Client(conn2, inspectOnlyTLSConfig("lab-tls.invalid"))
	if err := inspecting.Handshake(); err != nil {
		t.Fatalf("the inspecting handshake failed: %v", err)
	}
	if len(inspecting.ConnectionState().PeerCertificates) == 0 {
		t.Error("handshake succeeded and produced no certificate to inspect")
	}
}

// TestTheChainIsBoundedAndSoAreTheNames.
//
// A certificate from a scanned host is attacker-controlled. A thousand subject
// alternative names is a legal certificate and a payload nobody wants in
// Postgres; the count is still recorded, so the fact is not lost with the data.
func TestTheChainIsBoundedAndSoAreTheNames(t *testing.T) {
	many := make([]string, 0, 500)
	for i := range 500 {
		many = append(many, fmt.Sprintf("host%d.lab.invalid", i))
	}
	cert := selfSigned(t, func(c *x509.Certificate) { c.DNSNames = many }, 2048)

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	got := describeCert(parsed)
	if len(got.DNSNames) != MaxSANs {
		t.Errorf("dns_names has %d entries, want the bound of %d", len(got.DNSNames), MaxSANs)
	}
	if !got.NamesTruncated {
		t.Error("names were truncated and names_truncated is false, so the loss is invisible")
	}
}

// TestKeyBitsIsZeroRatherThanAGuessForAnUnsizedAlgorithm.
//
// Zero means UNKNOWN. "RSA below 2048 bits" is a finding, so a rule reading this
// field must be able to tell "not measured" from "measured and small".
func TestKeyBitsIsZeroRatherThanAGuessForAnUnsizedAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyBits(&x509.Certificate{PublicKey: &rsaKey.PublicKey}); got != 1024 {
		t.Errorf("rsa key_bits = %d, want 1024", got)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyBits(&x509.Certificate{PublicKey: &ecKey.PublicKey}); got != 384 {
		t.Errorf("ecdsa key_bits = %d, want 384", got)
	}

	if got := keyBits(&x509.Certificate{PublicKey: struct{}{}}); got != 0 {
		t.Errorf("an unsized algorithm reported %d bits; it must report 0 for unknown", got)
	}
}

// TestAServerThatOnlySpeaksAnOlderVersionIsStillReachable.
//
// ============================================================================
// The floor is deliberate: a client that refuses TLS 1.2 cannot report a
// server that only offers it.
// ============================================================================
//
// The first version of this file asserted certificate inspection against a
// server that happily negotiated TLS 1.3, so raising the client's MinVersion
// changed nothing and the mutation for it survived. A modern-only server does
// not exercise a floor — only an old one does.
//
// TLS 1.2 rather than 1.0 because Go's own server will not offer 1.0 any more;
// the mutation raises the floor to 1.3, which cannot talk to this server either
// way, so the bound is what is under test rather than the exact version.
func TestAServerThatOnlySpeaksAnOlderVersionIsStillReachable(t *testing.T) {
	cert := selfSigned(t, nil, 2048)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				if n, _ := c.Read(buf); n > 0 {
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.27.5\r\n\r\n"))
				}
			}()
		}
	}()

	cfg := baseConfig(uint16(ln.Addr().(*net.TCPAddr).Port))
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{
		Name: "tls-hello", Ports: []uint16{uint16(ln.Addr().(*net.TCPAddr).Port)}, TLS: true,
	}}

	got := collect(t, cfg, target())
	if len(got) != 1 || got[0].TLS == nil {
		t.Fatalf("no certificate from a TLS 1.2-only server: %+v", got)
	}
	if got[0].TLS.Version != "TLSv1.2" {
		t.Errorf("negotiated version = %q, want TLSv1.2", got[0].TLS.Version)
	}
}

// TestALongChainIsTruncatedAndSaysSo.
//
// A certificate chain is attacker-chosen: the host decides how many
// certificates to present, and each one here becomes a JSON object travelling
// to Core and a row's worth of payload in Postgres.
//
// Against describeTLS directly rather than through a handshake, because the
// bound is pure logic and building a ten-deep chain to exercise it would test
// x509.CreateCertificate rather than this.
func TestALongChainIsTruncatedAndSaysSo(t *testing.T) {
	one, err := x509.ParseCertificate(selfSigned(t, nil, 2048).Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	chain := make([]*x509.Certificate, 0, MaxChainDepth*2)
	for range MaxChainDepth * 2 {
		chain = append(chain, one)
	}

	got := describeTLS(tls.ConnectionState{
		Version:          tls.VersionTLS13,
		CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: chain,
	})
	if len(got.Chain) != MaxChainDepth {
		t.Errorf("described %d certificates, want the bound of %d", len(got.Chain), MaxChainDepth)
	}
	if !got.ChainTruncated {
		t.Error("the chain was truncated and chain_truncated is false, so the loss is invisible")
	}
	if got.ChainLength != MaxChainDepth*2 {
		t.Errorf("chain_length = %d, want the %d actually presented — the COUNT is evidence "+
			"even when the certificates are not kept", got.ChainLength, MaxChainDepth*2)
	}
}

// TestALPNIsOfferedSoTheAnswerCanBeNonEmpty.
//
// The `alpn` field existed while the config offered no protocols, so it could
// only ever be empty — a safety audit confirmed `alpn=[]` at a server with a
// hook on the ClientHello. A field the data can never populate is a claim
// nothing supports.
func TestALPNIsOfferedSoTheAnswerCanBeNonEmpty(t *testing.T) {
	if got := inspectOnlyTLSConfig("x").NextProtos; len(got) == 0 {
		t.Fatal("no ALPN protocols offered, so the negotiated value is always empty")
	}

	cert := selfSigned(t, nil, 2048)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"h2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() { defer func() { _ = c.Close() }(); _, _ = c.Write([]byte("x")) }()
		}
	}()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	cfg := baseConfig(port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{Name: "tls-hello", Ports: []uint16{port}, TLS: true}}

	got := collect(t, cfg, target())
	if len(got) != 1 || got[0].TLS == nil {
		t.Fatalf("no TLS payload: %+v", got)
	}
	if got[0].TLS.ALPN != "h2" {
		t.Errorf("alpn = %q, want h2 negotiated", got[0].TLS.ALPN)
	}
}

// TestAnUnusualExtensionCountIsFlaggedAndNothingIsDropped.
//
// MaxExtensionsFlagged bounds nothing — crypto/x509 has already parsed the
// extensions and this code copies none of them. The count is the evidence, and
// the flag says it is unusual. The constant's old comment claimed it "bounds the
// extension walk", which an audit pointed out described a walk that does not
// exist.
func TestAnUnusualExtensionCountIsFlaggedAndNothingIsDropped(t *testing.T) {
	ordinary, err := x509.ParseCertificate(selfSigned(t, nil, 2048).Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := describeCert(ordinary); got.ExtensionsUnusual {
		t.Errorf("an ordinary certificate with %d extensions is flagged as unusual",
			got.ExtensionCount)
	}

	many := selfSigned(t, func(c *x509.Certificate) {
		for i := range MaxExtensionsFlagged + 10 {
			c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
				Id: []int{1, 3, 6, 1, 4, 1, 99999, i}, Value: []byte{0x05, 0x00},
			})
		}
	}, 2048)
	parsed, err := x509.ParseCertificate(many.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	got := describeCert(parsed)
	if got.ExtensionCount <= MaxExtensionsFlagged {
		t.Fatalf("the fixture has %d extensions, which is not above the threshold of %d; "+
			"this test would pass for the wrong reason", got.ExtensionCount, MaxExtensionsFlagged)
	}
	if !got.ExtensionsUnusual {
		t.Error("a certificate with an unusual extension count is not flagged")
	}
}
