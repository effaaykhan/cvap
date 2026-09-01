package ca_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/control/ca"
)

func devCA(t *testing.T) (*ca.CA, string, string) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath, err := ca.GenerateSelfSigned(dir, "CVAP Test CA", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	authority, err := ca.Open(ca.Config{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return authority, certPath, keyPath
}

func csrFor(t *testing.T, subject string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: subject}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// A CSR is attacker-controlled. Only its public key may cross into the leaf.
func TestNothingFromTheCSRReachesTheCertificate(t *testing.T) {
	authority, _, _ := devCA(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Ask for everything a hostile scan point would want: a chosen identity,
	// SANs it could serve under, and a CA bit.
	tmpl := &x509.CertificateRequest{
		Subject:        pkix.Name{CommonName: "core.internal", Organization: []string{"Anthropic"}},
		DNSNames:       []string{"core.internal", "*.example.test"},
		EmailAddresses: []string{"root@example.test"},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ca.ParseCSR(der)
	if err != nil {
		t.Fatalf("a well-formed CSR was rejected: %v", err)
	}

	spID := uuid.New()
	leafDER, _, _, _, err := authority.SignScanPoint(csr, spID, time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	if leaf.Subject.CommonName != spID.String() {
		t.Errorf("CN = %q; the CSR named its own identity", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 0 || len(leaf.EmailAddresses) != 0 || len(leaf.IPAddresses) != 0 {
		t.Errorf("requested SANs survived: dns=%v email=%v ip=%v",
			leaf.DNSNames, leaf.EmailAddresses, leaf.IPAddresses)
	}
	if leaf.IsCA {
		t.Error("issued leaf has the CA bit")
	}
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			t.Error("issued leaf carries ServerAuth; a scan point never serves (ADR-005)")
		}
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign != 0 {
		t.Error("issued leaf may sign certificates")
	}
	// The public key IS taken from the CSR — that is the one thing that crosses.
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&key.PublicKey) {
		t.Error("the issued certificate does not carry the CSR's public key")
	}
}

func TestCSRKeyBounds(t *testing.T) {
	t.Run("RSA below 2048 refused", func(t *testing.T) {
		k, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Skip(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.ParseCSR(der); err == nil {
			t.Error("1024-bit RSA accepted")
		}
	})

	t.Run("RSA above 4096 refused", func(t *testing.T) {
		// The upper bound is a DoS control: signature verification cost is
		// chosen by the submitter, and this runs before any authentication.
		// An 8192-bit key is generated rather than a larger one only because
		// generating one is slow; the bound is what is being tested.
		k, err := rsa.GenerateKey(rand.Reader, 8192)
		if err != nil {
			t.Skip(err)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, k)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.ParseCSR(der); err == nil {
			t.Error("8192-bit RSA accepted; verification cost is submitter-chosen")
		}
	})

	t.Run("P-256 accepted", func(t *testing.T) {
		if _, err := ca.ParseCSR(csrFor(t, "x")); err != nil {
			t.Errorf("P-256 rejected: %v", err)
		}
	})

	t.Run("size cap", func(t *testing.T) {
		if _, err := ca.ParseCSR(make([]byte, 1<<20)); err == nil {
			t.Error("a 1MB CSR was accepted")
		}
		if _, err := ca.ParseCSR(nil); err == nil {
			t.Error("an empty CSR was accepted")
		}
	})
}

// Open's refusals. Each is a startup failure standing in for a much later,
// much less legible one.
func TestOpenRefusals(t *testing.T) {
	_, certPath, keyPath := devCA(t)

	t.Run("world-writable key refused even with the flag", func(t *testing.T) {
		dir := t.TempDir()
		c, k, err := ca.GenerateSelfSigned(dir, "w", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(k, 0o666); err != nil {
			t.Fatal(err)
		}
		// The flag relaxes readability, never writability: anyone who can write
		// the key substitutes the CA.
		if _, err := ca.Open(ca.Config{CertPath: c, KeyPath: k, AllowSharedKeyFileMode: true}); err == nil {
			t.Error("a world-writable signing key was accepted")
		}
	})

	t.Run("world-readable key refused unless allowed", func(t *testing.T) {
		dir := t.TempDir()
		c, k, err := ca.GenerateSelfSigned(dir, "r", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(k, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Open(ca.Config{CertPath: c, KeyPath: k}); err == nil {
			t.Error("a 0644 signing key was accepted")
		}
		if _, err := ca.Open(ca.Config{CertPath: c, KeyPath: k, AllowSharedKeyFileMode: true}); err != nil {
			t.Errorf("AllowSharedKeyFileMode did not permit a readable key: %v", err)
		}
	})

	t.Run("key must match the certificate", func(t *testing.T) {
		other := t.TempDir()
		_, otherKey, err := ca.GenerateSelfSigned(other, "other", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Open(ca.Config{CertPath: certPath, KeyPath: otherKey}); err == nil {
			t.Error("a signing key from a different CA was accepted")
		}
	})

	t.Run("non-CA certificate refused", func(t *testing.T) {
		dir := t.TempDir()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "leaf, not a CA"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cp := filepath.Join(dir, "leaf.crt")
		kp := filepath.Join(dir, "leaf.key")
		k8, _ := x509.MarshalPKCS8PrivateKey(key)
		writeFile(t, cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
		writeFile(t, kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: k8}), 0o600)

		if _, err := ca.Open(ca.Config{CertPath: cp, KeyPath: kp}); err == nil {
			t.Error("a non-CA certificate was accepted as a CA")
		}
	})

	t.Run("expired CA refused", func(t *testing.T) {
		dir := t.TempDir()
		// A CA that expired an hour ago.
		if _, _, err := ca.GenerateSelfSigned(dir, "expired", -time.Hour); err != nil {
			t.Fatal(err)
		}
		if _, err := ca.Open(ca.Config{
			CertPath: filepath.Join(dir, "ca.crt"), KeyPath: filepath.Join(dir, "ca.key"),
		}); err == nil {
			t.Error("an expired CA was accepted; every certificate it issues is unvalidatable")
		}
	})

	t.Run("unrelated certificate in the chain refused", func(t *testing.T) {
		// Everything in this file is shipped to every scan point as a trust
		// anchor, over a connection the scan point cannot yet verify. A stray
		// block is a fleet-wide trusted root.
		strayDir := t.TempDir()
		strayCert, _, err := ca.GenerateSelfSigned(strayDir, "TOTALLY UNRELATED ROOT", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		stray := readFile(t, strayCert)
		combined := append(readFile(t, certPath), stray...)

		dir := t.TempDir()
		cp := filepath.Join(dir, "ca.crt")
		writeFile(t, cp, combined, 0o644)

		if _, err := ca.Open(ca.Config{CertPath: cp, KeyPath: keyPath}); err == nil {
			t.Error("an unrelated root in the chain was accepted and would be shipped to the fleet")
		}
	})

	t.Run("missing config", func(t *testing.T) {
		if _, err := ca.Open(ca.Config{}); err == nil {
			t.Error("an empty Config was accepted")
		}
	})
}

// GenerateSelfSigned must refuse rather than clobber, and must not follow a
// pre-existing file's mode.
func TestGenerateSelfSignedRefusesToClobber(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := ca.GenerateSelfSigned(dir, "first", time.Hour); err != nil {
		t.Fatal(err)
	}
	before := readFile(t, filepath.Join(dir, "ca.key"))

	if _, _, err := ca.GenerateSelfSigned(dir, "second", time.Hour); err == nil {
		t.Fatal("a second generation into the same directory succeeded; " +
			"silently replacing a live CA key is a fleet-wide outage")
	}
	if after := readFile(t, filepath.Join(dir, "ca.key")); string(after) != string(before) {
		t.Error("the existing signing key was modified")
	}

	info, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		t.Errorf("generated key is mode %04o; Open will refuse to load it", mode)
	}
}

// A leaf must never outlive its issuer.
func TestLeafNeverOutlivesTheCA(t *testing.T) {
	dir := t.TempDir()
	// A CA with 10 days left, well under the 90-day leaf lifetime.
	certPath, keyPath, err := ca.GenerateSelfSigned(dir, "short", 10*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := ca.Open(ca.Config{CertPath: certPath, KeyPath: keyPath})
	if err != nil {
		t.Fatal(err)
	}

	csr, err := ca.ParseCSR(csrFor(t, "x"))
	if err != nil {
		t.Fatal(err)
	}
	der, _, _, notAfter, err := authority.SignScanPoint(csr, uuid.New(), time.Now())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(authority.NotAfter()) {
		t.Errorf("leaf expires %s, after the CA at %s", leaf.NotAfter, authority.NotAfter())
	}
	if !notAfter.Equal(leaf.NotAfter) {
		t.Error("the returned notAfter disagrees with the certificate")
	}
}

// Serials must be unpredictable, not merely unique.
func TestSerialsAreRandomAndLarge(t *testing.T) {
	authority, _, _ := devCA(t)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		csr, err := ca.ParseCSR(csrFor(t, "x"))
		if err != nil {
			t.Fatal(err)
		}
		der, serial, _, _, err := authority.SignScanPoint(csr, uuid.New(), time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if seen[serial] {
			t.Fatalf("serial %s issued twice", serial)
		}
		seen[serial] = true

		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if leaf.SerialNumber.BitLen() < 64 {
			t.Errorf("serial has %d bits; unpredictability needs at least 64",
				leaf.SerialNumber.BitLen())
		}
	}
}

// Fingerprint is the identity everything else keys on, so its form is fixed.
func TestFingerprintForm(t *testing.T) {
	fp := ca.Fingerprint([]byte("anything"))
	if len(fp) != 64 {
		t.Errorf("fingerprint is %d chars, want 64 hex chars of SHA-256", len(fp))
	}
	if fp != strings.ToLower(fp) {
		t.Error("fingerprint is not lowercase; dispatch and ingest must compute the same string")
	}
	if strings.Contains(fp, ":") {
		t.Error("fingerprint contains colons; the form must match everywhere it is compared")
	}
	if ca.Fingerprint([]byte("a")) == ca.Fingerprint([]byte("b")) {
		t.Error("different inputs share a fingerprint")
	}
}

func writeFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
