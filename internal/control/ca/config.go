package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
)

// Config is where the trust anchor comes from: paths, not constants.
//
// ADR-018's whole point. A binary that knew its CA would need a second
// enrollment path for on-prem, in the most security-sensitive component, which
// is exactly where ADR-017's single-codebase commitment would fail first.
type Config struct {
	// CertPath is the issuing CA certificate, PEM. If it contains more than one
	// certificate, the rest are treated as the chain above it.
	CertPath string

	// KeyPath is the signing key, PEM (PKCS#8, SEC1 or PKCS#1).
	//
	// A path today because that is what Compose and a systemd unit can provide
	// in every deployment mode including air-gapped. The seam that matters is
	// crypto.Signer, not this field: an HSM- or KMS-backed Open would set the
	// same unexported field and no caller would change.
	KeyPath string

	// AllowSharedKeyFileMode relaxes the READ-bit half of the file-mode refusal
	// below, for a deployment that genuinely manages access another way — a
	// read-only secret mount owned by a different uid.
	//
	// It does NOT relax the write bits, and cannot. A world-readable signing key
	// is a disclosure; a world-WRITABLE one is an attacker substituting the CA
	// and issuing themselves fleet identities, which is the worse half and not
	// something a convenience flag gets to permit. The previous name and check
	// covered both, which is how a flag ends up wider than anyone reading its
	// name would expect.
	AllowSharedKeyFileMode bool
}

// Open loads and validates the CA.
//
// Every check here is a startup failure rather than a first-enrollment failure.
// A CA misconfiguration that surfaces at the first scan point enrollment
// surfaces inside a customer's network, hours later, as a gRPC error nobody can
// correlate to a config change.
func Open(cfg Config) (*CA, error) {
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, fmt.Errorf("%w: CertPath and KeyPath are required", ErrNotConfigured)
	}

	// The key file must not be readable beyond its owner. Cheap, and it catches
	// the most common real mistake: a key committed or copied with 0644.
	info, err := os.Stat(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("ca: stat signing key: %w", err)
	}
	mode := info.Mode().Perm()
	if mode&0o022 != 0 {
		return nil, fmt.Errorf(
			"ca: signing key %s is mode %04o and is writable by group or other. "+
				"Anyone who can write it can substitute the CA and issue themselves fleet "+
				"identities; there is no flag for this", cfg.KeyPath, mode)
	}
	if mode&0o044 != 0 && !cfg.AllowSharedKeyFileMode {
		return nil, fmt.Errorf(
			"ca: signing key %s is mode %04o and is readable by group or other. "+
				"Fix the mode, or set AllowSharedKeyFileMode if access is managed another way",
			cfg.KeyPath, mode)
	}

	certPEM, err := os.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, fmt.Errorf("ca: read CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		// Note what is NOT wrapped: only the path and the OS error. The file
		// contents never reach an error string.
		return nil, fmt.Errorf("ca: read signing key: %w", err)
	}

	chain, err := parseCertChain(certPEM)
	if err != nil {
		return nil, err
	}
	issuer, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return nil, fmt.Errorf("ca: parse CA certificate: %w", err)
	}

	if !issuer.BasicConstraintsValid || !issuer.IsCA {
		return nil, fmt.Errorf("%w: %s", ErrNotACertAuthority, issuer.Subject)
	}
	if issuer.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%w: %s lacks KeyUsageCertSign", ErrNotACertAuthority, issuer.Subject)
	}

	// An expired CA signs certificates nothing can validate. Refusing at startup
	// turns that into one clear message here instead of a handshake failure in
	// a customer network, weeks later, that nobody can correlate to a CA which
	// quietly aged out. SignScanPoint additionally clamps a leaf to the CA's own
	// NotAfter, for the case where the CA expires mid-lifetime.
	if now := time.Now(); now.After(issuer.NotAfter) {
		return nil, fmt.Errorf("%w: %s expired at %s",
			ErrCAExpired, issuer.Subject, issuer.NotAfter.Format(time.RFC3339))
	}

	signer, err := parseSigner(keyPEM)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(signer.Public(), issuer.PublicKey) {
		return nil, ErrKeyMismatch
	}

	return &CA{signer: signer, cert: issuer, chain: chain}, nil
}

// parseCertChain reads the configured chain and VERIFIES it links.
//
// Whatever comes back here is shipped verbatim as EnrollResponse.ca_chain, and
// the scan point builds its trust store from it — over a connection it cannot
// yet verify, because at first contact it has no anchor. So a stray CERTIFICATE
// block in this one file is a trusted root on every scan point in the fleet.
//
// Collecting blocks without checking them made that a one-line mistake: append
// an unrelated self-signed certificate to the CA PEM and it becomes a fleet-wide
// trust anchor. Each element must therefore be a CA certificate, and each must
// actually have signed the one below it.
func parseCertChain(pemBytes []byte) ([][]byte, error) {
	var chain [][]byte
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		chain = append(chain, block.Bytes)
	}
	if len(chain) == 0 {
		return nil, errors.New("ca: no CERTIFICATE block in the configured chain")
	}

	parsed := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("ca: chain element %d: %w", i, err)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, fmt.Errorf(
				"%w: element %d (%s) is not a CA certificate. Everything in this file is "+
					"shipped to every scan point as a trust anchor", ErrChainBroken, i, c.Subject)
		}
		parsed[i] = c
	}

	// Issuer-first ordering: element i must be signed by element i+1. A
	// self-signed root at the end signs itself and is not checked against
	// anything above it, which is correct — it is the anchor.
	for i := 0; i+1 < len(parsed); i++ {
		if err := parsed[i].CheckSignatureFrom(parsed[i+1]); err != nil {
			return nil, fmt.Errorf(
				"%w: element %d (%s) was not signed by element %d (%s): %w",
				ErrChainBroken, i, parsed[i].Subject, i+1, parsed[i+1].Subject, err)
		}
	}
	return chain, nil
}

// parseSigner accepts the three PEM key encodings Go emits and openssl produces.
//
// It returns crypto.Signer, never the concrete key type, so the caller cannot
// hold anything narrower than "something that can sign".
func parseSigner(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("ca: signing key is not PEM")
	}

	// Errors below are deliberately not wrapped: a parse error on key material
	// can echo fragments of it, and this error travels into startup logs.
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return nil, errors.New("ca: PKCS#8 key cannot sign")
		}
		return s, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	return nil, errors.New("ca: signing key is not PKCS#8, SEC1 or PKCS#1")
}

func publicKeysEqual(a, b any) bool {
	type equaler interface{ Equal(x crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	switch k := a.(type) {
	case *ecdsa.PublicKey:
		other, ok := b.(*ecdsa.PublicKey)
		return ok && k.Equal(other)
	case *rsa.PublicKey:
		other, ok := b.(*rsa.PublicKey)
		return ok && k.Equal(other)
	case ed25519.PublicKey:
		other, ok := b.(ed25519.PublicKey)
		return ok && k.Equal(other)
	}
	return false
}

func pkixName(scanPointID uuid.UUID) pkix.Name {
	// CN is the scan point id so a certificate found in isolation is traceable.
	// It is NOT how the identity is resolved — that is the fingerprint, through
	// the database, which is what makes revocation immediate (ADR-031).
	return pkix.Name{
		CommonName:   scanPointID.String(),
		Organization: []string{"CVAP Scan Point"},
	}
}
