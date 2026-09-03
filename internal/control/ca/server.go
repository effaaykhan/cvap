package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"time"
)

// SignServer issues Core's own TLS server certificate.
//
// Core serves; scan points do not. That asymmetry is ADR-005's outbound-only
// posture, and it is why this is a separate function rather than a flag on
// SignScanPoint: a scan point certificate carries ExtKeyUsageClientAuth ONLY and
// no SANs, precisely so it cannot be presented as a server certificate. Sharing
// one code path would put a `serverAuth` branch inside the function whose job is
// to withhold it.
//
// The private key is generated here and returned to the caller, which is the
// opposite of the enrollment flow and correct for the opposite reason: this is
// Core's own key on Core's own host, not a remote device's identity that must
// never leave it.
func (c *CA) SignServer(hosts []string, now time.Time) (certPEM, keyPEM []byte, err error) {
	if c == nil || c.signer == nil {
		return nil, nil, ErrNotConfigured
	}
	if len(hosts) == 0 {
		return nil, nil, fmt.Errorf("ca: a server certificate needs at least one host")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: generate server key: %w", err)
	}

	sn, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}

	notBefore := now.Add(-backdate)
	notAfter := now.Add(Lifetime)
	if notAfter.After(c.cert.NotAfter) {
		// A leaf must never outlive its issuer, for the reason SignScanPoint
		// gives: a certificate valid past the CA's own expiry cannot be
		// validated by anything.
		notAfter = c.cert.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, nil, fmt.Errorf("%w: the CA expires at %s",
			ErrCAExpired, c.cert.NotAfter.Format(time.RFC3339))
	}

	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkix.Name{CommonName: hosts[0]},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,

		// ServerAuth only, mirroring the withholding on the other side. Core
		// never presents this as a client certificate to anything.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			continue
		}
		tmpl.DNSNames = append(tmpl.DNSNames, h)
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, key.Public(), c.signer)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: sign server: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(crypto.PrivateKey(key))
	if err != nil {
		return nil, nil, fmt.Errorf("ca: marshal server key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}
