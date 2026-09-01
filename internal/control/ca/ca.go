// Package ca is Core's certificate authority for scan point identities.
//
// ADR-018 makes the trust anchor configuration rather than an assumption baked
// into the binary, so enrollment is byte-identical in SaaS and on-prem. This
// package is where that lands: the chain and the signing key come from
// configuration, and nothing here knows which deployment mode it is in.
//
// # Custody is a seam, not a file path
//
// The signing key is held as a crypto.Signer in an unexported field. That
// interface exposes Public() and Sign() and nothing else, so this type
// STRUCTURALLY cannot hand back the private key — the same reasoning ADR-032
// applies to database connections, applied to key material. A file-backed key
// satisfies it today; PKCS#11, a cloud KMS or an HSM satisfy it later without a
// caller changing. That is what makes ADR-018's "trust anchor is configuration"
// extend to custody rather than stopping at which root is trusted.
//
// # Nothing here renders a key
//
// CA implements slog.LogValuer so the obvious slog.Any("ca", ca) is safe rather
// than catastrophic, and no method, field or error string exposes key material.
package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"time"

	"github.com/google/uuid"
)

// Certificate lifetime and the rotation point, per execution-plan §5.
//
// The scan point rotates at RotateAfter by comparing not_after against its own
// clock; EnrollResponse carries not_after precisely so that decision does not
// require parsing X.509 on the scan point.
const (
	Lifetime    = 90 * 24 * time.Hour
	RotateAfter = 60 * 24 * time.Hour

	// backdate absorbs clock skew between Core and a scan point. Small: a large
	// backdate widens the window in which a stolen-and-replayed CSR yields a
	// certificate that already looks established.
	backdate = 5 * time.Minute

	// maxCSRBytes bounds parsing work before any parsing happens. A CSR for a
	// P-256 key is ~250 bytes; RSA-4096 is ~1.7KB.
	maxCSRBytes = 16 * 1024
)

var (
	ErrCSRTooLarge       = errors.New("ca: CSR exceeds the size limit")
	ErrCSRMalformed      = errors.New("ca: CSR is not valid PKCS#10 DER")
	ErrCSRSignature      = errors.New("ca: CSR signature does not verify")
	ErrCSRWeakKey        = errors.New("ca: CSR public key is too weak or of an unsupported type")
	ErrNotConfigured     = errors.New("ca: not configured")
	ErrKeyMismatch       = errors.New("ca: signing key does not match the CA certificate")
	ErrNotACertAuthority = errors.New("ca: configured certificate is not a CA certificate")
	ErrCAExpired         = errors.New("ca: the CA certificate has expired")
	ErrChainBroken       = errors.New("ca: the configured chain does not verify")
)

// CA issues scan point client certificates.
type CA struct {
	// signer is the private half. crypto.Signer rather than *ecdsa.PrivateKey
	// deliberately: the interface cannot yield the key, so no method on this
	// type can be written that returns it, accidentally or otherwise.
	signer crypto.Signer

	cert  *x509.Certificate // the issuing certificate
	chain [][]byte          // DER, issuer-first, as configured
}

// Chain is what Core states to the scan point, verbatim from configuration.
//
// EnrollResponse.ca_chain exists so the binary does not assume a chain: the same
// code enrolls against our SaaS CA and against a customer's on-prem Core.
func (c *CA) Chain() [][]byte {
	out := make([][]byte, len(c.chain))
	copy(out, c.chain)
	return out
}

// Subject is the issuing certificate's subject, for logs and diagnostics.
func (c *CA) Subject() string { return c.cert.Subject.String() }

// NotAfter is when the CA certificate itself expires. Worth surfacing: a CA that
// expires before the certificates it issues produces a fleet-wide outage whose
// cause is not obvious from any scan point's perspective.
func (c *CA) NotAfter() time.Time { return c.cert.NotAfter }

// LogValue renders the CA usefully without going anywhere near the key.
//
// Be precise about what this does and does not do, because the obvious
// justification is wrong. Without it, fmt and slog would NOT print the private
// scalar: the signer is held behind an interface, so reflection renders it as a
// pointer address at depth > 0. The key is unreachable because of how it is
// HELD — a crypto.Signer in an unexported field, with no accessor — not because
// of this method.
//
// What this method buys is that slog.Any("ca", ca) produces something an
// operator can use (subject, serial, expiry) instead of an address, and that a
// future change to hold the key by value does not silently start rendering it.
// Hygiene and a guard, not the control.
//
// Contrast PlaintextToken, where the equivalent reasoning IS load-bearing:
// its value sits at depth 1 in a struct, so reflection prints it directly.
func (c *CA) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("subject", c.cert.Subject.String()),
		slog.String("serial", c.cert.SerialNumber.Text(16)),
		slog.Time("not_after", c.cert.NotAfter),
		slog.String("ski", hex.EncodeToString(c.cert.SubjectKeyId)),
		slog.Int("chain_len", len(c.chain)),
	)
}

// String is the fmt counterpart of LogValue, so %v and %s are safe too.
func (c *CA) String() string {
	return fmt.Sprintf("ca{subject=%s not_after=%s}",
		c.cert.Subject.String(), c.cert.NotAfter.Format(time.RFC3339))
}

// Fingerprint is SHA-256 over the certificate DER, lowercase hex.
//
// THE ONLY DEFINITION IN THE CODEBASE, deliberately. This value is the scan
// point's identity in scan_points.cert_fingerprint, in the audit log, and in
// CREDENTIAL_GRANT.delivered_to_fingerprint (ADR-020). Enrollment computes it
// here; the dispatch and ingest services must compute it here too, on
// tls.ConnectionState.PeerCertificates[0].Raw. Two definitions that disagree —
// over Raw versus RawTBSCertificate, or hex versus colon-separated — means every
// scan point fails to authenticate for a reason nothing reports.
func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// ParseCSR validates a PKCS#10 request and returns it.
//
// Everything except the public key is discarded by the caller. A CSR arrives
// from a scan point in a network whose compromise the threat model assumes
// (ADR-020), so its subject, SANs, extensions and requested key usage are
// attacker-chosen: honouring the subject would let a scan point name its own
// identity, and honouring requested extensions would let it ask for serverAuth
// or a CA bit.
func ParseCSR(der []byte) (*x509.CertificateRequest, error) {
	if len(der) == 0 {
		return nil, ErrCSRMalformed
	}
	if len(der) > maxCSRBytes {
		return nil, ErrCSRTooLarge
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		// The parse error is deliberately not wrapped into the returned error:
		// it is attacker-influenced text that would travel into a gRPC status.
		return nil, ErrCSRMalformed
	}

	// KEY CHECK BEFORE SIGNATURE CHECK, and the order is the point.
	//
	// CheckSignature on an RSA CSR costs a modular exponentiation whose size the
	// SUBMITTER chooses. Measured on a development machine: 30µs at 2048 bits,
	// 2.7ms at 16384, and 38ms at 65000 — a 1,265x amplification available to
	// anyone who can reach the listener, with no token and no certificate. The
	// 16KB size cap above does not help, because a 65000-bit modulus fits in it.
	//
	// Checking the key first turns that into a bounds comparison. Verifying a
	// signature over a key we have already refused buys nothing.
	if err := checkPublicKey(csr.PublicKey); err != nil {
		return nil, err
	}

	// Proof of possession. Without this, anyone could submit a CSR carrying
	// someone else's public key and be issued a certificate for a key they do
	// not hold — which would let them bind another party's key to an identity
	// of their choosing.
	if err := csr.CheckSignature(); err != nil {
		return nil, ErrCSRSignature
	}
	return csr, nil
}

// checkPublicKey refuses key types and sizes that would weaken the identity the
// whole protocol rests on.
func checkPublicKey(pub any) error {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256(), elliptic.P384(), elliptic.P521():
			return nil
		default:
			// P-224 and anything non-NIST.
			return ErrCSRWeakKey
		}
	case *rsa.PublicKey:
		// Bounded at BOTH ends. The lower bound is the obvious one. The upper
		// bound is what stops a submitter choosing our CPU cost: verification
		// is cubic-ish in modulus size, and nothing legitimate needs more than
		// 4096. Without it, a 65000-bit key costs 38ms of signature check per
		// request, before any authentication has happened.
		if bits := k.N.BitLen(); bits < 2048 || bits > 4096 {
			return ErrCSRWeakKey
		}
		return nil
	default:
		// Ed25519 is deliberately absent: Go's TLS supports it, but scan points
		// run months-old builds against middleboxes we do not control, and a
		// handshake failure inside a customer network is the thing ADR-022
		// exists to prevent. Revisit when the fleet is known to be uniform.
		return ErrCSRWeakKey
	}
}

// SignScanPoint issues a client certificate for a scan point.
//
// The template is built here, from the scan point id and nothing the CSR asked
// for. Only the public key crosses over.
func (c *CA) SignScanPoint(csr *x509.CertificateRequest, scanPointID uuid.UUID, now time.Time) (der []byte, serial string, notBefore, notAfter time.Time, err error) {
	if c == nil || c.signer == nil {
		return nil, "", time.Time{}, time.Time{}, ErrNotConfigured
	}

	sn, err := randomSerial()
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, err
	}

	notBefore = now.Add(-backdate)
	notAfter = now.Add(Lifetime)

	// A leaf must never outlive its issuer. A certificate valid past the CA's
	// own expiry cannot be validated by anything, and the failure surfaces
	// inside a customer network as a handshake error nobody can correlate to a
	// CA that quietly aged out. Open refuses an already-expired CA; this clamps
	// the case where the CA expires during a leaf's 90 days.
	if notAfter.After(c.cert.NotAfter) {
		notAfter = c.cert.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf(
			"%w: the CA certificate expires at %s, so no usable leaf can be issued",
			ErrCAExpired, c.cert.NotAfter.Format(time.RFC3339))
	}

	tmpl := &x509.Certificate{
		SerialNumber: sn,
		Subject:      pkixName(scanPointID),
		NotBefore:    notBefore,
		NotAfter:     notAfter,

		// DigitalSignature is what a TLS client certificate needs. Nothing else
		// is granted: no KeyEncipherment, no CertSign.
		KeyUsage: x509.KeyUsageDigitalSignature,

		// ClientAuth ONLY. A scan point never serves — ADR-005 makes the
		// transport outbound-only, and Core never opens an inbound connection
		// to a customer network for any reason. Withholding ServerAuth turns
		// that posture into a property of the certificate rather than a
		// convention someone can drift away from.
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},

		BasicConstraintsValid: true,
		IsCA:                  false,

		// No DNS or IP SANs. A SAN on a client certificate invites someone to
		// present it as a server certificate, which is exactly the use ADR-005
		// forbids. The identity is the fingerprint, resolved through the
		// database (ADR-031), not a name in the certificate.
	}

	der, err = x509.CreateCertificate(rand.Reader, tmpl, c.cert, csr.PublicKey, c.signer)
	if err != nil {
		return nil, "", time.Time{}, time.Time{}, fmt.Errorf("ca: sign: %w", err)
	}
	return der, sn.Text(16), notBefore, notAfter, nil
}

// randomSerial returns 128 unpredictable bits.
//
// Unpredictable rather than merely unique: a guessable serial is a component of
// several certificate-substitution attacks, and the CA/Browser Forum baseline
// requires at least 64 bits of entropy for the same reason.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("ca: serial: %w", err)
	}
	// Zero is a valid big.Int and an invalid serial.
	if sn.Sign() == 0 {
		sn = big.NewInt(1)
	}
	return sn, nil
}
