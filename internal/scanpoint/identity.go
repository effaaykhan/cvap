package scanpoint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// ============================================================================
// WHAT THIS COMPONENT WRITES TO DISK, IN FULL.
// ============================================================================
//
// ADR-020 says credential material is memory-only and never written to disk on a
// scan point. That rule has exactly one carve-out, and it is this file, so the
// complete list lives here rather than being inferable from the code:
//
//	<data>/            0700  directory
//	<data>/key.pem     0600  the scan point's own private key, PKCS#8
//	<data>/cert.pem    0644  its leaf certificate, public by definition
//	<data>/ca.pem      0644  the CA chain Core returned, public
//	<data>/identity    0644  scan point id, fingerprint, endpoints, not_after
//	<data>/key.pem.prev  0600  the previous key, kept across a rotation
//	<data>/cert.pem.prev 0644  and its certificate — see loadKeyPair
//
// NOTHING else. Not credential material from a CredentialGrant, not
// observations, not the enrollment token after it is spent. If a future change
// adds a file here, it belongs in this list with its reason.
//
// The private key is the one thing that MUST persist, and its persistence is
// what makes the rest of the model work: the key never leaves the scan point, so
// cert_fingerprint is a real per-device identity rather than a label, and that
// identity is what the audit log, CREDENTIAL_GRANT.delivered_to_fingerprint and
// immediate per-device revocation all rest on (ADR-018, ADR-020). A key Core
// generated would be a key Core had a copy of.
//
// Everything is written through os.Root so a symlink planted in the data
// directory cannot redirect a write outside it — the same reason
// internal/control/ca/devca.go does.

const (
	keyFile      = "key.pem"
	certFile     = "cert.pem"
	chainFile    = "ca.pem"
	identityFile = "identity"

	// prevSuffix marks the superseded key and certificate, kept across a
	// rotation so a crash between the two renames does not leave the scan point
	// with a key that matches no certificate. See loadKeyPair.
	prevSuffix = ".prev"

	dirMode     = 0o700
	keyMode     = 0o600
	publicMode  = 0o644
	identityDoc = "# CVAP scan point identity. Written by cvap-scanpoint; not secret.\n"
)

// Identity is what enrollment produced and the runtime needs on every start.
type Identity struct {
	ScanPointID     string
	Fingerprint     string
	NotAfter        time.Time
	DispatchAddr    string
	IngestAddr      string
	RulePacksAddr   string
	AcceptedVersion string
	MinVersion      string
}

// ErrNoIdentity means this scan point has not enrolled yet.
var ErrNoIdentity = errors.New("scanpoint: no identity on disk")

// LoadIdentity reads a previous enrollment, or reports ErrNoIdentity.
func LoadIdentity(dataDir string) (*Identity, error) {
	// Through os.Root, like every write here: a symlink planted in the data
	// directory cannot redirect the read outside it.
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoIdentity
		}
		return nil, fmt.Errorf("scanpoint: open data dir: %w", err)
	}
	defer func() { _ = root.Close() }()

	raw, err := readWithin(root, identityFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoIdentity
		}
		return nil, fmt.Errorf("scanpoint: read identity: %w", err)
	}
	// The key and certificate must exist too. An identity file without them is
	// a half-written enrollment, and continuing from it would produce a scan
	// point that believes it has an identity and cannot present one.
	for _, f := range []string{keyFile, certFile} {
		if _, err := root.Stat(f); err != nil {
			return nil, fmt.Errorf("scanpoint: identity is present but %s is not: %w", f, err)
		}
	}

	id := &Identity{}
	for _, line := range strings.Split(string(raw), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		switch k {
		case "scan_point_id":
			id.ScanPointID = v
		case "fingerprint":
			id.Fingerprint = v
		case "not_after_unix":
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				id.NotAfter = time.Unix(n, 0).UTC()
			}
		case "dispatch":
			id.DispatchAddr = v
		case "ingest":
			id.IngestAddr = v
		case "rulepacks":
			id.RulePacksAddr = v
		case "accepted_protocol_version":
			id.AcceptedVersion = v
		case "min_supported_version":
			id.MinVersion = v
		}
	}
	if id.ScanPointID == "" || id.DispatchAddr == "" || id.IngestAddr == "" {
		return nil, errors.New("scanpoint: identity file is incomplete")
	}
	return id, nil
}

// NewKey generates the scan point's key pair and returns a CSR for it.
//
// P-256 to match what internal/control/ca accepts. The key is returned rather
// than written, so the caller writes it only once Core has signed the request —
// a key on disk with no certificate is a file that looks like an identity and is
// not one.
func NewKey() (*ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("scanpoint: generate key: %w", err)
	}
	// An empty subject, deliberately. Core discards everything in the CSR but
	// the public key and names the certificate from the scan point id it
	// allocates — so a subject here would be a self-asserted label that looks
	// like an identity.
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("scanpoint: create csr: %w", err)
	}
	return key, csr, nil
}

// SaveIdentity writes the key, certificate, chain and identity file atomically
// enough that a crash cannot leave a usable-looking half.
//
// Order matters: the key first, then the public material, then the identity file
// LAST. LoadIdentity keys on the identity file, so a crash before that point
// leaves a directory that reports ErrNoIdentity and re-enrolls cleanly, rather
// than one that claims an identity it cannot use.
func SaveIdentity(dataDir string, key *ecdsa.PrivateKey, certDER []byte, chain [][]byte, id *Identity) error {
	if err := os.MkdirAll(dataDir, dirMode); err != nil {
		return fmt.Errorf("scanpoint: create data dir: %w", err)
	}
	// Re-assert the mode: MkdirAll applies umask, so a permissive umask leaves
	// the directory group- or world-readable. The private key's own mode is the
	// control, and this is defence in depth on the container around it.
	if err := os.Chmod(dataDir, dirMode); err != nil {
		return fmt.Errorf("scanpoint: chmod data dir: %w", err)
	}

	root, err := os.OpenRoot(dataDir)
	if err != nil {
		return fmt.Errorf("scanpoint: open data dir: %w", err)
	}
	defer func() { _ = root.Close() }()

	// Keep the outgoing pair before overwriting it. Best-effort: at first
	// enrolment there is nothing to keep.
	_ = copyWithin(root, keyFile, keyFile+prevSuffix, keyMode)
	_ = copyWithin(root, certFile, certFile+prevSuffix, publicMode)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("scanpoint: marshal key: %w", err)
	}
	if err := writeFile(root, keyFile, pem.EncodeToMemory(&pem.Block{
		Type: "PRIVATE KEY", Bytes: der,
	}), keyMode); err != nil {
		return err
	}

	if err := writeFile(root, certFile, pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: certDER,
	}), publicMode); err != nil {
		return err
	}

	var chainPEM []byte
	for _, c := range chain {
		chainPEM = append(chainPEM, pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: c,
		})...)
	}
	if err := writeFile(root, chainFile, chainPEM, publicMode); err != nil {
		return err
	}

	var b strings.Builder
	b.WriteString(identityDoc)
	fmt.Fprintf(&b, "scan_point_id=%s\n", id.ScanPointID)
	fmt.Fprintf(&b, "fingerprint=%s\n", id.Fingerprint)
	fmt.Fprintf(&b, "not_after_unix=%d\n", id.NotAfter.Unix())
	fmt.Fprintf(&b, "dispatch=%s\n", id.DispatchAddr)
	fmt.Fprintf(&b, "ingest=%s\n", id.IngestAddr)
	fmt.Fprintf(&b, "rulepacks=%s\n", id.RulePacksAddr)
	fmt.Fprintf(&b, "accepted_protocol_version=%s\n", id.AcceptedVersion)
	fmt.Fprintf(&b, "min_supported_version=%s\n", id.MinVersion)
	return writeFile(root, identityFile, []byte(b.String()), publicMode)
}

// writeFile replaces a file inside the data directory, through os.Root.
//
// Written to a temporary name and renamed, so a crash mid-write leaves the
// previous file rather than a truncated one — which for key.pem is the
// difference between a scan point that restarts and one that has lost its
// identity and cannot re-enrol without a new token.
// readWithin reads a bounded file from inside the data directory.
func readWithin(root *os.Root, name string) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, 1<<20))
}

// copyWithin duplicates a file inside the data directory.
func copyWithin(root *os.Root, from, to string, perm os.FileMode) error {
	f, err := root.Open(from)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return err
	}
	return writeFile(root, to, data, perm)
}

func writeFile(root *os.Root, name string, data []byte, perm os.FileMode) error {
	tmp := name + ".tmp"
	_ = root.Remove(tmp)

	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return fmt.Errorf("scanpoint: create %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return fmt.Errorf("scanpoint: write %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return fmt.Errorf("scanpoint: sync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("scanpoint: close %s: %w", tmp, err)
	}
	// Chmod after close, and the reason is the opposite of the obvious one.
	//
	// umask can only NARROW: OpenFile(perm 0600) under umask 000 already gives
	// 0600, so the private key is safe without this line. What the Chmod
	// actually does is re-WIDEN cert.pem, ca.pem and the identity file to 0644
	// under a restrictive umask, so an operator can read the public material.
	// Stated correctly because the next author generalises the story, not the
	// code.
	if err := root.Chmod(tmp, perm); err != nil {
		return fmt.Errorf("scanpoint: chmod %s: %w", tmp, err)
	}
	if err := root.Rename(tmp, name); err != nil {
		return fmt.Errorf("scanpoint: rename %s: %w", name, err)
	}
	// fsync the DIRECTORY, not just the file. A rename is metadata, and an
	// fsync of the file's contents does not make the directory entry durable —
	// so a power loss could leave the new contents with the old name.
	if d, err := root.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// ReadToken reads the enrollment token and removes it from memory as soon as the
// caller is done with it.
//
// The token is a bearer credential for a fleet identity: whoever holds it
// obtains one (ADR-018). It is read into a Credential — the ADR-038 holder — so
// that it cannot be rendered by any verb and can be erased once spent, rather
// than sitting in a string for the life of the process.
func ReadToken(path string) (*Credential, error) {
	// #nosec G304 -- the path is operator configuration (CVAP_SP_ENROLLMENT_TOKEN_FILE),
	// not input: it arrives from the process environment before any network
	// connection exists, and there is no root to scope it to because an
	// operator may keep the token anywhere. Bounded, because a token is 40-odd
	// bytes and anything larger is a misconfiguration rather than a token.
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("scanpoint: read enrollment token: %w", err)
	}
	trimmed := trimTrailingSpace(raw)
	return NewCredential("enrollment", "", "ENROLLMENT_TOKEN", nil, time.Time{}, trimmed), nil
}

// trimTrailingSpace removes a trailing newline in place.
//
// In place, and not with strings.TrimSpace, because a copy would be a second
// array holding the token that Zeroise cannot reach — the same reason
// NewCredential takes ownership rather than copying.
func trimTrailingSpace(b []byte) []byte {
	end := len(b)
	for end > 0 {
		switch b[end-1] {
		case '\n', '\r', ' ', '\t':
			b[end-1] = 0
			end--
		default:
			return b[:end]
		}
	}
	return b[:0]
}

// ShouldRotate reports whether the certificate is past its rotation point.
//
// From not_after rather than from the certificate: EnrollResponse carries
// not_after_unix precisely so this stays a comparison rather than an X.509
// dependency (enrollment.proto).
func ShouldRotate(notAfter time.Time, now time.Time) bool {
	if notAfter.IsZero() {
		return false
	}
	return now.After(notAfter.Add(-(CertLifetime - CertRotateAt)))
}
