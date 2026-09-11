package credhost

import (
	"net"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Two throwaway ed25519 public keys and their SHA256 fingerprints. Fixed strings,
// not generated, so the test needs no crypto import beyond ssh (the engine's own
// allowlist stays clean — see internal/enginepolicy).
const (
	keyA = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDDUmMQDAdEk6rgAH3kUPUOd/R8OWzmryZHI+kQWr8MG test-a"
	fpA  = "SHA256:EILUHN7jjJEOR+Csiwu2oipW3T5oL19wm6mFAlgCR8E"
	keyB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBjx8vfRme9HSuAOm1/KN4LFQIKzNY9OBoETspqHOxwx test-b"
)

func pub(t *testing.T, authorized string) ssh.PublicKey {
	t.Helper()
	p, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorized))
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	return p
}

func TestHostKeyCallbackAcceptsMatchingFingerprint(t *testing.T) {
	// The fleet default: Core supplies the SHA256 fingerprint CVAP captured.
	cb, err := hostKeyCallback(fpA)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("host:22", &net.TCPAddr{}, pub(t, keyA)); err != nil {
		t.Errorf("matching fingerprint rejected: %v", err)
	}
	if err := cb("host:22", &net.TCPAddr{}, pub(t, keyB)); err == nil {
		t.Error("a different host key was accepted against fingerprint A")
	}
}

func TestHostKeyCallbackAcceptsFullKnownHostsLine(t *testing.T) {
	// The operator-override path: a full "host keytype base64" line.
	cb, err := hostKeyCallback("192.168.0.5 " + keyA)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("host:22", &net.TCPAddr{}, pub(t, keyA)); err != nil {
		t.Errorf("matching full key rejected: %v", err)
	}
	if err := cb("host:22", &net.TCPAddr{}, pub(t, keyB)); err == nil {
		t.Error("a different host key was accepted against a pinned full key")
	}
}

func TestHostKeyCallbackRefusesWhenNoTrustMaterial(t *testing.T) {
	// No key and no fingerprint: refuse to connect rather than TOFU.
	if _, err := hostKeyCallback("\n# only a comment\n"); err == nil {
		t.Error("expected a refusal when no host keys or fingerprints are supplied")
	}
}

func TestHostKeyCallbackFingerprintOnHostLine(t *testing.T) {
	// A fingerprint may ride a known-hosts-style line ("host SHA256:...").
	cb, err := hostKeyCallback("10.0.0.9 " + fpA)
	if err != nil {
		t.Fatal(err)
	}
	if err := cb("host:22", &net.TCPAddr{}, pub(t, keyA)); err != nil {
		t.Errorf("fingerprint on a host line rejected: %v", err)
	}
}
