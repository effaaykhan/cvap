package scanpoint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func ed25519CredentialPEM(t *testing.T) (*Credential, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(block)
	cred := NewCredential("g", "j", "ssh-key", []string{"h"}, time.Now().Add(time.Hour), raw)
	return cred, pub
}

// The evidence for the ADR-020 guarantee (this session's ADR): after Zeroise, the
// signer the keyring still references produces a signature that no longer verifies —
// proof that the signer signs with the SAME backing array Zeroise overwrote, so no
// live copy of the key survives the zeroise path.
func TestCredAgentZeroiseBreaksSigning(t *testing.T) {
	cred, pub := ed25519CredentialPEM(t)
	a, err := NewCredAgent(cred)
	if err != nil {
		t.Fatal(err)
	}
	signers, err := a.keyring.Signers()
	if err != nil {
		t.Fatal(err)
	}
	if len(signers) != 1 {
		t.Fatalf("want 1 signer, got %d", len(signers))
	}
	data := []byte("challenge")

	sig1, err := signers[0].Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("sign before zeroise: %v", err)
	}
	// Verify sig1 against the real public key using the ssh wire verify.
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := sshPub.Verify(data, sig1); err != nil {
		t.Fatalf("signature before zeroise should verify: %v", err)
	}

	a.Zeroise()

	// The same signer now signs with a zeroed key: the signature must NOT verify.
	sig2, err := signers[0].Sign(rand.Reader, data)
	if err != nil {
		return // an error is also acceptable — the key is gone
	}
	if err := sshPub.Verify(data, sig2); err == nil {
		t.Fatal("signature still verified after Zeroise — a live copy of the key survived")
	}
}

// A non-ed25519 key is refused: its material cannot be overwritten in place, so
// accepting it would be a silent partial-zeroise (ADR-020).
func TestCredAgentRefusesNonEd25519(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	cred := NewCredential("g", "j", "ssh-key", nil, time.Now().Add(time.Hour), pem.EncodeToMemory(block))
	if _, err := NewCredAgent(cred); err == nil {
		t.Fatal("an RSA key must be refused (cannot be zeroised in place)")
	}
}
