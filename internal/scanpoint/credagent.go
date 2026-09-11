package scanpoint

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// CredAgent is the runtime side of the agent/signing-proxy placement (ADR-027/047,
// Phase-4 session scope). The runtime holds the SSH private key and answers signing
// challenges over a socket; the credentialed-host engine, a separate process, opens
// the network connection to the target and authenticates over that socket WITHOUT
// ever holding key material. ADR-047's net-to-target stays in the engine; ADR-027's
// "engines never hold the credential" stays true — the engine gets signatures, not
// the key.
//
// # The zeroise guarantee, ed25519, verified against x/crypto (this session's ADR)
//
// ADR-020 requires credential material be memory-only and zeroised, and ADR-038's
// func()[]byte pattern exists so a zeroise reaches every retained copy. An agent
// keyring risked a copy the zeroise path could not reach. It does not, for ed25519,
// and that was verified in the library rather than assumed:
//
//   - ssh.ParseRawPrivateKey yields a FRESH ed25519.PrivateKey ([]byte) — the one
//     slice we retain (keys.go allocates and copies into it).
//   - keyring.Add stores ssh.NewSignerFromKey(key), and for a crypto.Signer (which
//     ed25519.PrivateKey is) that is NewSignerFromSigner, which WRAPS the signer by
//     reference — no copy of the key bytes.
//   - The local keyring serving Sign requests never marshals the private key (only
//     the public key and the signature cross the wire).
//
// So one backing array holds the key, shared by the slice we keep and the signer the
// keyring uses, and Zeroise overwrites it — TestCredAgentZeroiseBreaksSigning proves
// signing fails afterward, which is the evidence that no live copy survives. For
// ed25519 this is a FULL ADR-020 guarantee. RSA and ECDSA private keys are structs
// of big.Int that cannot be overwritten in place, so they are the partial
// "unreachable-not-zeroised" case and are REFUSED here (NewCredAgent errors) rather
// than accepted with a silent gap. The lab key is ed25519.
type CredAgent struct {
	mu       sync.Mutex
	keyBytes ed25519.PrivateKey // the one retained copy; Zeroise overwrites this
	keyring  agent.Agent
	runtime  *net.UnixConn // runtime end, serving the agent
	zeroised bool
}

// NewCredAgent parses the ed25519 key from the runtime-held credential and prepares
// an in-memory agent. It does not read the key from disk and takes only the bytes the
// Credential reveals; the caller retains ownership of the Credential and zeroises it.
func NewCredAgent(cred *Credential) (*CredAgent, error) {
	raw := cred.Reveal()
	if len(raw) == 0 {
		return nil, errors.New("credagent: empty credential")
	}
	parsed, err := ssh.ParseRawPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("credagent: parse key: %w", err)
	}
	var key ed25519.PrivateKey
	switch k := parsed.(type) {
	case *ed25519.PrivateKey:
		key = *k
	case ed25519.PrivateKey:
		key = k
	default:
		// RSA/ECDSA keys are big.Int structs that cannot be overwritten in place, so
		// ADR-020's zeroise would be partial. Refuse rather than accept a silent gap.
		return nil, fmt.Errorf("credagent: only ed25519 keys are accepted (got %T); "+
			"other key types cannot be zeroised in place (ADR-020)", parsed)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: key}); err != nil {
		return nil, fmt.Errorf("credagent: add key: %w", err)
	}
	return &CredAgent{keyBytes: key, keyring: kr}, nil
}

// EngineFile returns a file to hand the engine as an extra FD (its agent socket). The
// runtime side is served in a goroutine until Zeroise/Close. One connection: this
// serves exactly one engine.
func (a *CredAgent) EngineFile() (*os.File, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.zeroised {
		return nil, errors.New("credagent: zeroised")
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, fmt.Errorf("credagent: socketpair: %w", err)
	}
	runtimeFile := os.NewFile(uintptr(fds[0]), "credagent-runtime")
	engineFile := os.NewFile(uintptr(fds[1]), "credagent-engine")
	rc, err := net.FileConn(runtimeFile)
	_ = runtimeFile.Close() // FileConn dups; close our copy of the runtime fd
	if err != nil {
		_ = engineFile.Close()
		return nil, fmt.Errorf("credagent: fileconn: %w", err)
	}
	a.runtime = rc.(*net.UnixConn)
	go func() { _ = agent.ServeAgent(a.keyring, a.runtime) }()
	return engineFile, nil
}

// Zeroise overwrites the key backing array and tears down the agent. Idempotent;
// safe on completion, lease loss and abort (ADR-020), and each of those may race.
func (a *CredAgent) Zeroise() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.runtime != nil {
		_ = a.runtime.Close() // stops ServeAgent
		a.runtime = nil
	}
	if a.keyBytes != nil {
		clear(a.keyBytes) // overwrites the array the keyring's signer shares
		a.keyBytes = nil
	}
	a.keyring = nil
	a.zeroised = true
}
