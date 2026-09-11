# ADR-086: Credentialed SSH authenticates through a runtime signing agent; the ed25519 zeroise guarantee is full and verified

**Status:** Accepted
**Date:** 2026-09-11

The Phase 4 credentialed-host engine (Session 40) authenticates to a target over SSH while honouring
two frozen decisions that pull apart: ADR-027 (an engine never holds credential material; the runtime
holds it) and ADR-047 (net-to-target belongs to an engine, not the runtime). The approved resolution
(session-39 scope) is an **agent / signing proxy**, and this ADR records it and the one guarantee it
had to make good rather than merely note.

## The placement

- The **engine** opens the network connection to the target (net-to-target stays in the engine —
  ADR-047 unchanged) and authenticates over a UNIX socket handed to it as an extra file descriptor.
- The **runtime** holds the private key in an in-memory agent and answers signing challenges on that
  socket. The engine receives **signatures, never the key** (ADR-027 unchanged) — the signature is
  exactly the "derived proof, not the credential" ADR-027's escape hatch describes, which SSH
  otherwise lacks.
- Key-based auth only. Password auth has no signing-proxy equivalent and is deferred.

`internal/scanpoint.CredAgent` is the runtime side: it parses the key from the runtime-held
`Credential` (ADR-020/038), serves an `x/crypto/ssh/agent` keyring over a socketpair, and hands the
engine the other end.

## The zeroise guarantee — the first time ADR-020 needed this analysis

ADR-020 requires credential material be memory-only and zeroised; ADR-038's `func()[]byte` pattern
exists so a zeroise reaches every retained copy. An agent keyring risked holding a copy the zeroise
path could not reach. **It does not, for ed25519, and this was verified in x/crypto v0.55.0 rather
than assumed:**

- `ssh.ParseRawPrivateKey` allocates a fresh `ed25519.PrivateKey` `[]byte` and copies the parsed key
  into it (`keys.go`) — that slice is the one copy `CredAgent` retains.
- `keyring.Add` stores `ssh.NewSignerFromKey(key)`; for a `crypto.Signer` (which `ed25519.PrivateKey`
  is) that is `NewSignerFromSigner`, which **wraps the signer by reference** — no copy of the bytes.
- The local keyring, serving `Sign` requests, **never marshals the private key** — only the public
  key and the signature cross the socket.

So one backing array holds the key, shared by the slice `CredAgent` keeps and the signer the keyring
uses, and `Zeroise` overwrites it. `TestCredAgentZeroiseBreaksSigning` is the evidence: after
`Zeroise`, the signer the keyring still references produces a signature that no longer verifies —
which can only happen if it signs with the same array the zeroise overwrote. **For ed25519 the
ADR-020 guarantee is full: no live copy survives.**

## Non-ed25519 is refused, not silently partial

An RSA or ECDSA private key is a struct of `big.Int` values that cannot be overwritten in place (and
`big.Int` may reallocate), so its zeroise would be the partial "unreachable-not-overwritten" case —
exactly what ADR-020 forbids. `NewCredAgent` **refuses** a non-ed25519 key rather than accept it with
a hidden gap (`TestCredAgentRefusesNonEd25519`). The lab and fleet credentialed key is ed25519. If a
non-ed25519 key is ever required, closing its zeroise gap (a custom `big.Int`-scrubbing signer, or a
documented accepted partial) is a decision to take openly then, not a default reached silently now.

## Consequence

- This is the first credential in the system whose in-memory lifetime spans a *third* process's use
  (the engine's, via the socket) — and the guarantee holds because the third process never receives
  the key, only signatures. The agent socket closes and the key is zeroised on job completion, lease
  loss and abort (`CredAgent.Zeroise`, the ADR-020 triggers).
- The transient copies ADR-038 already acknowledges (the PEM decode buffers inside
  `ParseRawPrivateKey`) remain GC garbage, not retained — unchanged from ADR-038's standing caveat.
