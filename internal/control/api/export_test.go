package api

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

// HashPasswordForTest exposes the password hasher to the integration test, which
// lives in api_test and therefore cannot reach an unexported function.
//
// A test-only export rather than making hashPassword public: nothing outside
// this package should be producing verifiers, because the parameters and the
// encoding are this package's to change.
func HashPasswordForTest(t *testing.T, password string) string {
	t.Helper()
	phc, err := hashPassword(password)
	if err != nil {
		t.Fatalf("hashPassword: %v", err)
	}
	return phc
}

// PKCEChallengeForTest exposes the S256 derivation so a test can check that the
// verifier actually sent to the token endpoint hashes to the challenge that was
// advertised — the property PKCE consists of, and one that would still "pass" a
// test that only asserted a verifier was present.
func PKCEChallengeForTest(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
