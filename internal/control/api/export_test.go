package api

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/effaaykhan/cvap/internal/control/credential"
)

// HashPasswordForTest wraps credential.Hash so the integration test seeds a
// verifier the same way production does, with a t.Fatalf on error.
func HashPasswordForTest(t *testing.T, password string) string {
	t.Helper()
	phc, err := credential.Hash(password)
	if err != nil {
		t.Fatalf("credential.Hash: %v", err)
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

// OIDCBindingCookieNameForTest exposes the binding cookie's name so a test can
// find it among the Set-Cookie headers. The name differs between secure and
// insecure deployments because __Host- requires Secure.
func OIDCBindingCookieNameForTest(insecure bool) string {
	if insecure {
		return oidcBindingCookieInsecure
	}
	return oidcBindingCookieSecure
}
