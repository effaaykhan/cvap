package api_test

import (
	cryptoHash "crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A real identity provider, small enough to reason about.
//
// It serves discovery, a JWKS, and a token endpoint, and signs ID tokens with a
// key generated per test. Everything the callback verifies — signature, issuer,
// audience, expiry, nonce, subject — is a value this fake can be told to get
// wrong, which is the only way to find out whether the verification is real.

type fakeIDP struct {
	t      *testing.T
	server *httptest.Server
	key    *rsa.PrivateKey
	kid    string

	// What the next token endpoint call returns. Set per test.
	issuer   string
	audience string
	subject  string
	email    string
	verified bool
	nonce    string
	expiry   time.Time

	// Faults a test can inject.
	signWithWrongKey bool
	omitIDToken      bool
	tokenStatus      int

	// plainJWKS serves jwks_uri over http rather than https, which is the one
	// discovery endpoint the first version of the scheme check omitted.
	plainJWKS *httptest.Server

	// extraClaims are merged into the ID token, so a test can assert on a claim
	// the standard struct does not name — a mapped address claim, or azp.
	extraClaims map[string]any

	// audiences, when set, replaces the single audience with a multi-valued one.
	audiences []string

	// What the token endpoint actually received, so a test can assert PKCE and
	// the redirect_uri travelled.
	lastForm map[string]string
}

// roots is the trust the server must be given to reach this fake, standing in
// for an on-prem deployment's private CA bundle.
func (f *fakeIDP) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(f.server.Certificate())
	return pool
}

func newFakeIDP(t *testing.T) *fakeIDP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIDP{
		t: t, key: key, kid: "test-key-1",
		subject: "sub-" + randomHex(t, 8), verified: true,
		expiry: time.Now().Add(5 * time.Minute),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		jwks := idp.issuer + "/jwks"
		if idp.plainJWKS != nil {
			jwks = idp.plainJWKS.URL + "/jwks"
		}
		writeJSONTest(w, map[string]any{
			"issuer":                                idp.issuer,
			"authorization_endpoint":                idp.issuer + "/authorize",
			"token_endpoint":                        idp.issuer + "/token",
			"jwks_uri":                              jwks,
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		pub := idp.key.Public().(*rsa.PublicKey)
		writeJSONTest(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": idp.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		idp.lastForm = map[string]string{}
		for k := range r.Form {
			idp.lastForm[k] = r.Form.Get(k)
		}
		if idp.tokenStatus != 0 && idp.tokenStatus != http.StatusOK {
			w.WriteHeader(idp.tokenStatus)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		if idp.omitIDToken {
			writeJSONTest(w, map[string]any{"access_token": "a", "token_type": "Bearer"})
			return
		}
		writeJSONTest(w, map[string]any{
			"access_token": "a", "token_type": "Bearer", "id_token": idp.mintIDToken(),
		})
	})

	// TLS, because tenant_auth_config requires an https issuer — and that
	// constraint is right: the token exchange carries the authorization code.
	idp.server = httptest.NewTLSServer(mux)
	idp.issuer = idp.server.URL
	idp.audience = "test-client"
	t.Cleanup(idp.server.Close)
	return idp
}

// mintIDToken signs a token with whatever this fake is currently configured to
// assert. Written out rather than pulled from a library so a test can make each
// field wrong individually.
func (f *fakeIDP) mintIDToken() string {
	f.t.Helper()

	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": f.kid}
	claims := map[string]any{
		"iss": f.issuer,
		"aud": f.audience,
		"sub": f.subject,
		"exp": f.expiry.Unix(),
		"iat": time.Now().Add(-time.Minute).Unix(),
	}
	if f.audiences != nil {
		claims["aud"] = f.audiences
	}
	if f.nonce != "" {
		claims["nonce"] = f.nonce
	}
	if f.email != "" {
		claims["email"] = f.email
		claims["email_verified"] = f.verified
	}
	for k, v := range f.extraClaims {
		claims[k] = v
	}

	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	signing := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)

	key := f.key
	if f.signWithWrongKey {
		other, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			f.t.Fatal(err)
		}
		key = other
	}
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, cryptoHash.SHA256, sum[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func writeJSONTest(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func randomHex(t *testing.T, n int) string {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// servePlainJWKS points the discovery document's jwks_uri at a cleartext
// server. The signing keys are the root of every signature check, so fetching
// them over http lets an on-path attacker substitute the key set.
func (f *fakeIDP) servePlainJWKS() {
	f.t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		writeJSONTest(w, map[string]any{"keys": []any{}})
	})
	f.plainJWKS = httptest.NewServer(mux)
	f.t.Cleanup(f.plainJWKS.Close)
}
