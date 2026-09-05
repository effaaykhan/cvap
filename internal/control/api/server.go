package api

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/effaaykhan/cvap/internal/store"
)

// Config is what the operator API needs from the deployment.
type Config struct {
	// Version appears in the OpenAPI document.
	Version string

	// LocalAuthEnabled turns on password authentication, DEPLOYMENT-WIDE.
	//
	// ============================================================================
	// Core-wide, never per tenant. That is the control, not an implementation
	// convenience.
	// ============================================================================
	//
	// A per-tenant switch would let the administrator of a tenant enable password
	// login for their own users and thereby opt their tenant out of the
	// deployment operator's SSO policy — using a permission that was granted to
	// them for administering their own tenant. tenant_auth_config.method can say
	// 'local' all it likes; without this flag, and without the tenant being
	// on-prem, login refuses.
	LocalAuthEnabled bool

	// Insecure drops the Secure attribute from cookies, for local development
	// over plain HTTP.
	//
	// ============================================================================
	// Honoured only when ListenAddr is loopback. New refuses it otherwise.
	// ============================================================================
	//
	// The comment here used to say "refused unless the deployment is explicitly a
	// dev one" and nothing refused anything — a security review found the
	// sentence describing a guard that did not exist, which is the exact class of
	// defect this codebase polices everywhere else. So the guard is real now, and
	// the rule is one that can actually be checked: a session cookie without
	// Secure is a bearer credential a browser will send over cleartext, and an
	// address reachable from another machine is where that matters.
	Insecure bool

	// ListenAddr is the address the API is served on, used only to decide
	// whether Insecure may be honoured. Empty means "not loopback".
	ListenAddr string

	// AllowPrivateIssuers lets an OIDC issuer resolve to a private or loopback
	// address.
	//
	// For an on-prem deployment whose identity provider is on the internal
	// network, which is the normal shape of on-prem rather than an exception.
	// Off by default because on a SaaS deployment the issuer is customer-supplied
	// configuration, and Core fetching it is a server-side request forgery
	// primitive handed to a customer.
	//
	// Link-local stays refused either way: that is where cloud instance metadata
	// lives and no identity provider belongs there.
	AllowPrivateIssuers bool

	// OIDCRootCAs replaces the system trust store for identity-provider traffic.
	//
	// For an on-prem deployment whose internal provider is issued by a private
	// CA. Nil means the system roots. There is deliberately no setting that
	// disables verification: the authorization code travels in the token
	// exchange, and a deployment that cannot supply its CA is one where that
	// exchange is unprotected.
	OIDCRootCAs *x509.CertPool

	// SessionTTL is capped by a CHECK constraint on sessions at 12 hours. Set
	// lower here; it cannot be set higher, and the database is what says so.
	SessionTTL time.Duration

	// ExportRowCap bounds a CSV export; 0 means store.ExportRowCap. An export
	// matching more than the cap is refused rather than truncated, so an
	// incomplete file never masquerades as complete. Configurable so a
	// deployment can lower it and a test can prove the refusal without seeding
	// the default cap's worth of rows.
	ExportRowCap int
}

// Server is the operator API.
type Server struct {
	db  *store.DB
	log *slog.Logger
	cfg Config
	reg *Registry
	mux *http.ServeMux

	// hashSem bounds concurrent argon2id verifications.
	//
	// Each one asks for 64 MiB. Without a bound, the memory cost of an
	// UNAUTHENTICATED endpoint is a function of how many requests arrive, which
	// is a denial of service anyone can reach. See verifyUnderLimit.
	hashSem chan struct{}

	// oidcClient is the hardened outbound client, and the ONLY one this package
	// uses for identity-provider traffic. See oidc_client.go: the issuer is
	// operator-supplied, so every fetch from it is a server-side request
	// forgery surface.
	oidcClient *http.Client

	// providers caches discovery documents by issuer. It holds nothing
	// tenant-specific — the client id and the audience check come from each
	// tenant's own row every time a verifier is built.
	providers *providerCache

	// decoyHash is verified when there is no user, so that an unknown address
	// costs the same as a known one.
	//
	// Generated at startup rather than being a constant, because a constant
	// would be a known-plaintext verifier sitting in the binary — harmless in
	// itself, and exactly the kind of thing that gets copied into a fixture and
	// then into a real row.
	decoyHash string
}

// maxConcurrentHashes bounds password verification, derived from the machine.
//
// ============================================================================
// The bound is about CPU, not memory, and the first version got that wrong.
// ============================================================================
//
// A fixed eight looked reasonable on the memory argument — 8 × 64 MiB is half a
// gigabyte of transient allocation. Then the regression test still showed an
// unrelated authenticated read taking 780ms under load on a four-core box, and
// the reason was arithmetic nobody had done: argon2 is memory-HARD, so each
// verification saturates a core for its whole duration, and eight of them
// oversubscribed the machine by a factor of two before the rest of the server
// got any time at all.
//
// GOMAXPROCS-1, minimum one, so at least one processor is always available for
// everything that is not a login. Read once at startup: a GOMAXPROCS that
// changes under a running server is not a case worth tracking, and a bound that
// moved would make the property this enforces untestable.
var maxConcurrentHashes = max(1, runtime.GOMAXPROCS(0)-1)

// MaxBodyBytes bounds a request body.
//
// 1 MiB. Every body this API accepts is a small JSON object; the largest is a
// scan creation carrying a target list, and a target list that does not fit in a
// megabyte is one that should have been a prefix. The bound exists so that a
// handler cannot be made to buffer an arbitrary amount of memory by a client
// that simply keeps sending.
const MaxBodyBytes = 1 << 20

// New builds the server and registers every route.
func New(db *store.DB, log *slog.Logger, cfg Config) (*Server, error) {
	if db == nil {
		return nil, errors.New("api: nil store")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	if cfg.Insecure && !isLoopback(cfg.ListenAddr) {
		return nil, fmt.Errorf(
			"api: insecure cookies were requested but the API listens on %q, which is not "+
				"loopback. A session cookie without Secure is a bearer credential a browser "+
				"will send over cleartext; this is a development-only setting",
			cfg.ListenAddr)
	}
	if cfg.SessionTTL > 12*time.Hour {
		// Refused rather than clamped. A deployment that asked for a 24-hour
		// session and silently got 12 would believe something about its own
		// configuration that is not true, and the database would refuse the
		// INSERT anyway — at which point login fails for a reason nobody can see
		// from the config file.
		return nil, fmt.Errorf("api: session_ttl %s exceeds the 12h cap enforced by the sessions CHECK constraint", cfg.SessionTTL)
	}

	decoy, err := hashPassword(uuid.NewString())
	if err != nil {
		return nil, fmt.Errorf("api: decoy verifier: %w", err)
	}

	s := &Server{
		db: db, log: log, cfg: cfg,
		reg: NewRegistry(), mux: http.NewServeMux(),
		hashSem:    make(chan struct{}, maxConcurrentHashes),
		decoyHash:  decoy,
		oidcClient: newOIDCClient(cfg.AllowPrivateIssuers, cfg.OIDCRootCAs),
		providers:  newProviderCache(),
	}
	s.routes()
	s.mount()
	return s, nil
}

// Handler is the API's http.Handler, with the outermost middleware applied.
func (s *Server) Handler() http.Handler { return s.withRequestID(s.mux) }

// Registry exposes the routes, for the OpenAPI generator and for tests that
// assert properties of the whole surface.
func (s *Server) Registry() *Registry { return s.reg }

// mount wires each route through the chain.
//
// The chain is built PER ROUTE from the route's own declaration, rather than
// applied globally with per-handler checks inside. That is what makes the
// deny-by-default guarantee mechanical: there is no way to reach a handler
// except through the middleware built from that handler's Access, because the
// handler is only ever referenced here.
func (s *Server) mount() {
	for _, r := range s.reg.Routes() {
		var h http.Handler = r.Handler
		h = s.authorize(r, h)
		h = s.authenticate(r, h)
		h = s.resolveTenant(h)
		h = limitBody(h)
		s.mux.Handle(r.Method+" "+r.Path, h)
	}
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// decode reads a JSON body, refusing unknown fields.
//
// DisallowUnknownFields, deliberately. A client that sends tenant_id, or
// safety_mode to an endpoint that does not accept one, gets an error rather than
// silence — and silence is what makes a client believe a field had an effect.
// The specific case worth naming: nothing in this API accepts a tenant from a
// body, so a body carrying one must fail loudly rather than be ignored.
func decode(w http.ResponseWriter, r *http.Request, into any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return err
	}
	// Exactly one JSON value. A body with trailing content is a body somebody
	// built by concatenation, and accepting the first value silently discards
	// whatever they thought they were sending.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("body must contain exactly one JSON object")
	}
	return nil
}

// newToken mints a bearer value: 256 bits, base64url, no padding.
func newToken() (string, [32]byte, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", [32]byte{}, fmt.Errorf("api: generating a token: %w", err)
	}
	tok := base64.RawURLEncoding.EncodeToString(b[:])
	return tok, sha256.Sum256([]byte(tok)), nil
}

// sessionCookie builds the session cookie.
//
// HttpOnly so script cannot read it. SameSite=Lax rather than Strict: Strict
// breaks the OIDC redirect back from the identity provider, which is a
// cross-site navigation by construction, and Lax already withholds the cookie
// from the cross-site POSTs that CSRF is about — with the double-submit header
// covering what remains.
//
// No Domain attribute, ever. A cookie without one is host-only, which is what
// keeps a tenant's session from being sent to a sibling hostname; setting
// Domain to the registrable domain would share sessions across every tenant
// under it, which on a SaaS deployment is every customer.
// #nosec G124 -- Secure is set unless Config.Insecure, which is the dev-only
// escape hatch documented in env.example; HttpOnly and SameSite are literal.
func (s *Server) sessionCookie(value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.cfg.Insecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}
}

// csrfCookie is readable by script, by necessity: the page has to echo it into a
// header. It carries no authority on its own — it is only ever compared against
// the hash stored with the session, so possessing it without the session cookie
// achieves nothing.
// #nosec G124 -- HttpOnly is deliberately false — the page must read this value to
// echo it into a header — and the cookie carries no authority on its own.
func (s *Server) csrfCookie(value string, ttl time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     CSRFCookie,
		Value:    value,
		Path:     "/",
		HttpOnly: false,
		Secure:   !s.cfg.Insecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	}
}

// #nosec G124 -- A clearing cookie with an empty value and MaxAge -1. Its attributes
// match the cookie being cleared, which is what makes browsers replace it.
func (s *Server) expiredCookie(name string, httpOnly bool) *http.Cookie {
	return &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: httpOnly,
		Secure:   !s.cfg.Insecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	}
}

// pathUUID reads a uuid path parameter.
func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	return uuid.Parse(r.PathValue(name))
}

// actor is the current user, for audit events.
func actor(r *http.Request) *uuid.UUID {
	sess, ok := sessionFrom(r.Context())
	if !ok {
		return nil
	}
	id := sess.UserID
	return &id
}

// isLoopback reports whether an address is one only this machine can reach.
//
// Conservative: anything it cannot parse, and any hostname other than the two
// spellings of localhost, is treated as NOT loopback. The consequence of being
// wrong in that direction is a refused startup with a clear message; the
// consequence of the other direction is cookies without Secure on a reachable
// address.
func isLoopback(addr string) bool {
	if addr == "" {
		return false
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
}
