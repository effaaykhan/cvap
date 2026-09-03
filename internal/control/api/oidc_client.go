package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"

	"github.com/effaaykhan/cvap/internal/target"
)

// The outbound HTTP client for identity-provider traffic.
//
// ============================================================================
// This is the only place in Core that fetches a URL an operator supplied.
// ============================================================================
//
// `tenant_auth_config.oidc_issuer` is set by a tenant administrator, and Core
// then fetches discovery, JWKS and the token endpoint from it. That is a
// server-side request forgery primitive handed to a customer: an issuer of
// `https://169.254.169.254/` makes Core fetch cloud instance metadata —
// credentials for the machine this deployment runs on — and return errors that
// leak whether an internal host answered.
//
// The address is therefore checked at DIAL time, after DNS resolution, not by
// inspecting the URL. Checking the hostname is the version that does not work:
// an attacker controls their own DNS, so `idp.attacker.example` resolving to
// 169.254.169.254 passes any name-based check, and a name that resolves
// differently on the second lookup defeats a resolve-then-validate one. The dial
// hook sees the address the connection is actually being made to, which is the
// only value that cannot be rebound underneath it.

// oidcHTTPTimeout bounds one request to an identity provider.
//
// Short, and it needs to be: these fetches happen inside a login request, and an
// issuer that accepts a connection and never answers would otherwise hold a
// handler — and, through the semaphore-free path, a goroutine — for as long as
// it liked.
const oidcHTTPTimeout = 10 * time.Second

// newOIDCClient builds the hardened client.
//
// allowPrivate permits RFC 1918 and loopback addresses, for an on-prem
// deployment whose identity provider is on the internal network — which is the
// normal shape of on-prem, not an exception. It does NOT permit link-local:
// 169.254.169.254 is the cloud metadata service, there is no legitimate identity
// provider there, and an on-prem operator has no reason to want one.
// roots, when non-nil, REPLACES the system trust store for identity-provider
// traffic. For an on-prem deployment whose internal provider is issued by a
// private CA — the same deployment shape allowPrivate exists for. Nil means the
// system roots, which is what a public issuer needs.
func newOIDCClient(allowPrivate bool, roots *x509.CertPool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
		// Control runs after resolution, once per address the dialer tries, and
		// before the connection is established. Refusing here refuses the
		// connection rather than closing one that was already made.
		Control: func(network, address string, _ syscall.RawConn) error {
			return refuseUnsafeAddress(network, address, allowPrivate)
		},
	}
	return &http.Client{
		Timeout: oidcHTTPTimeout,
		Transport: &boundedBody{max: MaxIDPResponseBytes, inner: &http.Transport{
			DialContext: dialer.DialContext,
			// Never InsecureSkipVerify, and there is no setting that makes it
			// so. A deployment with a private CA supplies the CA; one that
			// cannot is one whose token exchange is not protected, and the
			// authorization code travels in that exchange.
			TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: 5 * time.Second,
			// A response body from an identity provider is a JSON document of a
			// few kilobytes. Anything claiming otherwise is not one.
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      false,
			ForceAttemptHTTP2:      true,
		}},
		// An identity provider that redirects is following its own discovery
		// document, which is fine — but each hop is re-dialled and therefore
		// re-checked, and the count is bounded so a redirect loop is not a way to
		// hold a handler open.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("api: identity provider redirected more than 5 times")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("api: identity provider redirected to a non-https URL")
			}
			return nil
		},
	}
}

// refuseUnsafeAddress decides whether Core may connect to a resolved address.
//
// ============================================================================
// This was a blocklist wearing an allowlist's comment, and an audit walked past
// it six different ways.
// ============================================================================
//
// The first version was a switch enumerating bad ranges — loopback, private,
// link-local, multicast, CGNAT, Teredo — ending in `return nil`. So an address
// it did not recognise was PERMITTED, which is the exact inverse of what its own
// comment and ADR-046 both claimed. An ADR-compliance pass ran it and got
// `2002:a00:1::1` (6to4 carrying 10.0.0.1), `64:ff9b::a00:1` (NAT64 carrying the
// same), `::a9fe:a9fe` (the metadata address in v4-compatible form), `240.0.0.1`,
// `0.1.2.3` and `fec0::1` all permitted. Its accompanying test asserted the
// blocklist entries and reported that as evidence of an allowlist.
//
// Two structures replace it, and they are different in kind on purpose:
//
//   - IPv6 is a genuine ALLOWLIST. Only 2000::/3 is globally-routable unicast
//     (RFC 4291), so everything outside it — ::/96, 64:ff9b::/96, fc00::/7,
//     fe80::/10, fec0::/10, ff00::/8 — is refused by the one condition, without
//     anybody having had to think of it.
//   - IPv4 is the IANA special-purpose registry, which IS an enumeration and is
//     defensible where "ways to spell an address" was not: the registry is
//     finite, standardised and changes about once a decade, whereas notations
//     are open-ended. Claiming otherwise would be the same overclaim again.
//
// And the notation problem is solved by EXTRACTION rather than enumeration:
// every IPv4 address an IPv6 form can carry is pulled out with the same
// target.TranslatedV4s that ADR-039 uses for scope exclusions, and each is
// checked as IPv4. A refusal list is exclusion-shaped, so ADR-039's rule applies
// to it whole rather than one mechanism at a time.
func refuseUnsafeAddress(network, address string, allowPrivate bool) error {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return fmt.Errorf("api: refusing a %s connection to an identity provider", network)
	}

	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("api: unparseable identity provider address %q", address)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		// The dialer hands Control a literal address, so this cannot be a name.
		// If it ever is, refuse: an unresolved value is one nothing has checked.
		return fmt.Errorf("api: identity provider address %q is not an IP", host)
	}

	// Every address the connection could be reaching: the address itself, and
	// every IPv4 address an IPv6 form embeds. Unmap first, so ::ffff:10.0.0.5 is
	// simply 10.0.0.5 — ADR-039 is explicit that the v4-mapped form is a
	// notation rather than one of the five translations.
	candidates := []netip.Addr{ip.Unmap()}
	candidates = append(candidates, target.TranslatedV4s(ip)...)

	for _, c := range candidates {
		if err := refuseOneAddress(c, ip, allowPrivate); err != nil {
			return err
		}
	}
	return nil
}

// refuseOneAddress judges a single candidate. via is the address actually being
// dialled, for the error message, which differs from c when c was extracted.
func refuseOneAddress(c, via netip.Addr, allowPrivate bool) error {
	named := c.String()
	if c != via.Unmap() {
		named = fmt.Sprintf("%s (embedded in %s)", c, via)
	}

	if c.Is4() {
		r := specialPurposeV4(c)
		if r == "" {
			return nil
		}
		// Private and loopback are the two an on-prem deployment legitimately
		// needs, and the only two the flag opens. Everything else in the
		// registry — link-local above all — is refused whatever it says.
		if allowPrivate && (r == reasonPrivate || r == reasonLoopback) {
			return nil
		}
		return fmt.Errorf("api: identity provider address %s is %s", named, r)
	}

	// IPv6, and the allowlist is one condition.
	if !globalUnicastV6.Contains(c) {
		if allowPrivate && (c.IsLoopback() || uniqueLocalV6.Contains(c)) {
			return nil
		}
		return fmt.Errorf("api: identity provider address %s is outside 2000::/3, the only "+
			"globally-routable IPv6 unicast range", named)
	}
	// Inside 2000::/3, three sub-ranges are special-purpose. Each also carries or
	// implies a v4 address, and TranslatedV4s has already extracted those — this
	// refuses the wrapper itself, which is a route through infrastructure the
	// deployment does not control.
	for _, sp := range specialPurposeV6 {
		if sp.prefix.Contains(c) {
			return fmt.Errorf("api: identity provider address %s is %s", named, sp.reason)
		}
	}
	return nil
}

const (
	reasonPrivate  = "in private address space (RFC 1918)"
	reasonLoopback = "loopback"
)

var (
	// The only globally-routable IPv6 unicast range (RFC 4291 §2.4).
	globalUnicastV6 = netip.MustParsePrefix("2000::/3")

	// fc00::/7, permitted only under allowPrivate — the IPv6 equivalent of
	// RFC 1918, and what an on-prem network actually uses.
	uniqueLocalV6 = netip.MustParsePrefix("fc00::/7")

	specialPurposeV6 = []struct {
		prefix netip.Prefix
		reason string
	}{
		{netip.MustParsePrefix("2001::/32"), "a Teredo address"},
		{netip.MustParsePrefix("2001:2::/48"), "benchmarking space"},
		{netip.MustParsePrefix("2001:db8::/32"), "documentation space"},
		{netip.MustParsePrefix("2002::/16"), "a 6to4 address"},
		{netip.MustParsePrefix("3fff::/20"), "documentation space"},
	}

	// The IANA IPv4 Special-Purpose Address Registry, in full.
	//
	// Written out rather than approximated with netip's predicates, because
	// those do not cover 100.64.0.0/10, 192.0.0.0/24, the three TEST-NETs,
	// 198.18.0.0/15 or 240.0.0.0/4 — which is how 240.0.0.1 and 0.1.2.3 were
	// permitted.
	specialPurposeV4 = func() func(netip.Addr) string {
		entries := []struct {
			prefix netip.Prefix
			reason string
		}{
			{netip.MustParsePrefix("0.0.0.0/8"), "this-network space"},
			{netip.MustParsePrefix("10.0.0.0/8"), reasonPrivate},
			{netip.MustParsePrefix("100.64.0.0/10"), "shared address space (RFC 6598)"},
			{netip.MustParsePrefix("127.0.0.0/8"), reasonLoopback},
			{netip.MustParsePrefix("169.254.0.0/16"), "link-local — where cloud instance metadata lives"},
			{netip.MustParsePrefix("172.16.0.0/12"), reasonPrivate},
			{netip.MustParsePrefix("192.0.0.0/24"), "IETF protocol assignments"},
			{netip.MustParsePrefix("192.0.2.0/24"), "documentation space"},
			{netip.MustParsePrefix("192.88.99.0/24"), "the 6to4 relay anycast range"},
			{netip.MustParsePrefix("192.168.0.0/16"), reasonPrivate},
			{netip.MustParsePrefix("198.18.0.0/15"), "benchmarking space"},
			{netip.MustParsePrefix("198.51.100.0/24"), "documentation space"},
			{netip.MustParsePrefix("203.0.113.0/24"), "documentation space"},
			{netip.MustParsePrefix("224.0.0.0/4"), "multicast"},
			{netip.MustParsePrefix("240.0.0.0/4"), "reserved space"},
		}
		return func(a netip.Addr) string {
			for _, e := range entries {
				if e.prefix.Contains(a) {
					return e.reason
				}
			}
			return ""
		}
	}()
)

// MaxIDPResponseBytes bounds any single response from an identity provider.
//
// A discovery document is a few kilobytes and a JWKS is smaller. One megabyte is
// far beyond either and far below anything that hurts.
const MaxIDPResponseBytes = 1 << 20

// boundedBody caps every response body fetched through this client.
//
// ============================================================================
// The cap is in the TRANSPORT because the caller is not ours.
// ============================================================================
//
// exchangeCode reads its own body through an io.LimitReader, which is fine for
// the one fetch this package performs itself. The other two — discovery and the
// JWKS refresh — happen INSIDE go-oidc, which uses io.ReadAll, and an
// *http.Client has no setting that limits a body.
//
// A security review measured the consequence: an issuer serving a 256 MiB
// discovery document took Core's heap to 2.2 GiB from a single UNAUTHENTICATED
// GET of /v1/auth/oidc/start. The issuer is tenant-administrator configuration,
// so that is one customer's row OOM-killing the process that runs dispatch,
// ingest and lease renewal for every other tenant.
//
// Wrapping the RoundTripper puts the bound below every caller, including ones
// added later and ones inside a dependency.
type boundedBody struct {
	max   int64
	inner http.RoundTripper
}

func (b *boundedBody) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := b.inner.RoundTrip(r)
	if err != nil || resp.Body == nil {
		return resp, err
	}
	// The original Body is kept as the Closer, so the connection is still
	// released properly; only what can be READ is capped.
	resp.Body = &cappedReadCloser{
		Reader: io.LimitReader(resp.Body, b.max),
		Closer: resp.Body,
	}
	return resp, nil
}

type cappedReadCloser struct {
	io.Reader
	io.Closer
}
