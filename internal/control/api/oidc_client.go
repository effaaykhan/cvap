package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"syscall"
	"time"
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
		Transport: &http.Transport{
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
		},
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

// refuseUnsafeAddress rejects anything that is not a public unicast address, or
// — when allowPrivate is set — anything that is not public, private or loopback.
//
// Deny by default: an address this function does not understand is refused. The
// structure is deliberately "permit these, refuse the rest" rather than a list of
// blocked ranges, because a blocklist is the enumeration failure this codebase
// keeps finding: there is always one more range, and the one nobody listed is
// the one that reaches the metadata service.
//
// LINK-LOCAL IS REFUSED EVEN WITH allowPrivate. That is the whole point of
// separating the two: an on-prem operator legitimately needs 10.0.0.5, and
// nobody legitimately needs 169.254.169.254.
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
	ip = ip.Unmap()

	// Checked BEFORE the allowPrivate cases, so nothing below can permit it.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("api: identity provider resolved to a link-local address %s — "+
			"169.254.169.254 and fe80::/10 are where cloud instance metadata lives, and no "+
			"identity provider belongs there", ip)
	}
	if allowPrivate && (ip.IsLoopback() || ip.IsPrivate()) {
		return nil
	}

	switch {
	case ip.IsLoopback():
		return fmt.Errorf("api: identity provider resolved to loopback %s", ip)
	case ip.IsPrivate():
		return fmt.Errorf("api: identity provider resolved to a private address %s", ip)
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		// 169.254.169.254 and fe80::/10. The cloud metadata case.
		return fmt.Errorf("api: identity provider resolved to a link-local address %s", ip)
	case ip.IsUnspecified():
		return fmt.Errorf("api: identity provider resolved to the unspecified address")
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return fmt.Errorf("api: identity provider resolved to a multicast address %s", ip)
	case !ip.IsGlobalUnicast():
		return fmt.Errorf("api: identity provider resolved to a non-global address %s", ip)
	case ip.Is4() && ip.As4()[0] == 100 && ip.As4()[1]&0xC0 == 64:
		// 100.64.0.0/10, RFC 6598 carrier-grade NAT. Not covered by IsPrivate,
		// and it is where a cloud provider's own infrastructure often sits.
		return fmt.Errorf("api: identity provider resolved to a shared-address-space address %s", ip)
	case ip.Is6() && ip.As16()[0] == 0x20 && ip.As16()[1] == 0x01 && ip.As16()[2] == 0x00:
		// 2001:0000::/32, Teredo. It carries an embedded v4 address, so
		// permitting it would permit reaching a private v4 host through a
		// translator — the ADR-039 asymmetry, arrived at from the other side.
		return fmt.Errorf("api: identity provider resolved to a Teredo address %s", ip)
	}
	return nil
}
