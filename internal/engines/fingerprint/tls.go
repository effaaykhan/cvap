package fingerprint

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"
)

// TLS inspection: looking at a certificate, which is not the same as trusting
// one.
//
// ============================================================================
// A scanner that VERIFIED certificates would be unable to report the problems
// it exists to find.
// ============================================================================
//
// An expired certificate, a self-signed one, a hostname mismatch, a chain that
// does not build — those are the findings. A verifying dial fails the handshake
// on every one of them and returns an error instead of the evidence, so the
// scan would be blind to exactly the estate it was pointed at.
//
// That makes InsecureSkipVerify correct here and nowhere else in this codebase,
// which is a dangerous combination: the words are identical to the ones in every
// real vulnerability, and a reader skimming for them finds a match. So it
// appears exactly once, inside a constructor whose name is the argument, and
// never at a call site.
//
// # Certificates from a scanned host are attacker-controlled
//
// By definition — the host chose what to send. crypto/x509 has parsed the chain
// by the time this code runs, so the parser's own bounds apply, but what this
// package then walks is unbounded in the ways that matter: chain depth, SAN
// count and extension count are all attacker-chosen, and each becomes an
// observation payload that travels to Core and into Postgres. The bounds below
// are the same argument as the banner read bound, one layer up.

// inspectOnlyTLSConfig returns a TLS configuration for INSPECTING a
// certificate, not for trusting it.
//
// ============================================================================
// The ONLY place InsecureSkipVerify appears. Do not write a tls.Config
// elsewhere in this package.
// ============================================================================
//
// Verification is off because verification failures ARE the findings — see the
// file comment. Nothing here establishes a trusted channel, sends a credential,
// or acts on what the peer says: the connection carries a fingerprint probe and
// its response, and both are recorded as evidence rather than believed.
//
// MinVersion is deliberately the floor rather than a modern default. A scanner
// that refused to negotiate TLS 1.0 could not report a server that only speaks
// TLS 1.0, which is a finding week 6 wants. gosec objects to both settings and
// is right to in general; the exception is annotated rather than silenced
// globally, so a second one elsewhere still fails the build.
//
// tls_mutation_test.go asserts that a plain verified dial FAILS the lab
// handshake — which is what makes this deliberate rather than incidental.
func inspectOnlyTLSConfig(serverName string) *tls.Config {
	// #nosec G402 -- deliberate and load-bearing. Certificate verification is
	// disabled because an unverifiable certificate is the OBSERVATION this
	// engine exists to produce; a verifying dial returns an error instead of the
	// evidence. MinVersion is the floor for the same reason: an obsolete
	// protocol version cannot be reported by a client that refuses to speak it.
	// Nothing is trusted, sent or acted upon over this connection.
	return &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,

		// ServerName drives SNI, which decides which certificate a virtual host
		// presents — without it a multi-tenant server returns its default and
		// the observation describes the wrong site. It is the target the runtime
		// authorised and never a name this engine composed.
		ServerName: serverName,

		// ALPN, offered so the answer means something.
		//
		// The tls payload had an `alpn` field and this config set no NextProtos,
		// so the field could only ever be empty — a safety audit confirmed
		// `alpn=[]` at a server with a hook on the ClientHello. A field that
		// cannot be non-empty is a claim the data will never support.
		//
		// These two are what every browser offers, so advertising them provokes
		// nothing unusual, and the negotiated answer is real evidence: a server
		// that selects h2 is a different thing from one that cannot.
		NextProtos: []string{"h2", "http/1.1"},
	}
}

// Bounds on what a hostile certificate can make this engine hold.
const (
	// MaxChainDepth is how many certificates of a presented chain are described.
	//
	// A real chain is two or three. crypto/tls will accept a long one, and each
	// certificate here becomes a JSON object on the wire and a row's worth of
	// payload in Postgres.
	MaxChainDepth = 6

	// MaxSANs bounds the names lifted from one certificate. A certificate may
	// legitimately carry many; it may also carry tens of thousands.
	MaxSANs = 64

	// MaxExtensionsFlagged is the extension count above which a certificate is
	// marked as carrying an unusual number.
	//
	// It bounds NOTHING, and the previous comment claiming it "bounds the
	// extension walk" was wrong — an audit pointed out there is no walk.
	// crypto/x509 has already parsed the extensions and holds them; this code
	// records `len` and a flag, and copies none of them into the payload. The
	// count is the evidence, and a certificate with a thousand extensions is
	// worth knowing about without carrying them.
	MaxExtensionsFlagged = 128

	// MaxNameLength truncates a subject or issuer DN.
	MaxNameLength = 512

	// TLSHandshakeCost is the packet cost of a handshake BEYOND the TCP
	// connection, charged to the rate budget.
	//
	// FOUR, and the number is measured rather than counted off the diagram.
	//
	// Three was the first value, reasoned from the record sequence: ClientHello,
	// then the client's change-cipher-spec and Finished, plus an ACK. A capture
	// of nine TLS probe connections against the lab's TLS host put 76 packets on
	// the wire against 68 charged — a shortfall of very close to one per
	// connection, which is the ACK of the server's flight that the reasoning
	// missed. At four, the model and the wire agree.
	//
	// Like EstablishedCost it errs high rather than low, because a ceiling that
	// guesses low is not a ceiling. `make safety` measures whether it holds.
	TLSHandshakeCost = 4
)

// certPayload describes one certificate. Everything week 6's non-CVE rules need
// to ask about a certificate, and nothing that would let this become a store of
// key material.
type certPayload struct {
	Subject   string `json:"subject"`
	Issuer    string `json:"issuer"`
	Serial    string `json:"serial,omitempty"`
	NotBefore string `json:"not_before"`
	NotAfter  string `json:"not_after"`

	DNSNames       []string `json:"dns_names,omitempty"`
	IPAddresses    []string `json:"ip_addresses,omitempty"`
	NamesTruncated bool     `json:"names_truncated,omitempty"`

	SelfSigned bool `json:"self_signed"`
	IsCA       bool `json:"is_ca"`

	SignatureAlgorithm string `json:"signature_algorithm"`
	PublicKeyAlgorithm string `json:"public_key_algorithm"`

	// KeyBits is zero when the algorithm is one this build does not size. Zero
	// means UNKNOWN and a rule must read it that way; reporting a guess would be
	// worse than reporting nothing, because "RSA below 2048 bits" is a finding
	// and a wrong zero is a false one.
	KeyBits int `json:"key_bits,omitempty"`

	// ExtensionCount is how many the certificate carried; none are copied into
	// this payload. ExtensionsUnusual flags a count above MaxExtensionsFlagged —
	// a fact about the certificate, not a statement that anything was dropped.
	ExtensionCount    int  `json:"extension_count"`
	ExtensionsUnusual bool `json:"extensions_unusual,omitempty"`
}

// tlsPayload is the `tls` object inside a service observation.
//
// Inside the service payload rather than an observation type of its own — see
// ADR-048. A certificate is a property of a service on a port, and splitting it
// out would force week 6's rules to join two observations to ask one question.
type tlsPayload struct {
	// Version is what was NEGOTIATED, which is the best both ends support and
	// not the worst the server would accept. A server offering TLS 1.0 and 1.3
	// reports 1.3 here. Detecting the obsolete floor needs one handshake per
	// version, which is a packet cost per port, and is deferred — see ADR-048.
	Version     string `json:"version"`
	CipherSuite string `json:"cipher_suite"`
	ALPN        string `json:"alpn,omitempty"`

	Chain          []certPayload `json:"chain,omitempty"`
	ChainLength    int           `json:"chain_length"`
	ChainTruncated bool          `json:"chain_truncated,omitempty"`
}

// dialTLS completes a handshake and describes what came back.
//
// Takes an already-connected TCP conn, so the caller has already paid for and
// charged the connection. Returns the wrapped connection for the caller to send
// its probe payload over.
func dialTLS(ctx context.Context, conn net.Conn, serverName string, timeout time.Duration) (*tls.Conn, *tlsPayload, error) {
	tc := tls.Client(conn, inspectOnlyTLSConfig(serverName))

	hsCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		return nil, nil, fmt.Errorf("tls handshake: %w", err)
	}
	return tc, describeTLS(tc.ConnectionState()), nil
}

// describeTLS turns a handshake into an observation payload, bounded.
func describeTLS(st tls.ConnectionState) *tlsPayload {
	p := &tlsPayload{
		Version:     tlsVersionName(st.Version),
		CipherSuite: tls.CipherSuiteName(st.CipherSuite),
		ALPN:        st.NegotiatedProtocol,
		ChainLength: len(st.PeerCertificates),
	}
	certs := st.PeerCertificates
	if len(certs) > MaxChainDepth {
		certs = certs[:MaxChainDepth]
		p.ChainTruncated = true
	}
	for _, c := range certs {
		p.Chain = append(p.Chain, describeCert(c))
	}
	return p
}

func describeCert(c *x509.Certificate) certPayload {
	out := certPayload{
		Subject:   truncate(c.Subject.String(), MaxNameLength),
		Issuer:    truncate(c.Issuer.String(), MaxNameLength),
		NotBefore: c.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  c.NotAfter.UTC().Format(time.RFC3339),
		IsCA:      c.IsCA,
		// Self-signed by NAME, which is what it means before any verification:
		// the subject and issuer are the same distinguished name. Not a
		// signature check — that would be verification, and this engine does
		// none.
		SelfSigned:         c.Subject.String() == c.Issuer.String(),
		SignatureAlgorithm: c.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: c.PublicKeyAlgorithm.String(),
		KeyBits:            keyBits(c),
	}
	if c.SerialNumber != nil {
		out.Serial = truncate(c.SerialNumber.String(), 80)
	}

	for _, n := range c.DNSNames {
		if len(out.DNSNames) >= MaxSANs {
			out.NamesTruncated = true
			break
		}
		out.DNSNames = append(out.DNSNames, truncate(n, 253))
	}
	for _, ip := range c.IPAddresses {
		if len(out.IPAddresses) >= MaxSANs {
			out.NamesTruncated = true
			break
		}
		out.IPAddresses = append(out.IPAddresses, ip.String())
	}

	out.ExtensionCount = len(c.Extensions)
	out.ExtensionsUnusual = out.ExtensionCount > MaxExtensionsFlagged
	return out
}

// keyBits sizes a public key, or returns zero for an algorithm this build does
// not size.
//
// Zero means UNKNOWN, never "small". A rule reading this must treat it as
// absent, which is why the field is omitempty: "RSA below 2048 bits" is a
// finding, and a wrong zero would be a false one.
func keyBits(c *x509.Certificate) int {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen()
	case *ecdsa.PublicKey:
		if k.Curve == nil || k.Params() == nil {
			return 0
		}
		return k.Params().BitSize
	default:
		// Ed25519 and anything newer. Sized by algorithm rather than by bits,
		// so reporting a number here would be inventing one.
		return 0
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1.0"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		// Named rather than left blank: an unrecognised version is itself worth
		// reporting, and a blank field reads as "no TLS".
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
