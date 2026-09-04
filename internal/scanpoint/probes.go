package scanpoint

import "github.com/effaaykhan/cvap/internal/enginewire"

// The probe corpus lives HERE, in the runtime, and not in the engine.
//
// ============================================================================
// An engine holds no probes, so "safe mode" is not a branch it could get wrong.
// ============================================================================
//
// ADR-021 makes safe the default for every policy, which means it is the mode
// most deployments run and the one that must be unable to provoke anything. Two
// ways to get that: tell the engine which mode it is in and trust it, or hand it
// nothing to send. The second is the same shape as ADR-027's rate budget — the
// engine cannot exceed an allocation it was never given — and it is the one that
// survives a bug in the engine, a rule that asks for a probe, and an engine
// written by somebody else later.
//
// # What counts as safe
//
// SAFE reads what a service volunteers on connect and sends nothing. SSH, FTP,
// SMTP, POP3, IMAP and MySQL all announce themselves; a connect and a bounded
// read identify them without a byte leaving in the other direction.
//
// INTRUSIVE sends one of these. The cost of the line is concrete and worth
// naming rather than discovering: **HTTP does not volunteer**, so in safe mode a
// web server is an open port with no service attached. That is the trade ADR-021
// asks for — the default mode identifies less — and it is why the mode is
// recorded on every observation rather than inferred later.
//
// # Why these are small and dull
//
// Each is a minimal, well-formed request that any conforming server answers, and
// none of them is a payload that achieves anything. Invariant 9: detection
// establishes evidence without achieving impact. A probe that exercised a parser
// bug to identify a version would be an exploit with a fingerprinting
// justification.

// ProbeCorpus is what an intrusive job may send.
//
// Returned as a fresh slice each call. The runtime hands this to an engine over
// a pipe and a shared backing array would be a mutable global reachable from the
// job path — cheap to avoid, and the kind of aliasing nobody finds later.
//
// # Which of these have been fired at a real server
//
// Named because the difference matters and would otherwise be invisible. The
// HTTP, HTTPS, response-shape and PostgreSQL rules below were written from
// captured responses — lab targets a1, a5, a6 and the dev PostgreSQL. The SMB,
// RDP, DNS and MSSQL rules are derived from their protocol specifications and
// have never fired against a live server, because the lab has no target for any
// of them. That is a gap in the LAB, recorded here rather than in a commit
// message: a rule nothing has exercised is a rule that may silently match
// nothing, which is the failure mode this codebase keeps finding.
//
// Their payloads are a different question from their patterns, and the payloads
// are the safety-relevant half: each is the standard opening packet of its
// protocol, sent before any authentication, and none of them is bounded by my
// confidence in it — MaxProbePayload and the non-inert port denylist in
// corpus.go bind whatever the pattern turns out to do.
func ProbeCorpus() []enginewire.Probe {
	return []enginewire.Probe{
		{
			// The one that matters most, because HTTP is silent until asked.
			// Measured: lab target-a1 answers a connect with nothing at all for
			// three seconds, and answers this with its Server header.
			//
			// HEAD rather than GET: it returns the status line and headers,
			// which is everything a service identification needs, and no body —
			// so a probe against an unexpected endpoint cannot pull a megabyte
			// of content back through the scan point.
			//
			// Host is required by HTTP/1.1 and a bare "*" is not valid for it,
			// so a literal placeholder travels; the engine substitutes the
			// target it was authorised for and constructs no other.
			Name:      "http-head",
			Ports:     []uint32{80, 81, 88, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888},
			Payload:   []byte("HEAD / HTTP/1.1\r\nHost: {{target}}\r\nUser-Agent: CVAP\r\nConnection: close\r\nAccept: */*\r\n\r\n"),
			ReadBytes: 8 << 10,
			Rarity:    1,
			Matches:   httpMatches(),
		},
		{
			// The same request through a TLS handshake.
			//
			// TLS is a flag rather than a payload because a handshake is a
			// conversation, and it is what makes the certificate reachable:
			// version, cipher, chain and subject all come from the negotiation,
			// not from anything the application layer says afterwards. Week 6's
			// non-CVE rules read that certificate, so this probe is the one
			// carrying most of next week's evidence.
			Name:      "https-head",
			Ports:     []uint32{443, 4443, 8443, 9443, 10443},
			TLS:       true,
			Payload:   []byte("HEAD / HTTP/1.1\r\nHost: {{target}}\r\nUser-Agent: CVAP\r\nConnection: close\r\nAccept: */*\r\n\r\n"),
			ReadBytes: 8 << 10,
			Rarity:    1,
			Matches:   httpMatches(),
		},
		{
			// A handshake and nothing else, for the ports where TLS wraps
			// something that is not HTTP. The certificate is the whole point;
			// there is no application payload to send, and sending an HTTP
			// request to an IMAPS port would be noise.
			Name:      "tls-hello",
			Ports:     []uint32{465, 563, 636, 989, 990, 992, 993, 995, 5061, 5671, 8883},
			TLS:       true,
			ReadBytes: 4 << 10,
			Rarity:    2,
		},
		{
			// ============================================================
			// Response SHAPE, for software configured not to name itself.
			// ============================================================
			//
			// Measured against lab target-a6, which runs `server_tokens off`.
			// That suppresses the version everywhere — but nginx still answers a
			// bad HTTP version with its own 505 page ending
			// `<hr><center>nginx</center>`, and Apache with an `<address>` line.
			// The shape identifies the product when the banner will not.
			//
			// Rarity 5: only worth the packets once the cheaper probes have
			// settled the protocol and left the product open.
			Name:      "http-badversion",
			Ports:     []uint32{80, 81, 88, 591, 3000, 5000, 8000, 8008, 8080, 8081, 8888},
			Payload:   []byte("GET / HTTP/9.9\r\n\r\n"),
			ReadBytes: 4 << 10,
			Rarity:    5,
			Matches:   shapeMatches(),
		},
		{
			// PostgreSQL, which volunteers NOTHING — measured, three seconds of
			// silence on connect. This is a startup packet naming protocol
			// version 0.65535, which no server supports, so the answer is an
			// error that names the product and its supported range and reaches
			// no authentication path at all.
			//
			// Measured response: `EFATAL:  unsupported frontend protocol
			// 0.65535: server supports 3.0 to 3.0`.
			Name:      "postgres-startup",
			Ports:     []uint32{5432, 5433, 6432},
			Payload:   []byte{0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0xff, 0xff},
			ReadBytes: 2 << 10,
			Rarity:    2,
			Matches: []enginewire.Match{
				{
					Pattern: `unsupported frontend protocol[^\n]*server supports (?P<info>[\d. ]+to[\d. ]+)`,
					Service: "postgresql", Product: "PostgreSQL",
					Confidence: ConfProductOnly,
				},
				{
					// Any error response at all, on a PostgreSQL port. The wire
					// format is `E` then a length then NUL-delimited fields.
					Pattern: `(?s)^E.*FATAL`,
					Service: "postgresql", Soft: true,
					Confidence: ConfProtocolOnly,
				},
			},
		},
		{
			// MSSQL, which also volunteers nothing. TDS pre-login is the first
			// packet of every client connection and carries no credentials.
			//
			// SPEC-DERIVED, never fired at a real server. Header: type 0x12
			// (pre-login), status 0x01 (end of message), length 0x0014, then a
			// VERSION option token and a terminator.
			Name:  "mssql-prelogin",
			Ports: []uint32{1433, 1434},
			Payload: []byte{
				0x12, 0x01, 0x00, 0x14, 0x00, 0x00, 0x01, 0x00,
				0x00, 0x00, 0x06, 0x00, 0x06, 0xff,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			ReadBytes: 2 << 10,
			Rarity:    3,
			Matches: []enginewire.Match{
				{
					// A pre-login RESPONSE is packet type 0x04 with the
					// end-of-message status. Structural, so it identifies the
					// protocol and not the product — which is what soft is for.
					Pattern: `(?s)^\x04\x01`,
					Service: "ms-sql-s", Soft: true, OSHint: "Windows",
					Confidence: ConfProtocolOnly,
				},
			},
		},
		{
			// SMB2 negotiate. SPEC-DERIVED, never fired at a real server.
			//
			// NetBIOS session header, an SMB2 header with the NEGOTIATE command,
			// and a negotiate request offering the 2.0.2 and 2.1 dialects. It is
			// the opening packet of every SMB2 conversation and precedes session
			// setup, which is where authentication would be.
			Name:  "smb2-negotiate",
			Ports: []uint32{139, 445},
			Payload: []byte{
				0x00, 0x00, 0x00, 0x45,
				0xfe, 'S', 'M', 'B', 0x40, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x24, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00,
				0x02, 0x02, 0x10, 0x02,
			},
			ReadBytes: 4 << 10,
			Rarity:    3,
			Matches: []enginewire.Match{
				{
					Pattern: `(?s)^....\xfeSMB`,
					Service: "microsoft-ds", Soft: true, OSHint: "Windows",
					Confidence: ConfProtocolOnly,
				},
				{
					// SMB1 servers answer an SMB2 negotiate with an SMB1
					// response, which is itself worth recording: SMB1 enabled is
					// a finding week 6 will want.
					Pattern: `(?s)^....\xffSMB`,
					Service: "netbios-ssn", Product: "SMBv1", OSHint: "Windows",
					Confidence: ConfProductOnly,
				},
			},
		},
		{
			// RDP. SPEC-DERIVED, never fired at a real server.
			//
			// A TPKT-framed X.224 connection request with an RDP negotiation
			// request — the first packet of the connection sequence, before any
			// credential exchange.
			Name:  "rdp-connect",
			Ports: []uint32{3389},
			Payload: []byte{
				0x03, 0x00, 0x00, 0x13,
				0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			ReadBytes: 1 << 10,
			Rarity:    3,
			Matches: []enginewire.Match{
				{
					// TPKT version 3, then an X.224 connection CONFIRM.
					Pattern: `(?s)^\x03\x00..\x0e\xd0`,
					Service: "ms-wbt-server", Soft: true, OSHint: "Windows",
					Confidence: ConfProtocolOnly,
				},
			},
		},
		{
			// DNS over TCP. SPEC-DERIVED, never fired at a real server.
			//
			// A CHAOS-class TXT query for `version.bind`, which is the
			// conventional way to ask a nameserver what it is. A read-only
			// query for a record the server publishes about itself.
			Name:  "dns-version-bind",
			Ports: []uint32{53},
			Payload: []byte{
				0x00, 0x1d,
				0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x07, 'v', 'e', 'r', 's', 'i', 'o', 'n',
				0x04, 'b', 'i', 'n', 'd', 0x00,
				0x00, 0x10, 0x00, 0x03,
			},
			ReadBytes: 2 << 10,
			Rarity:    3,
			Matches: []enginewire.Match{
				{
					// The BIND version string, when the server publishes one.
					Pattern: `(?s)version\x04bind\x00.*?(?P<version>9\.[\d]+\.[\w.\-]+)`,
					Service: "domain", Product: "ISC BIND",
					Confidence: ConfExactVersion,
				},
				{
					// Our own query id echoed back with the response bit set.
					Pattern: `(?s)^..\x124[\x80-\x87]`,
					Service: "domain", Soft: true,
					Confidence: ConfProtocolOnly,
				},
			},
		},
		{
			// ============================================================
			// A KEY EXCHANGE, not a payload. Its own kind (ADR-049).
			// ============================================================
			//
			// ADR-007's `ssh_hostkey` is the only identity key most Linux hosts
			// can offer: every strong key needs an agent or cloud metadata, and
			// without a moderate key asset resolution cannot merge a host across
			// a DHCP change. That is week 5's deliverable, so this probe is the
			// difference between a resolver that works for TLS-bearing hosts and
			// one that works.
			//
			// The engine offers curve25519 and nothing else, attempts no
			// authentication ever, and abandons the exchange once the host key
			// arrives — structurally, by implementing no message past the reply.
			// See internal/engines/fingerprint/ssh.go.
			//
			// Rarity 2: after the banner, which usually names OpenSSH and its
			// version already. This probe is for the KEY, not the name.
			Name:      "ssh-hostkey",
			Kind:      enginewire.ProbeKindSSHHostKey,
			Ports:     []uint32{22, 2222, 22222},
			ReadBytes: 4 << 10,
			Rarity:    2,
		},
		{
			// ============================================================
			// A newline is NOT inert, and this probe is port-scoped for it.
			// ============================================================
			//
			// It was written with no Ports, which means every open port —
			// and a packet-capture audit pointed out where that lands: 9100
			// is raw print, where a bare line is a print job; 502 is Modbus
			// and 102 is S7, where unsolicited bytes reach a PLC's protocol
			// stack. Invariant 9 is that detection establishes evidence
			// without achieving impact, and printing a page is impact.
			//
			// Scoped to text protocols that answer a bare line with a
			// banner or a syntax error and do nothing else with it.
			//
			// Rarity 9: the last thing tried, because it identifies least.
			Name: "newline",
			Ports: []uint32{
				21,   // FTP
				25,   // SMTP
				110,  // POP3
				119,  // NNTP
				143,  // IMAP
				587,  // submission
				1723, // PPTP
			},
			Payload:   []byte("\r\n"),
			ReadBytes: 4 << 10,
			Rarity:    9,
			// No matches of its own: what comes back is a greeting or a syntax
			// error, and BuiltinBannerMatches already reads greetings. A probe
			// with no matches still contributes — the response is recorded, and
			// the banner rules run against it.
		},
	}
}

// httpMatches identifies a web server from its response headers.
//
// Shared between the plain and TLS-wrapped HTTP probes, because HTTPS is HTTP
// after the handshake and duplicating the list would let the two drift.
//
// The generic Server-header rule at the end is the one that earns its place: it
// lifts the product and version out of ANY `Server: name/version` header through
// capture groups, so a server nobody wrote a rule for is still identified. The
// named rules above it exist for the cases where that shape does not hold.
func httpMatches() []enginewire.Match {
	return []enginewire.Match{
		{
			// Measured: lab target-a1, `Server: nginx/1.27.5`.
			Pattern: `\r\nServer: nginx/(?P<version>[\w.]+)`,
			Service: "http", Product: "nginx",
			Confidence: ConfExactVersion,
		},
		{
			// Measured: lab target-a6, `server_tokens off`, `Server: nginx`
			// with no version. The product survives; the version does not.
			Pattern: `\r\nServer: nginx\r\n`,
			Service: "http", Product: "nginx",
			Confidence: ConfProductOnly,
		},
		{
			Pattern: `\r\nServer: Apache/(?P<version>[\w.]+)(?: \((?P<info>[^)\r\n]+)\))?`,
			Service: "http", Product: "Apache httpd",
			Confidence: ConfExactVersion,
		},
		{
			Pattern: `\r\nServer: Microsoft-IIS/(?P<version>[\w.]+)`,
			Service: "http", Product: "Microsoft IIS httpd", OSHint: "Windows",
			Confidence: ConfExactVersion,
		},
		{
			Pattern:    `\r\nServer: (?P<product>[^\r\n/]+)/(?P<version>[^\r\n ]+)`,
			Service:    "http",
			Confidence: ConfExactVersion,
		},
		{
			Pattern:    `\r\nServer: (?P<product>[^\r\n]+)\r\n`,
			Service:    "http",
			Confidence: ConfProductOnly,
		},
		{
			// It answered HTTP and named nothing. A correct answer.
			Pattern: `^HTTP/1\.[01] \d{3}`,
			Service: "http", Soft: true,
			Confidence: ConfProtocolOnly,
		},
	}
}

// shapeMatches identifies a product from how it FAILS rather than what it claims.
//
// Measured against lab target-a6: `server_tokens off` removes the version from
// every header and every error page, and leaves the page structure alone.
func shapeMatches() []enginewire.Match {
	return []enginewire.Match{
		{
			// nginx signs its error pages in a centred horizontal rule. Present
			// with server_tokens off, which is the whole reason to send this.
			Pattern: `<hr><center>nginx(?:/(?P<version>[\w.]+))?</center>`,
			Service: "http", Product: "nginx",
			Confidence: ConfShape,
		},
		{
			Pattern: `<address>Apache/?(?P<version>[\w.]*)[^<]*</address>`,
			Service: "http", Product: "Apache httpd",
			Confidence: ConfShape,
		},
		{
			Pattern: `^HTTP/1\.[01] \d{3}`,
			Service: "http", Soft: true,
			Confidence: ConfProtocolOnly,
		},
	}
}

// ProbeTargetPlaceholder is what an engine substitutes with the target it was
// given.
//
// A placeholder rather than a target-shaped field, so that the corpus stays a
// constant and the only address a probe can carry is the one the runtime already
// authorised. An engine that could compose its own Host header could name a host
// nobody approved — which is target construction, and ADR-027 forbids it.
//
// The engines hold their own copy of the literal, because internal/enginewire is
// the contract between the two and this package is not on the engine import
// allowlist. probes_test.go asserts the two agree, since a silent divergence
// would send `Host: {{target}}` to a real server.
//
// # It grows the payload, and the payload bound has to know that
//
// Substitution happens in the engine, AFTER every bound in this package. A
// 510-byte probe made of 51 placeholders was measured putting 867 bytes on the
// wire against a v4-mapped address and would put ~1989 against a full IPv6 one.
// MaxProbePayload is therefore checked against the SUBSTITUTED worst case — see
// substitutedSize in corpus.go — and the engine bounds the result again.
const ProbeTargetPlaceholder = "{{target}}"

// MaxTargetLength is the longest address that can replace a placeholder.
//
// A full IPv6 address with an embedded IPv4 suffix is 45 characters
// ("0000:...:255.255.255.255"); 46 leaves a byte of margin. Used to compute the
// worst-case substituted payload size, so a probe cannot slip past the payload
// bound by carrying placeholders instead of bytes.
const MaxTargetLength = 46
