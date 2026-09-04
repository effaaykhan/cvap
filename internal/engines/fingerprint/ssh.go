package fingerprint

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strings"
	"time"
)

// Reading an SSH host key, and stopping the instant we have it.
//
// ============================================================================
// This is a KEY EXCHANGE, not a payload. It is its own probe kind for that
// reason (ADR-049).
// ============================================================================
//
// ADR-048's probe policy — a payload bound, a non-inert port denylist, nothing
// in safe mode, nothing at a fragile target — was written for byte strings, and
// three of those four still apply here. The payload bound does not, because
// this probe has no payload: it has a conversation. Stretching a bound written
// about bytes to cover a handshake would have been the wrong repair; ADR-049
// makes probe KIND explicit instead.
//
// # Why this is hand-written and golang.org/x/crypto/ssh is refused
//
// That package would read a host key in about six lines, through a
// HostKeyCallback that captures the key and returns an error to abort. It is
// also a complete SSH client: it can authenticate.
//
// Invariant 9 is that detection establishes evidence without achieving impact,
// and "we do not send credentials" is a promise, not a property. What is written
// below cannot authenticate because THERE IS NO CODE HERE THAT CAN. It sends two
// messages, reads two, and closes. It has no password path, no public-key path,
// no SSH_MSG_SERVICE_REQUEST, and no implementation of SSH_MSG_USERAUTH_REQUEST
// at all — the constant is not even defined.
//
// The cost is ~200 lines of binary protocol against a dependency that already
// exists. The benefit is that the safety property is structural.
//
// # What is offered, and where it stops
//
// KEX algorithms offered: curve25519-sha256 and its libssh.org alias, and
// nothing else. A server that speaks neither ends the exchange with no host key
// learned, which is the correct outcome — widening the offer to reach an ancient
// server means implementing more of the protocol, and the point is to implement
// as little as possible.
//
// Host key algorithms offered: broadly, because the server picks one and what it
// picks is the evidence.
//
// The exchange is ABANDONED after SSH_MSG_KEX_ECDH_REPLY. Not "we stop before
// auth" — the reply carrying the host key is the last message this code can
// parse, and the next thing it does is close the socket. Nothing derives session
// keys, nothing sends SSH_MSG_NEWKEYS, and past that point the protocol is
// simply not implemented.
//
// The shared secret is never computed either. The ephemeral X25519 key exists
// only because the protocol requires the client to send one; its private half is
// used for nothing.

// SSH message numbers, and deliberately only these (RFC 4253 §12, RFC 5656 §7.1).
//
// SSH_MSG_SERVICE_REQUEST (5) and SSH_MSG_USERAUTH_REQUEST (50) are absent
// because nothing here sends them. Defining a constant is not sending a message,
// but the absence is a reviewable statement about how far this goes.
const (
	sshMsgDisconnect  = 1
	sshMsgIgnore      = 2
	sshMsgDebug       = 4
	sshMsgKexInit     = 20
	sshMsgKexECDHInit = 30
	sshMsgKexECDHRepl = 31
)

// Bounds on a conversation with a host that may be adversarial.
const (
	// sshMaxPacket is the largest binary packet accepted. RFC 4253 requires
	// implementations to support 35000; anything beyond that from a scan target
	// is not a packet we need.
	sshMaxPacket = 64 << 10

	// sshMaxVersionLine bounds the identification string, which RFC 4253 caps at
	// 255 bytes including CRLF. A server may send other lines before it.
	sshMaxVersionLine  = 255
	sshMaxVersionLines = 8

	// sshMaxSkippedMessages bounds how many DEBUG or IGNORE messages a host may
	// interpose before the one being waited for. A server that sends more is
	// keeping this connection open, which is what the bound is against.
	sshMaxSkippedMessages = 16

	// sshMaxNames bounds an algorithm name-list, which is attacker-chosen and
	// travels into an observation payload.
	sshMaxNames    = 64
	sshMaxNameLen  = 64
	sshMaxHostKey  = 8 << 10
	sshClientIdent = "SSH-2.0-CVAP"

	// SSHProbeCost is what this exchange costs in packets, charged up front.
	//
	// Version line, KEXINIT, KEX_ECDH_INIT — three the client sends — plus the
	// ACKs for the server's own flight. Six, erring high like every other cost
	// in this engine, because a ceiling that guesses low is not a ceiling.
	SSHProbeCost = 6
)

// errSSHNoHostKey means the exchange ended without one. Not a failure worth
// abandoning a chain for: a host that will not negotiate curve25519 is a fact
// about the host.
var errSSHNoHostKey = errors.New("fingerprint: no host key was offered")

// sshPayload is the `ssh` object inside a service observation.
//
// Inside the service payload for the same reason the `tls` object is (ADR-048
// §5): a host key is a property of a service on a port, and splitting it makes
// every rule that reads it a join.
type sshPayload struct {
	// HostKeyType is the algorithm the server chose — ssh-ed25519, rsa-sha2-512.
	HostKeyType string `json:"host_key_type"`

	// Fingerprint is SHA-256 over the host key blob, rendered the way OpenSSH
	// renders one so an operator can compare it against `ssh-keygen -lf`.
	//
	// This is ADR-007's `ssh_hostkey` identity key: moderate strength, and the
	// only one most Linux hosts can offer, since every strong key needs an agent
	// or cloud metadata.
	Fingerprint string `json:"fingerprint"`

	// What the SERVER offered, which is evidence in its own right: `ssh-rsa`
	// still on the list, or a KEX algorithm long deprecated, are both findings
	// week 6 will want.
	HostKeyAlgorithms []string `json:"host_key_algorithms,omitempty"`
	KexAlgorithms     []string `json:"kex_algorithms,omitempty"`

	// Truncated says a list was longer than the bound and is not complete.
	Truncated bool `json:"truncated,omitempty"`
}

// sshHostKey performs the exchange and abandons it.
//
// Takes an already-connected socket, so the caller has paid for and charged the
// connection. Returns as soon as the host key is in hand.
func sshHostKey(ctx context.Context, conn net.Conn, timeout time.Duration) (*sshPayload, error) {
	if dl, ok := ctx.Deadline(); ok && dl.Before(time.Now().Add(timeout)) {
		timeout = time.Until(dl)
	}
	if timeout <= 0 {
		return nil, errSSHNoHostKey
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	// ---- version exchange -------------------------------------------------
	if _, err := conn.Write([]byte(sshClientIdent + "\r\n")); err != nil {
		return nil, err
	}
	if err := readSSHVersion(conn); err != nil {
		return nil, err
	}

	// ---- our KEXINIT ------------------------------------------------------
	if err := writeSSHPacket(conn, clientKexInit()); err != nil {
		return nil, err
	}

	// ---- the server's, which is where the offered algorithms come from ----
	serverKex, err := readSSHPacketOfType(conn, sshMsgKexInit)
	if err != nil {
		return nil, err
	}
	out := &sshPayload{}
	kex, hostKeys, truncated, err := parseKexInit(serverKex)
	if err != nil {
		return nil, err
	}
	out.KexAlgorithms, out.HostKeyAlgorithms, out.Truncated = kex, hostKeys, truncated

	// ---- KEX_ECDH_INIT ----------------------------------------------------
	//
	// The private half of this key is used for NOTHING. No shared secret is
	// computed, no session keys are derived; the protocol requires a client
	// public key and this is one.
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	init := make([]byte, 0, 1+4+32)
	init = append(init, sshMsgKexECDHInit)
	init = appendSSHString(init, priv.PublicKey().Bytes())
	if err := writeSSHPacket(conn, init); err != nil {
		return nil, err
	}

	// ---- the reply, and then we stop --------------------------------------
	reply, err := readSSHPacketOfType(conn, sshMsgKexECDHRepl)
	if err != nil {
		return nil, err
	}
	blob, _, ok := readSSHString(reply[1:])
	if !ok || len(blob) == 0 || len(blob) > sshMaxHostKey {
		return nil, fmt.Errorf("%w: host key blob is %d bytes", errSSHNoHostKey, len(blob))
	}

	// The key type is the first string INSIDE the blob, which is how the server
	// names what it sent. Taken from there rather than from the negotiated
	// algorithm name, because the blob is the thing being fingerprinted.
	keyType, _, _ := readSSHString(blob)
	sum := sha256.Sum256(blob)
	out.HostKeyType = truncate(string(keyType), sshMaxNameLen)
	out.Fingerprint = "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])

	// ========================================================================
	// This is the end of the implementation, and that is the safety property.
	// ========================================================================
	//
	// There is no SSH_MSG_NEWKEYS here, no key derivation, no service request
	// and no userauth. Not "we choose not to" — the code does not exist. The
	// caller closes the socket.
	return out, nil
}

// readSSHVersion consumes the server's identification string.
//
// A server may send informational lines first (RFC 4253 §4.2), so a bounded
// number are skipped until one starts with "SSH-".
func readSSHVersion(conn net.Conn) error {
	buf := make([]byte, 1)
	for range sshMaxVersionLines {
		var line []byte
		for len(line) < sshMaxVersionLine {
			if _, err := io.ReadFull(conn, buf); err != nil {
				return err
			}
			if buf[0] == '\n' {
				break
			}
			if buf[0] != '\r' {
				line = append(line, buf[0])
			}
		}
		if strings.HasPrefix(string(line), "SSH-") {
			return nil
		}
	}
	return fmt.Errorf("%w: no identification string", errSSHNoHostKey)
}

// clientKexInit builds our offer.
func clientKexInit() []byte {
	cookie := make([]byte, 16)
	// A failure here would mean the process has no entropy, which is not a
	// condition this can proceed under — but the cookie's only role is
	// freshness in an exchange hash nothing computes, so a zero cookie is not
	// a security decision. Ignored deliberately rather than silently.
	_, _ = rand.Read(cookie)

	p := []byte{sshMsgKexInit}
	p = append(p, cookie...)
	for _, list := range [][]string{
		// KEX: curve25519 only. A narrower offer is a smaller implementation.
		{"curve25519-sha256", "curve25519-sha256@libssh.org"},
		// Host keys: broad, because what the server picks is the evidence.
		{
			"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256",
			"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
			"ssh-rsa", "ssh-dss",
		},
		// Ciphers and MACs are offered because the message requires them and
		// are never used: nothing past the host key is implemented.
		{"aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com"},
		{"aes128-ctr", "aes256-ctr", "chacha20-poly1305@openssh.com"},
		{"hmac-sha2-256", "hmac-sha2-512"},
		{"hmac-sha2-256", "hmac-sha2-512"},
		{"none"},
		{"none"},
		{},
		{},
	} {
		p = appendSSHString(p, []byte(strings.Join(list, ",")))
	}
	p = append(p, 0)          // first_kex_packet_follows
	p = append(p, 0, 0, 0, 0) // reserved
	return p
}

// parseKexInit lifts the two name-lists worth recording.
func parseKexInit(p []byte) (kex, hostKeys []string, truncated bool, err error) {
	if len(p) < 17 {
		return nil, nil, false, fmt.Errorf("%w: short KEXINIT", errSSHNoHostKey)
	}
	rest := p[17:] // message number and the 16-byte cookie

	kexRaw, rest, ok := readSSHString(rest)
	if !ok {
		return nil, nil, false, fmt.Errorf("%w: no kex algorithms", errSSHNoHostKey)
	}
	hostRaw, _, ok := readSSHString(rest)
	if !ok {
		return nil, nil, false, fmt.Errorf("%w: no host key algorithms", errSSHNoHostKey)
	}
	kex, t1 := boundedNames(string(kexRaw))
	hostKeys, t2 := boundedNames(string(hostRaw))
	return kex, hostKeys, t1 || t2, nil
}

// boundedNames splits a comma-separated name-list under a bound.
//
// The list is attacker-chosen and every entry becomes a JSON string travelling
// to Core and into Postgres — the same argument as the certificate SAN bound,
// one protocol over.
func boundedNames(list string) ([]string, bool) {
	if list == "" {
		return nil, false
	}
	parts := strings.Split(list, ",")
	truncated := false
	if len(parts) > sshMaxNames {
		parts, truncated = parts[:sshMaxNames], true
	}
	out := make([]string, 0, len(parts))
	for _, n := range parts {
		if len(n) > sshMaxNameLen {
			n, truncated = n[:sshMaxNameLen], true
		}
		out = append(out, n)
	}
	return out, truncated
}

// writeSSHPacket frames a payload in the binary packet protocol (RFC 4253 §6).
//
// No MAC and no encryption: none has been negotiated at this point in the
// exchange, and none ever will be here.
func writeSSHPacket(conn net.Conn, payload []byte) error {
	// packet_length covers padding_length + payload + padding, and the whole
	// packet including the length field must be a multiple of 8 with at least
	// four bytes of padding.
	pad := 8 - ((5 + len(payload)) % 8)
	if pad < 4 {
		pad += 8
	}
	pkt := make([]byte, 0, 5+len(payload)+pad)
	pkt = binary.BigEndian.AppendUint32(pkt, sshLen(1+len(payload)+pad))
	pkt = append(pkt, byte(pad))
	pkt = append(pkt, payload...)
	padding := make([]byte, pad)
	_, _ = rand.Read(padding)
	pkt = append(pkt, padding...)

	_, err := conn.Write(pkt)
	return err
}

// readSSHPacketOfType reads until a packet of the wanted type arrives.
//
// DEBUG and IGNORE are skipped under a bound; DISCONNECT ends it. Anything else
// unexpected ends it too — this implementation understands four messages and
// guessing at a fifth is how a parser grows.
func readSSHPacketOfType(conn net.Conn, want byte) ([]byte, error) {
	for range sshMaxSkippedMessages {
		p, err := readSSHPacket(conn)
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			continue
		}
		switch p[0] {
		case want:
			return p, nil
		case sshMsgIgnore, sshMsgDebug:
			continue
		case sshMsgDisconnect:
			return nil, fmt.Errorf("%w: the host disconnected", errSSHNoHostKey)
		default:
			return nil, fmt.Errorf("%w: unexpected message %d", errSSHNoHostKey, p[0])
		}
	}
	return nil, fmt.Errorf("%w: too many interposed messages", errSSHNoHostKey)
}

func readSSHPacket(conn net.Conn) ([]byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(hdr[:4])
	padding := uint32(hdr[4])
	// Bounded before allocating: `length` is the first thing a hostile host
	// controls, and a four-gigabyte make() is the whole attack.
	if length < 2 || length > sshMaxPacket || padding+1 > length {
		return nil, fmt.Errorf("%w: packet length %d padding %d", errSSHNoHostKey, length, padding)
	}
	body := make([]byte, length-1)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body[:len(body)-int(padding)], nil
}

func appendSSHString(b, s []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, sshLen(len(s)))
	return append(b, s...)
}

// sshLen narrows a length for the wire, saturating rather than wrapping.
//
// Everything this file frames is something it built — a name-list, a 32-byte
// public key — so the bound is unreachable in practice. It is a saturating
// conversion rather than a `#nosec` because a wrapped length is a framing bug
// that would desynchronise the stream, and saturating turns that into a packet
// the peer rejects instead of one it misreads.
func sshLen(n int) uint32 {
	if n < 0 {
		return 0
	}
	if n > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

func readSSHString(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, nil, false
	}
	n := binary.BigEndian.Uint32(b[:4])
	// Compared in int64 rather than by converting the length to unsigned: the
	// length is attacker-controlled and `len(b)-4` is the value a wrong bound
	// would turn negative, which as an unsigned comparison becomes enormous and
	// admits everything.
	if int64(n) > int64(len(b))-4 {
		return nil, nil, false
	}
	return b[4 : 4+n], b[4+n:], true
}
