package fingerprint

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// SSH tests, against a server this test speaks itself.
//
// ============================================================================
// The server is hand-written for the same reason the client is.
// ============================================================================
//
// The obvious test server is golang.org/x/crypto/ssh, and importing it — even
// only in a test — would put a package that can authenticate inside this
// engine's import allowlist. `internal/enginepolicy` checks test imports on
// purpose, and "only in tests" is how the first exception gets made without
// anyone deciding to make one.
//
// Writing the server here also buys the assertion that matters: it RECORDS every
// message the client sends, so the test can state that nothing followed the key
// exchange rather than trusting that nothing does.
//
// Mutations, declared beside the tests that must kill them.
//
// mutate:subject internal/engines/fingerprint/ssh.go
// mutate:test    ./internal/engines/fingerprint/ -run TestTheHostKeyIsRead|TestTheExchangeIsAbandoned|TestAnOversizedSSHPacket|TestASSHNameListIsBounded
//
// mutate:case    an oversized SSH packet length is allocated before it is bounded
// mutate:old     if length < 2 || length > sshMaxPacket || padding+1 > length {
// mutate:new     if length < 2 || padding+1 > length {
//
// The first thing a hostile host controls is that length. A four-gigabyte
// make() is the whole attack, and it happens before a single byte of the body
// has been read.
//
// The other half of the abandonment property — that this package contains no
// code able to send a fourth message — is asserted in internal/scanpoint, which
// may import `os` to read this file. The engine may not, and the guard fired
// when it was written here.
//
// mutate:case    an algorithm name-list is lifted without a bound
// mutate:old     if len(parts) > sshMaxNames {
// mutate:new     if len(parts) > 1<<30 {
//
// mutate:case    a host key blob is accepted at any size
// mutate:old     if !ok || len(blob) == 0 || len(blob) > sshMaxHostKey {
// mutate:new     if !ok || len(blob) == 0 {

// sshServer speaks just enough of RFC 4253 to hand out a host key, and records
// what the client sent.
type sshServer struct {
	port uint16

	mu       sync.Mutex
	received []byte // message numbers, in order
	extra    int    // bytes read after the exchange completed

	hostKeyBlob []byte
	kexList     string
	hostKeyList string
	packetPad   int // override padding, to build a malformed packet
}

func newSSHServer(t *testing.T, s *sshServer) *sshServer {
	t.Helper()
	if s.hostKeyBlob == nil {
		// A well-formed ssh-ed25519 blob: the type string, then the 32-byte key.
		s.hostKeyBlob = appendSSHString(appendSSHString(nil, []byte("ssh-ed25519")),
			make([]byte, 32))
	}
	if s.kexList == "" {
		s.kexList = "curve25519-sha256,ecdh-sha2-nistp256"
	}
	if s.hostKeyList == "" {
		s.hostKeyList = "ssh-ed25519,rsa-sha2-512"
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s.port = uint16(ln.Addr().(*net.TCPAddr).Port)

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.serve(c)
		}
	}()
	return s
}

func (s *sshServer) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := c.Write([]byte("SSH-2.0-test-server\r\n")); err != nil {
		return
	}
	// The client's identification line.
	buf := make([]byte, 1)
	for range 256 {
		if _, err := io.ReadFull(c, buf); err != nil {
			return
		}
		if buf[0] == '\n' {
			break
		}
	}

	// KEXINIT, ours.
	kex := []byte{sshMsgKexInit}
	kex = append(kex, make([]byte, 16)...)
	for _, l := range []string{s.kexList, s.hostKeyList, "aes128-ctr", "aes128-ctr",
		"hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""} {
		kex = appendSSHString(kex, []byte(l))
	}
	kex = append(kex, 0, 0, 0, 0, 0)
	if err := s.write(c, kex); err != nil {
		return
	}

	// Theirs, then their KEX_ECDH_INIT.
	for range 2 {
		p, err := readSSHPacket(c)
		if err != nil || len(p) == 0 {
			return
		}
		s.mu.Lock()
		s.received = append(s.received, p[0])
		s.mu.Unlock()
	}

	reply := []byte{sshMsgKexECDHRepl}
	reply = appendSSHString(reply, s.hostKeyBlob)
	reply = appendSSHString(reply, make([]byte, 32)) // Q_S
	reply = appendSSHString(reply, []byte("signature-not-verified-by-the-client"))
	if err := s.write(c, reply); err != nil {
		return
	}

	// ====================================================================
	// Anything the client sends now is a message past the host key.
	// ====================================================================
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	tail := make([]byte, 512)
	n, _ := c.Read(tail)
	s.mu.Lock()
	s.extra = n
	s.mu.Unlock()
}

func (s *sshServer) write(c net.Conn, payload []byte) error {
	pad := s.packetPad
	if pad == 0 {
		pad = 8 - ((5 + len(payload)) % 8)
		if pad < 4 {
			pad += 8
		}
	}
	pkt := binary.BigEndian.AppendUint32(nil, uint32(1+len(payload)+pad))
	pkt = append(pkt, byte(pad))
	pkt = append(pkt, payload...)
	pkt = append(pkt, make([]byte, pad)...)
	_, err := c.Write(pkt)
	return err
}

func (s *sshServer) sent() ([]byte, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.received...), s.extra
}

// TestTheHostKeyIsReadAndFingerprinted.
//
// ADR-007's `ssh_hostkey` is the only identity key most Linux hosts can offer,
// and asset resolution cannot merge a host across a DHCP change without one.
func TestTheHostKeyIsReadAndFingerprinted(t *testing.T) {
	srv := newSSHServer(t, &sshServer{})

	cfg := baseConfig(srv.port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{Name: "ssh-hostkey", Kind: probeKindSSHHostKey, Ports: []uint16{srv.port}}}

	got := collect(t, cfg, target())
	if len(got) != 1 || got[0].SSH == nil {
		t.Fatalf("no ssh payload: %+v", got)
	}
	ssh := got[0].SSH
	if ssh.HostKeyType != "ssh-ed25519" {
		t.Errorf("host_key_type = %q", ssh.HostKeyType)
	}
	if !strings.HasPrefix(ssh.Fingerprint, "SHA256:") || len(ssh.Fingerprint) < 20 {
		t.Errorf("fingerprint = %q, want an OpenSSH-style SHA256 digest", ssh.Fingerprint)
	}
	if len(ssh.KexAlgorithms) == 0 || len(ssh.HostKeyAlgorithms) == 0 {
		t.Error("the server's offered algorithms were not recorded; they are week 6 evidence")
	}
	if got[0].Service != "ssh" || !got[0].Softmatch {
		t.Errorf("a completed key exchange must be a SOFT ssh match: service=%q soft=%v",
			got[0].Service, got[0].Softmatch)
	}
}

// TestTheExchangeIsAbandonedAfterTheHostKey.
//
// ============================================================================
// The safety property, asserted at the wire and in the source.
// ============================================================================
//
// Invariant 9: detection establishes evidence without achieving impact. An SSH
// probe that proceeded past the key exchange would be touching authentication.
// "We do not send credentials" is a promise; this asserts the two things that
// make it a property — the client sends exactly three things and then stops, and
// the package contains no code that could send a fourth.
func TestTheExchangeIsAbandonedAfterTheHostKey(t *testing.T) {
	srv := newSSHServer(t, &sshServer{})

	cfg := baseConfig(srv.port)
	cfg.SafetyMode = "intrusive"
	cfg.Probes = []Probe{{Name: "ssh-hostkey", Kind: probeKindSSHHostKey, Ports: []uint16{srv.port}}}
	collect(t, cfg, target())

	msgs, extra := srv.sent()
	if len(msgs) != 2 || msgs[0] != sshMsgKexInit || msgs[1] != sshMsgKexECDHInit {
		t.Errorf("client sent messages %v, want exactly KEXINIT then KEX_ECDH_INIT", msgs)
	}
	if extra != 0 {
		t.Errorf("%d bytes were sent AFTER the host key arrived; the exchange must be "+
			"abandoned there", extra)
	}

}

// TestAnOversizedSSHPacketIsRefusedBeforeItIsAllocated.
//
// The packet length is the first thing a hostile host controls, and a
// four-gigabyte make() is the whole attack.
func TestAnOversizedSSHPacketIsRefusedBeforeItIsAllocated(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = c.Write([]byte("SSH-2.0-hostile\r\n"))
		// A length field claiming a gigabyte, and then nothing.
		_, _ = c.Write(binary.BigEndian.AppendUint32(nil, 1<<30))
		_, _ = c.Write([]byte{4})
		time.Sleep(200 * time.Millisecond)
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := sshHostKey(t.Context(), conn, 2*time.Second); err == nil {
			t.Error("a packet claiming 2^30 bytes was accepted")
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sshHostKey did not return; it is probably waiting on a gigabyte")
	}
}

// TestASSHNameListIsBounded.
//
// Every entry becomes a JSON string travelling to Core and into Postgres — the
// same argument as the certificate SAN bound, one protocol over.
func TestASSHNameListIsBounded(t *testing.T) {
	long := make([]string, sshMaxNames*3)
	for i := range long {
		long[i] = strings.Repeat("a", sshMaxNameLen+10)
	}
	names, truncated := boundedNames(strings.Join(long, ","))
	if len(names) != sshMaxNames {
		t.Errorf("kept %d names, want the bound of %d", len(names), sshMaxNames)
	}
	if !truncated {
		t.Error("the list was truncated and truncated is false, so the loss is invisible")
	}
	for _, n := range names {
		if len(n) > sshMaxNameLen {
			t.Errorf("a name of %d bytes survived the per-name bound", len(n))
		}
	}
}
