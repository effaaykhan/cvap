// Package sshalgo is the ONE host-key algorithm preference CVAP offers an SSH
// server, shared by the two clients that meet the same host.
//
// The fingerprint engine records the host key a server presents in its own
// key exchange, and that fingerprint is the trust material the credentialed
// engine later verifies against (ADR-091, the observed source). A server holds
// several host keys — ed25519, RSA, ECDSA — and presents whichever the CLIENT
// prefers first. Two clients with two preference orders therefore see two
// different keys for one host, and the observed fingerprint verifies nothing:
// the first end-to-end run failed with "host key mismatch" for exactly that
// reason, the fingerprint engine having offered ed25519 first and the
// credentialed client x/crypto's default order.
//
// No imports, so the fingerprint engine (which deliberately does not depend on
// golang.org/x/crypto/ssh) and credscan (which does) can both take it.
package sshalgo

// HostKeyPreference is the order offered in KEXINIT, most preferred first. The
// server picks the first entry it holds a key for. ed25519 first because it is
// the key most Linux hosts have and the one an operator sees from
// `ssh-keygen -lf` by default; the rest broad, because for the fingerprint
// engine what the server picks is the evidence.
var HostKeyPreference = []string{
	"ssh-ed25519", "rsa-sha2-512", "rsa-sha2-256",
	"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
	"ssh-rsa", "ssh-dss",
}
