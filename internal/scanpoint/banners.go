package scanpoint

import "github.com/effaaykhan/cvap/internal/enginewire"

// Banner matches: what a service says before anyone asks it anything.
//
// ============================================================================
// Reading is not sending. These travel in SAFE mode, and probes do not.
// ============================================================================
//
// Seven of the nine services in the week 5 brief announce themselves on connect,
// and identifying those costs nothing and provokes nothing — a connect and a
// bounded read, which discovery already performs. That is the whole safe-mode
// service identification story, and it is why the safe/intrusive line is drawn
// at the probe corpus rather than here.
//
// # Two of the nine do NOT volunteer, and saying so is the point
//
// PostgreSQL and MSSQL are in the brief's banner list and belong in the probe
// list instead. Measured rather than assumed: a connect to postgres:5432 and a
// three-second read returns nothing at all — the protocol has the client speak
// first, so there is no banner to parse in any mode. MSSQL's TDS is the same
// shape. Both are in ProbeCorpus, which means they are identified under an
// intrusive job and not under a safe one, and the honest consequence is that
// safe mode finds an open 5432 with no service attached.
//
// Left as a comment claiming they volunteer, this would have been a matcher that
// silently never fired.
//
// # Patterns run against RAW bytes, latin-1 mapped
//
// A banner is not text: MySQL's handshake is a length-prefixed binary packet and
// Telnet opens with IAC option negotiation. The engine maps each response byte to
// the rune of the same value before matching, so `\x00` and `\xff` in a pattern
// mean those bytes and `.` means exactly one byte. Matching the UTF-8 encoding of
// a string built from hostile bytes would mean `\xff` never matched anything,
// which is a rule that quietly does nothing.
//
// # Ports scope a match for the same reason they scope a probe
//
// `220 ` opens both SMTP and FTP, and no amount of pattern work disambiguates
// them from the bytes alone. A generic rule therefore carries the ports it
// applies to; a rule that names a product does not need to.

// Confidence bands, so the numbers below mean the same thing in every rule.
//
// ADR-014 makes confidence decide how a finding is presented, so these are the
// difference between "nginx 1.27.5, here is its advisory" and "something that
// answers HTTP".
const (
	// The service named itself and gave a version. Little left to doubt.
	ConfExactVersion = 0.95

	// The service named itself and withheld the version — `server_tokens off`
	// and its equivalents.
	ConfProductOnly = 0.85

	// The protocol is certain and the product is not. A SOFTMATCH.
	ConfProtocolOnly = 0.70

	// The product was inferred from the SHAPE of a response rather than from
	// anything it claimed. Deliberately the lowest band that still reports:
	// shape evidence is real and it is not a self-description.
	ConfShape = 0.60
)

// BuiltinBannerMatches is the in-binary minimum, used when no signed pack is
// loaded and merged ahead of one when there is.
//
// In the binary rather than only in a pack because safe mode must identify
// something on a scan point that has never fetched anything, and because a
// corpus that arrives as content should not be the only thing standing between
// this build and "every port is unknown".
//
// Order matters: first hit wins, so a rule naming a product precedes the generic
// rule for its protocol.
func BuiltinBannerMatches() []enginewire.Match {
	return []enginewire.Match{
		// ---- SSH -------------------------------------------------------
		//
		// The OS hint is real and is exactly why OSHint carries a
		// non-authoritative flag downstream: `SSH-2.0-OpenSSH_8.9p1
		// Ubuntu-3ubuntu0.4` names the distribution, the patch level and the
		// vendor's own package version, which is precisely what ADR-014 wants
		// for advisory matching and precisely what must not be believed on its
		// own, because a banner is a string the host chose to send.
		{
			Pattern: `^SSH-2\.0-OpenSSH_(?P<version>[0-9][\w.]*)[ -]+(?P<info>[Uu]buntu\S*)`,
			Service: "ssh", Product: "OpenSSH", OSHint: "Ubuntu",
			Confidence: ConfExactVersion,
		},
		{
			Pattern: `^SSH-2\.0-OpenSSH_(?P<version>[0-9][\w.]*)[ -]+(?P<info>[Dd]ebian\S*)`,
			Service: "ssh", Product: "OpenSSH", OSHint: "Debian",
			Confidence: ConfExactVersion,
		},
		{
			// Measured against lab target-a5: `SSH-2.0-OpenSSH_10.3\r\n`.
			Pattern: `^SSH-2\.0-OpenSSH_(?P<version>[0-9][\w.]*)`,
			Service: "ssh", Product: "OpenSSH",
			Confidence: ConfExactVersion,
		},
		{
			Pattern: `^SSH-2\.0-dropbear_(?P<version>[\w.]+)`,
			Service: "ssh", Product: "Dropbear SSH",
			Confidence: ConfExactVersion,
		},
		{
			// Every SSH implementation must send this line; the part after the
			// second dash is free text. Protocol certain, product unknown.
			Pattern: `^SSH-(?P<info>\d+\.\d+)-`,
			Service: "ssh", Soft: true,
			Confidence: ConfProtocolOnly,
		},

		// ---- SMTP ------------------------------------------------------
		{
			Pattern: `^220[ -][^\r\n]*ESMTP Postfix`,
			Service: "smtp", Product: "Postfix",
			Confidence: ConfProductOnly,
		},
		{
			Pattern: `^220[ -][^\r\n]*ESMTP Exim (?P<version>[\d.]+)`,
			Service: "smtp", Product: "Exim",
			Confidence: ConfExactVersion,
		},
		{
			Pattern: `^220[ -][^\r\n]*Sendmail[ /](?P<version>[\d.]+)`,
			Service: "smtp", Product: "Sendmail",
			Confidence: ConfExactVersion,
		},
		{
			Pattern: `^220[ -][^\r\n]*Microsoft ESMTP MAIL Service[^\r\n]*Version: (?P<version>[\d.]+)`,
			Service: "smtp", Product: "Microsoft Exchange smtpd", OSHint: "Windows",
			Confidence: ConfExactVersion,
		},
		{
			// ESMTP in the greeting settles SMTP without naming the software.
			Pattern: `^220[ -][^\r\n]*(?:ESMTP|SMTP)`,
			Service: "smtp", Soft: true,
			Confidence: ConfProtocolOnly,
		},

		// ---- FTP -------------------------------------------------------
		{
			Pattern: `^220[ -][^\r\n]*vsFTPd (?P<version>[\d.]+)`,
			Service: "ftp", Product: "vsftpd",
			Confidence: ConfExactVersion,
		},
		{
			Pattern: `^220[ -]ProFTPD (?P<version>[\d.\w]+) Server`,
			Service: "ftp", Product: "ProFTPD",
			Confidence: ConfExactVersion,
		},
		{
			Pattern: `^220[ -][^\r\n]*FileZilla Server[ v]*(?P<version>[\d.]*)`,
			Service: "ftp", Product: "FileZilla ftpd", OSHint: "Windows",
			Confidence: ConfProductOnly,
		},
		{
			Pattern: `^220[ -][^\r\n]*Pure-FTPd`,
			Service: "ftp", Product: "Pure-FTPd",
			Confidence: ConfProductOnly,
		},
		{
			// The ambiguous one. `220` alone is SMTP or FTP and the bytes do not
			// say which, so this rule is scoped to the FTP ports and the SMTP
			// softmatch above is scoped by its ESMTP/SMTP keyword.
			Pattern: `^220[ -]`,
			Service: "ftp", Soft: true,
			Ports:      []uint32{21, 990, 2121},
			Confidence: ConfProtocolOnly,
		},

		// ---- POP3 / IMAP -----------------------------------------------
		{
			Pattern: `^\+OK[^\r\n]*Dovecot`,
			Service: "pop3", Product: "Dovecot pop3d",
			Confidence: ConfProductOnly,
		},
		{
			Pattern: `^\+OK`,
			Service: "pop3", Soft: true,
			Ports:      []uint32{110, 995},
			Confidence: ConfProtocolOnly,
		},
		{
			Pattern: `^\* OK[^\r\n]*Dovecot`,
			Service: "imap", Product: "Dovecot imapd",
			Confidence: ConfProductOnly,
		},
		{
			// IMAP4rev1 in the greeting is protocol evidence rather than a port
			// prior, so this one needs no port scope.
			Pattern: `^\* OK[^\r\n]*IMAP4rev1`,
			Service: "imap", Soft: true,
			Confidence: ConfProtocolOnly,
		},
		{
			Pattern: `^\* OK`,
			Service: "imap", Soft: true,
			Ports:      []uint32{143, 993},
			Confidence: ConfProtocolOnly,
		},

		// ---- Telnet ----------------------------------------------------
		{
			// IAC (0xff) followed by WILL/WONT/DO/DONT (0xfb-0xfe). This is the
			// pattern that forces latin-1 mapping: as UTF-8, `\xff` is two bytes
			// and matches nothing a Telnet server ever sends.
			Pattern: `^\xff[\xfb-\xfe]`,
			Service: "telnet", Soft: true,
			Confidence: ConfProtocolOnly,
		},

		// ---- MySQL / MariaDB -------------------------------------------
		//
		// A handshake packet, not text: three length bytes, a sequence byte, then
		// protocol version 10 and a NUL-terminated version string. MariaDB
		// announces itself inside that string, so it precedes the MySQL rule.
		{
			Pattern: `(?s)^...\x00\x0a(?P<version>[0-9][^\x00]*MariaDB[^\x00]*)\x00`,
			Service: "mysql", Product: "MariaDB",
			Confidence: ConfExactVersion,
		},
		{
			Pattern: `(?s)^...\x00\x0a(?P<version>[0-9][^\x00]*)\x00`,
			Service: "mysql", Product: "MySQL",
			Confidence: ConfExactVersion,
		},
		{
			// The other thing a MySQL server says on connect: a refusal, which
			// identifies it just as well and is the common answer to a scanner.
			Pattern: `(?s)^...\xff.{2}(?P<info>[Hh]ost [^\x00]*is not allowed to connect)`,
			Service: "mysql", Product: "MySQL",
			Confidence: ConfProductOnly,
		},
	}
}
