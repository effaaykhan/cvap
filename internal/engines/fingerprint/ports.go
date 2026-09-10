package fingerprint

// ServicePorts is the default set of ports to identify when the runtime supplies
// none.
//
// ============================================================================
// A default that exists because Core cannot yet say which ports are open.
// ============================================================================
//
// The right input is discovery's own findings: a fingerprint job should be told
// "10.10.0.11 has 22, 80 and 443 open" and connect to exactly those. That needs
// the observation-to-asset-to-plan path, which is week 5's second half, so until
// then this engine falls back to a port list of its own and re-establishes what
// discovery already knew.
//
// The cost is a duplicated connect per port, which is exactly the sort of
// silently-doubled packet spend the budget exists to make visible — so it is
// recorded in ADR-048 as a named deferral rather than left as a default nobody
// questions. ToEngine.Ports is the field that closes it.
//
// Shorter than discovery's ~180. Discovery's job is to find anything listening;
// this one's is to identify what is worth identifying, and a chain of probes
// against every ephemeral port is the packet spend the cap exists to prevent.
func ServicePorts() []uint16 {
	return []uint16{
		21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143,
		389, 443, 445, 465, 514, 587, 631, 636, 993, 995,
		1433, 1521, 1723, 2049, 2121, 3000, 3306, 3389, 4443, 5000,
		5060, 5432, 5433, 5900, 5985, 6379, 8000, 8008, 8080, 8081,
		8443, 8888, 9000, 9200, 9443, 10443, 11211, 27017,
	}
}

// clientSpeaksFirst reports whether a protocol expects the CLIENT to open the
// conversation.
//
// ============================================================================
// Measured, not assumed. PostgreSQL is on this list because a connect to it
// returns nothing for three seconds.
// ============================================================================
//
// Used only to shorten the banner wait — see bannerWait. A port not on this list
// gets the full wait, so being wrong here costs a quarter of a second of
// patience and never costs an identification outright.
//
// HTTP and TLS are the two that matter most by volume. SMB, RDP, MSSQL and DNS
// are the same shape; MySQL is deliberately ABSENT because it does volunteer a
// handshake packet, and so are SSH, SMTP, FTP, POP3, IMAP and Telnet.
func clientSpeaksFirst(port uint16) bool {
	switch port {
	case 53, 80, 81, 88, 135, 139, 389, 443, 445, 636, 1433, 2049,
		3000, 3389, 4443, 5000, 5432, 5433, 5985, 6379, 8000, 8008,
		8080, 8081, 8443, 8888, 9000, 9200, 9443, 10443, 11211, 27017:
		return true
	default:
		return false
	}
}

// delaysGreeting reports whether a SERVER-speaks-first protocol may hold its
// greeting well past the normal one-second wait. SMTP is the measured case: exim
// delays its 220 until a reverse-DNS lookup of the connecting client completes —
// ~4s in the lab, above the 3s connect ceiling — so the 1s/connect-capped
// bannerWait missed it and dropped the release vote NON-DETERMINISTICALLY (ADR-083).
// Mail and FTP protocols classically do this client lookup on connect; SSH and MySQL
// greet immediately and are here only for symmetry with the discovery engine's
// greeter set (a fast greeter returns the instant it speaks, so the longer budget
// costs nothing on it). A port here gets maxBannerWait, ABOVE the connect cap,
// because greeting is a phase distinct from connecting.
func delaysGreeting(port uint16) bool {
	switch port {
	case 21, 22, 23, 25, 465, 587, 110, 995, 143, 993, 3306:
		return true
	default:
		return false
	}
}
