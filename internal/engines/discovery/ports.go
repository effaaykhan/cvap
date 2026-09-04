package discovery

// The default port set.
//
// ============================================================================
// This is NOT the top 1000, and pretending otherwise would be the worse error.
// ============================================================================
//
// docs/execution-plan.md §2 asks for "top-1000 ports plus configurable". What is
// here is a curated ~180 chosen to cover every service the MVP's finding rules
// actually reason about — the plaintext protocols, the management interfaces,
// the database ports, the TLS endpoints — plus the common web and mail ports.
//
// The full top-1000 is empirical frequency data, not a range, and it belongs in
// a data file alongside the fingerprint corpus rather than as a literal in
// source. That is a data change rather than a code change and it is recorded as
// such in the execution plan; shipping a padded list that LOOKED like the top
// 1000 would make the gap invisible, which is the failure this codebase weighs
// heaviest.
//
// A job may override this entirely, which is the "plus configurable" half.

// DefaultPorts is what a job scans when it names none.
//
// Sorted, because the order packets go out in is the order a host sees them and
// an unsorted list makes a capture harder to read than it needs to be.
func DefaultPorts() []uint16 {
	out := make([]uint16, len(defaultPorts))
	copy(out, defaultPorts)
	return out
}

var defaultPorts = []uint16{
	7, 9, 13, 19, 21, 22, 23, 25, 26, 37, 53, 67, 68, 69, 70, 79, 80, 81, 82, 83,
	84, 88, 89, 102, 110, 111, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162,
	179, 199, 389, 427, 443, 444, 445, 465, 500, 502, 512, 513, 514, 515, 520,
	523, 548, 554, 587, 623, 626, 631, 636, 646, 873, 902, 990, 993, 995,
	1025, 1026, 1027, 1028, 1029, 1080, 1099, 1110, 1194, 1214, 1241, 1311,
	1352, 1433, 1434, 1521, 1720, 1723, 1741, 1755, 1801, 1883, 1900, 1911,
	1962, 2000, 2001, 2049, 2082, 2083, 2086, 2087, 2095, 2096, 2121, 2181,
	2222, 2375, 2376, 2379, 2380, 2404, 2483, 2484, 2638, 2701, 3000, 3128,
	3260, 3268, 3269, 3283, 3306, 3389, 3478, 3632, 3690, 3702, 4000, 4045,
	4369, 4443, 4444, 4500, 4567, 4711, 4786, 4840, 4848, 5000, 5001, 5006,
	5007, 5009, 5051, 5060, 5061, 5222, 5269, 5353, 5355, 5432, 5555, 5601,
	5631, 5632, 5666, 5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6001,
	6379, 6443, 6446, 6666, 6667, 7000, 7001, 7002, 7070, 7077, 7199, 7443,
	7474, 7547, 7657, 7777, 8000, 8005, 8008, 8009, 8010, 8020, 8042, 8080,
	8081, 8082, 8086, 8088, 8089, 8090, 8091, 8123, 8161, 8181, 8200, 8222,
	8443, 8500, 8530, 8531, 8649, 8686, 8787, 8834, 8880, 8888, 8983, 9000,
	9001, 9042, 9060, 9080, 9090, 9091, 9100, 9160, 9200, 9300, 9418, 9443,
	9600, 9990, 9999, 10000, 10250, 10255, 11211, 11214, 11215, 12345, 15672,
	16992, 16993, 20000, 27017, 27018, 27019, 28017, 32400, 49152, 50000,
	50070, 50075, 61616, 61621,
}

// HostDiscoveryPorts are tried to decide whether a host is alive at all.
//
// A short list on purpose. Host discovery answers one question — is anything
// there — and asking it with 180 connects per host would spend the rate budget
// on the question rather than on the answer. These are the ports most likely to
// be open on something worth scanning.
//
// A host that answers none of these and does not answer ICMP is reported as not
// alive, which is a statement about what was OBSERVED rather than a claim that
// nothing is there. A fully filtered host is indistinguishable from an absent
// one over TCP connect, and connect-scan-only cannot close that gap — see the
// deferral note in the ADR.
func HostDiscoveryPorts() []uint16 {
	return []uint16{80, 443, 22, 3389, 445, 8080, 21, 23, 25, 3306, 5432, 8443}
}
