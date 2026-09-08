package version

// Scheme selects a distribution's version-comparison semantics. dpkg and rpm are
// different algorithms (ADR-014); the caller must know which family a package
// came from, because comparing an RPM version with dpkg rules is silently wrong.
type Scheme int

const (
	SchemeDpkg Scheme = iota // Debian, Ubuntu and derivatives
	SchemeRPM                // RHEL, Fedora, SUSE, Amazon, and derivatives
)

// Compare dispatches to the scheme's comparator and returns -1, 0 or +1.
func Compare(s Scheme, a, b string) int {
	if s == SchemeRPM {
		return CompareRPM(a, b)
	}
	return CompareDpkg(a, b)
}

// Op is a comparison operator an advisory uses to bound an affected version set.
type Op int

const (
	OpLT Op = iota // <
	OpLE           // <=
	OpGT           // >
	OpGE           // >=
	OpEQ           // ==
)

// Satisfies reports whether `version <op> ref` holds under the scheme — the
// less-than / greater-or-equal comparisons advisory data expresses directly.
func Satisfies(s Scheme, version string, op Op, ref string) bool {
	c := Compare(s, version, ref)
	switch op {
	case OpLT:
		return c < 0
	case OpLE:
		return c <= 0
	case OpGT:
		return c > 0
	case OpGE:
		return c >= 0
	case OpEQ:
		return c == 0
	default:
		return false
	}
}

// AffectedRange is the range form: a vendor advisory says a package is affected
// from Introduced (inclusive; "" = from the beginning) until Fixed (exclusive;
// "" = never fixed). This is ADR-014's ADVISORY_FIXED_PACKAGE shape — a host is
// vulnerable when its installed version is at or above Introduced and strictly
// below Fixed. The strict-below-Fixed is where the backport case lands:
// 2.2.8-1ubuntu0.22 is NOT below a fix of 2.2.8-1ubuntu0.22, so a patched host is
// correctly cleared.
type AffectedRange struct {
	Introduced string
	Fixed      string
}

// Vulnerable reports whether an installed version falls in the affected range.
func (r AffectedRange) Vulnerable(s Scheme, installed string) bool {
	if r.Introduced != "" && Compare(s, installed, r.Introduced) < 0 {
		return false
	}
	if r.Fixed != "" && Compare(s, installed, r.Fixed) >= 0 {
		return false
	}
	return true
}
