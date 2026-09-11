package version

import (
	"strconv"
	"strings"
)

// Scheme selects a distribution's version-comparison semantics. dpkg and rpm are
// different algorithms (ADR-014); the caller must know which family a package
// came from, because comparing an RPM version with dpkg rules is silently wrong.
type Scheme int

const (
	SchemeDpkg Scheme = iota // Debian, Ubuntu and derivatives
	SchemeRPM                // RHEL, Fedora, SUSE, Amazon, and derivatives
)

// SchemeByName maps the comparator name a stored advisory row carries
// (advisory_fixed_packages.comparator, the version_comparator enum) to the
// Scheme the matcher must use. The name travels with the data because the feed
// that wrote the row is the only thing that knows which family the version is —
// a dpkg version compared with rpm rules is silently wrong (ADR-014, ADR-062).
// The bool is false for an unknown name: the matcher must refuse to guess a
// comparator rather than default to one, because a wrong default is a wrong
// verdict that looks right.
func SchemeByName(name string) (Scheme, bool) {
	switch name {
	case "dpkg":
		return SchemeDpkg, true
	case "rpm":
		return SchemeRPM, true
	default:
		return 0, false
	}
}

// Compare dispatches to the scheme's comparator and returns -1, 0 or +1.
func Compare(s Scheme, a, b string) int {
	if s == SchemeRPM {
		return compareRPMEVR(a, b)
	}
	return CompareDpkg(a, b)
}

// compareRPMEVR compares two full RPM epoch:version-release strings the way rpm's
// own rpmVersionCompare does, and the way CompareRPM (rpmvercmp) alone does NOT: it
// compares the epoch NUMERICALLY first (an absent epoch is 0), then rpmvercmp on the
// version, then rpmvercmp on the release. CompareRPM treats ':' and '-' as ordinary
// separators, so handing it a full EVR compares the epoch digit against the first
// version segment — which made a fully-patched host (installed "0:9.9p1-25…") read as
// below an epoch-less advisory fix ("9.9p1-25…") and produced credentialed false
// positives. Found by B26 — the rpm comparator against a real advisory on a real host
// (ADR-062 validated rpmvercmp against rpm's corpus, but never the EVR layer around
// it). CompareRPM (the validated rpmvercmp core) is unchanged; this adds the EVR
// splitting rpm itself performs.
func compareRPMEVR(a, b string) int {
	ea, va, ra := splitEVR(a)
	eb, vb, rb := splitEVR(b)
	if ea != eb {
		if ea < eb {
			return -1
		}
		return 1
	}
	if c := CompareRPM(va, vb); c != 0 {
		return c
	}
	return CompareRPM(ra, rb)
}

// splitEVR splits an RPM "[epoch:]version[-release]" into its parts. An absent epoch
// is 0 (rpm's rule); a non-numeric or absent epoch is treated as 0. Version and
// release split at the first '-' (an rpm version contains no '-'); an absent release
// is "".
func splitEVR(s string) (epoch int, version, release string) {
	if i := strings.IndexByte(s, ':'); i >= 0 {
		if e, err := strconv.Atoi(s[:i]); err == nil {
			epoch = e
		}
		s = s[i+1:]
	}
	if i := strings.IndexByte(s, '-'); i >= 0 {
		return epoch, s[:i], s[i+1:]
	}
	return epoch, s, ""
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
