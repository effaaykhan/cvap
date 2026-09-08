// Package version compares distribution package versions for advisory matching
// (ADR-014). The comparator is ours — Core cannot shell out to dpkg/rpm, because
// it must compare an RHEL version from a Debian-based host and the answer must not
// depend on which tools that host happens to have. Getting it subtly wrong is a
// SILENT false negative — a vulnerable package judged safe — so each scheme is
// pinned by a labelled ordering corpus (the *_test.go files), the P3.1 gate.
package version

import "strings"

// CompareDpkg compares two Debian/Ubuntu versions with dpkg semantics and returns
// -1 (a<b), 0 (a==b) or +1 (a>b).
//
// A version is epoch:upstream-revision. The epoch (default 0) dominates; then the
// upstream part; then the revision — each of the last two by verrevcmp, dpkg's
// own algorithm, reproduced rather than approximated. The load-bearing detail is
// that an ABSENT revision sorts below any present one, so a backport revision
// (2.2.8-1ubuntu0.22) is correctly NEWER than bare upstream (2.2.8) — the exact
// case ADR-014 exists for.
func CompareDpkg(a, b string) int {
	ea, ua, ra := splitDpkg(a)
	eb, ub, rb := splitDpkg(b)
	if c := compareInt(ea, eb); c != 0 {
		return c
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

// splitDpkg breaks a version into (epoch, upstream, revision).
func splitDpkg(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		epoch = atoiOr0(v[:i])
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		revision = v[i+1:]
		upstream = v[:i]
	} else {
		upstream = v
	}
	return epoch, upstream, revision
}

func atoiOr0(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// order is dpkg's collating rank for one byte of the non-digit part: '~' sorts
// before everything including end-of-string, then end-of-string (0), then letters
// by byte value, then any other byte ABOVE letters. This is why 1.0~rc1 < 1.0 and
// 1.0 < 1.0a.
func order(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0 // digits never reach order(); handled numerically
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	default:
		return int(c) + 256
	}
}

// verrevcmp compares two version parts as alternating non-digit and digit runs:
// non-digit byte-by-byte via order() (end-of-string ranks 0), digit runs
// numerically with leading zeros stripped, and a longer digit run is larger.
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = order(a[i])
			}
			if j < len(b) {
				bc = order(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		firstDiff := 0
		for i < len(a) && isDigit(a[i]) && j < len(b) && isDigit(b[j]) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if i < len(a) && isDigit(a[i]) {
			return 1
		}
		if j < len(b) && isDigit(b[j]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func compareInt(a, b int) int { return sign(a - b) }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}
