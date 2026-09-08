package version

import "bytes"

// CompareRPM compares two RPM versions with rpmvercmp semantics and returns -1,
// 0 or +1. These are NOT dpkg's and NOT lexicographic (ADR-014): segments are
// runs of digits or runs of letters, non-alphanumeric bytes are separators, a
// numeric segment outranks an alphabetic one, a longer numeric segment (after
// stripping leading zeros) wins, `~` sorts before everything, and `^` sorts a
// version above its base.
//
// This is a faithful port of rpm's own lib/rpmver.c rpmvercmp, reproduced rather
// than approximated — a subtly-wrong RPM compare is the same silent false
// negative dpkg's is, and it is pinned by Red Hat's own rpmvercmp test corpus in
// rpm_test.go.
func CompareRPM(a, b string) int {
	if a == b {
		return 0
	}
	one := []byte(a)
	two := []byte(b)
	i, j := 0, 0

	for i < len(one) || j < len(two) {
		// Skip separators — anything not alphanumeric, ~ or ^.
		for i < len(one) && !rpmAlnum(one[i]) && one[i] != '~' && one[i] != '^' {
			i++
		}
		for j < len(two) && !rpmAlnum(two[j]) && two[j] != '~' && two[j] != '^' {
			j++
		}

		// Tilde: sorts before everything, including a segment or end-of-string.
		oneTilde := i < len(one) && one[i] == '~'
		twoTilde := j < len(two) && two[j] == '~'
		if oneTilde || twoTilde {
			if !oneTilde {
				return 1
			}
			if !twoTilde {
				return -1
			}
			i++
			j++
			continue
		}

		// Caret: like tilde, except a version WITH a caret suffix outranks the
		// bare base version that ended.
		oneCaret := i < len(one) && one[i] == '^'
		twoCaret := j < len(two) && two[j] == '^'
		if oneCaret || twoCaret {
			if i >= len(one) {
				return -1
			}
			if j >= len(two) {
				return 1
			}
			if !oneCaret {
				return 1
			}
			if !twoCaret {
				return -1
			}
			i++
			j++
			continue
		}

		// If either ran out, the loop is done; the tail is settled below.
		if i >= len(one) || j >= len(two) {
			break
		}

		// Grab one wholly-numeric or wholly-alphabetic segment from each.
		startOne, startTwo := i, j
		var isnum bool
		if isDigit(one[i]) {
			for i < len(one) && isDigit(one[i]) {
				i++
			}
			for j < len(two) && isDigit(two[j]) {
				j++
			}
			isnum = true
		} else {
			for i < len(one) && rpmAlpha(one[i]) {
				i++
			}
			for j < len(two) && rpmAlpha(two[j]) {
				j++
			}
			isnum = false
		}

		segOne := one[startOne:i]
		segTwo := two[startTwo:j]

		// Different segment types at this position: `one` has a segment of its
		// type and `two` has none of it. A numeric segment outranks an alpha one.
		if len(segTwo) == 0 {
			if isnum {
				return 1
			}
			return -1
		}

		if isnum {
			segOne = stripLeadingZeros(segOne)
			segTwo = stripLeadingZeros(segTwo)
			if len(segOne) > len(segTwo) {
				return 1
			}
			if len(segTwo) > len(segOne) {
				return -1
			}
		}

		// Equal length (for numbers) or alpha: a byte comparison decides, and for
		// equal-length zero-stripped digit runs it is the same as numeric order.
		if rc := bytes.Compare(segOne, segTwo); rc != 0 {
			return sign(rc)
		}
	}

	switch {
	case i >= len(one) && j >= len(two):
		return 0
	case i >= len(one):
		return -1
	default:
		return 1
	}
}

func rpmAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func rpmAlnum(c byte) bool { return rpmAlpha(c) || isDigit(c) }

func stripLeadingZeros(b []byte) []byte {
	k := 0
	for k < len(b) && b[k] == '0' {
		k++
	}
	return b[k:]
}
