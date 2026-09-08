package version

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The vendored corpora are the real gate (ADR-062): they are the distributions'
// OWN test data (testdata/corpora/{rpm,dpkg}/, with PROVENANCE.md), so a pass is
// the comparator agreeing with rpm/dpkg's own understanding, not with ours. A
// parse that finds zero cases FAILS — a corpus that silently stopped being read
// is indistinguishable from one nobody wrote (the §5.5 presence lesson).
//
// Failures are collected and named individually, then the test fails once at the
// end. "Passes 847 of 850" must say which three — those are the edge cases a
// future refactor breaks, and "fixed, now passes" would erase them.

// One mutate:test per suite file (mutate.py keeps the last one), so it must run
// BOTH corpus tests — the dpkg mutations are killed by TestDpkgCorpus and the rpm
// one by TestRPMCorpus. A single -run regex covers both; splitting the test
// target across two mutate:test lines would silently run every mutation against
// only the last test, and a dpkg mutation checked by an rpm-only test survives.
//
// mutate:subject internal/version/dpkg.go
// mutate:test    ./internal/version/ -run TestDpkgCorpus|TestRPMCorpus
//
// mutate:case    the tilde loses its special rank, so a pre-release sorts above the release
// mutate:old     case c == '~':
// mutate:new     case c == '\a':
//
// mutate:case    the numeric first-difference is inverted, reversing equal-length digit runs
// mutate:old     firstDiff = int(a[i]) - int(b[j])
// mutate:new     firstDiff = int(b[j]) - int(a[i])
//
// mutate:subject internal/version/rpm.go
//
// mutate:case    the rpm tilde ordering is inverted, so a pre-release sorts above the release
// mutate:old     if !oneTilde {
// mutate:new     if oneTilde {

type corpusCase struct {
	a, b string
	want int
}

var rpmMacro = regexp.MustCompile(`RPMVERCMP\(\s*(.*?)\s*,\s*(.*?)\s*,\s*(-?\d+)\s*\)`)

func loadRPMCorpus(t *testing.T) []corpusCase {
	t.Helper()
	data, err := os.ReadFile("testdata/corpora/rpm/rpmvercmp.at")
	if err != nil {
		t.Fatalf("read rpm corpus: %v", err)
	}
	var out []corpusCase
	for _, m := range rpmMacro.FindAllStringSubmatch(string(data), -1) {
		want, err := strconv.Atoi(m[3])
		if err != nil {
			continue
		}
		out = append(out, corpusCase{m[1], m[2], want})
	}
	if len(out) == 0 {
		t.Fatal("rpm corpus parsed to ZERO cases — it stopped being read (testdata/corpora/rpm/rpmvercmp.at)")
	}
	return out
}

func loadDpkgCorpus(t *testing.T) []corpusCase {
	t.Helper()
	f, err := os.Open("testdata/corpora/dpkg/Dpkg_Version.t")
	if err != nil {
		t.Fatalf("read dpkg corpus: %v", err)
	}
	defer f.Close()
	var out []corpusCase
	sc := bufio.NewScanner(f)
	inData := false
	for sc.Scan() {
		line := sc.Text()
		if !inData {
			if strings.TrimSpace(line) == "__DATA__" {
				inData = true
			}
			continue
		}
		// The __DATA__ triples are `a b result`; anything else after __DATA__
		// (blank lines) is skipped, and a malformed result is skipped rather than
		// guessed.
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		want, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		out = append(out, corpusCase{fields[0], fields[1], want})
	}
	if len(out) == 0 {
		t.Fatal("dpkg corpus parsed to ZERO cases — it stopped being read (testdata/corpora/dpkg/Dpkg_Version.t)")
	}
	return out
}

func runCorpus(t *testing.T, name string, cases []corpusCase, cmp func(string, string) int) {
	t.Helper()
	var failures []string
	for _, c := range cases {
		if got := cmp(c.a, c.b); got != c.want {
			failures = append(failures, fmt.Sprintf("cmp(%q,%q)=%d want %d", c.a, c.b, got, c.want))
		}
		if got := cmp(c.b, c.a); got != -c.want {
			failures = append(failures, fmt.Sprintf("cmp(%q,%q)=%d want %d (reverse)", c.b, c.a, got, -c.want))
		}
	}
	checks := len(cases) * 2
	t.Logf("%s corpus: %d cases (%d directional checks), %d passed, %d failed",
		name, len(cases), checks, checks-len(failures), len(failures))
	for _, f := range failures {
		t.Errorf("%s: %s", name, f)
	}
}

func TestDpkgCorpus(t *testing.T) {
	runCorpus(t, "dpkg (Debian t-versions)", loadDpkgCorpus(t), CompareDpkg)
}

func TestRPMCorpus(t *testing.T) {
	runCorpus(t, "rpm (rpmvercmp.at)", loadRPMCorpus(t), CompareRPM)
}
