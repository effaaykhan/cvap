package version

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

// The oracle differential (ADR-062): compare our comparator against the
// distribution's OWN library over the corpus pairs — dpkg (libdpkg, same version
// logic as libapt) and rpm (librpm). This is the validation a static vendored
// corpus cannot be — agreement with the actual implementation, not with a fixed
// list "derived from the same understanding that produced it".
//
// Shape matches CVAP_REQUIRE_LAB: present -> runs and fails on any disagreement;
// absent -> SKIPS LOUDLY, naming what did not run; CVAP_REQUIRE_VERCMP_ORACLE=1
// (set in CI, which installs the tools) turns the skip into a failure so the gate
// cannot silently disappear.

func oracleRequired() bool { return os.Getenv("CVAP_REQUIRE_VERCMP_ORACLE") == "1" }

func skipOrFailOracle(t *testing.T, tool string) {
	t.Helper()
	msg := tool + " oracle did NOT run — the differential against the distribution's own library was skipped, so agreement with " + tool + " is UNVERIFIED"
	if oracleRequired() {
		t.Fatalf("CVAP_REQUIRE_VERCMP_ORACLE=1 but %s (install %s and re-run)", msg, tool)
	}
	t.Skip(msg + " (set CVAP_REQUIRE_VERCMP_ORACLE=1 in an environment with " + tool + " to make this fatal)")
}

// dpkgOracle asks dpkg itself. usable=false means dpkg refused the version (an
// invalid-by-design string) and the pair is not part of the differential.
func dpkgOracle(a, b string) (result int, usable bool) {
	run := func(op string) (holds, ok bool) {
		err := exec.Command("dpkg", "--compare-versions", "--", a, op, b).Run()
		if err == nil {
			return true, true
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ExitCode() == 1 {
			return false, true // dpkg ran and the relation is false
		}
		return false, false // dpkg errored — version invalid to it
	}
	if eq, ok := run("eq"); !ok {
		return 0, false
	} else if eq {
		return 0, true
	}
	if lt, ok := run("lt"); !ok {
		return 0, false
	} else if lt {
		return -1, true
	}
	return 1, true
}

func TestDpkgOracleDifferential(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		skipOrFailOracle(t, "dpkg")
		return
	}
	ran, mism := 0, 0
	for _, c := range loadDpkgCorpus(t) {
		want, usable := dpkgOracle(c.a, c.b)
		if !usable {
			continue
		}
		ran++
		if got := CompareDpkg(c.a, c.b); got != want {
			mism++
			t.Errorf("dpkg disagreement: CompareDpkg(%q,%q)=%d, dpkg says %d", c.a, c.b, got, want)
		}
	}
	t.Logf("dpkg oracle: %d/%d corpus pairs agree with libdpkg (%d disagreements)", ran-mism, ran, mism)
	if ran == 0 {
		t.Error("dpkg is present but zero pairs were compared — the oracle proved nothing")
	}
}

// rpmOracleTool finds an available librpm oracle: python3's rpm module (cleanest,
// prints -1/0/1) or rpmdev-vercmp.
func rpmOracleTool() (kind string, ok bool) {
	if _, err := exec.LookPath("python3"); err == nil {
		if exec.Command("python3", "-c", "import rpm").Run() == nil {
			return "python3-rpm", true
		}
	}
	if _, err := exec.LookPath("rpmdev-vercmp"); err == nil {
		return "rpmdev-vercmp", true
	}
	return "", false
}

func rpmOraclePy(a, b string) (int, bool) {
	out, err := exec.Command("python3", "-c",
		"import rpm,sys;print(rpm.labelCompare((None,sys.argv[1],None),(None,sys.argv[2],None)))",
		a, b).Output()
	if err != nil {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(out)))
	if err != nil {
		return 0, false
	}
	return sign(n), true
}

func TestRPMOracleDifferential(t *testing.T) {
	kind, ok := rpmOracleTool()
	if !ok {
		skipOrFailOracle(t, "librpm")
		return
	}
	if kind != "python3-rpm" {
		// rpmdev-vercmp exit codes vary across versions; the python module is the
		// authoritative oracle. Rather than trust a fragile exit code, skip loudly.
		skipOrFailOracle(t, "python3-rpm")
		return
	}
	ran, mism := 0, 0
	for _, c := range loadRPMCorpus(t) {
		want, usable := rpmOraclePy(c.a, c.b)
		if !usable {
			continue
		}
		ran++
		if got := CompareRPM(c.a, c.b); got != want {
			mism++
			t.Errorf("librpm disagreement: CompareRPM(%q,%q)=%d, librpm says %d", c.a, c.b, got, want)
		}
	}
	t.Logf("librpm oracle: %d/%d corpus pairs agree with librpm (%d disagreements)", ran-mism, ran, mism)
	if ran == 0 {
		t.Error("an rpm oracle is present but zero pairs were compared — the oracle proved nothing")
	}
}
