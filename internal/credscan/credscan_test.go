package credscan

import "testing"

func TestParseDpkgQuery(t *testing.T) {
	// jammy-style output of DpkgQueryCommand; the third line has an empty
	// ${source:Package} (source name == binary), which must fall back to the binary.
	out := "openssl\topenssl\t3.0.2-0ubuntu1.10\tamd64\n" +
		"mysql-5.7\tmysql-server\t5.7.42-0ubuntu0.22.04.1\tamd64\n" +
		"\tbash\t5.1-6ubuntu1\tamd64\n" +
		"\n" // trailing blank tolerated
	pkgs, err := ParseDpkgQuery(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
	}
	if pkgs[1].Source != "mysql-5.7" || pkgs[1].Binary != "mysql-server" || pkgs[1].Version != "5.7.42-0ubuntu0.22.04.1" {
		t.Errorf("mysql row wrong: %+v", pkgs[1])
	}
	if pkgs[2].Source != "bash" { // empty source fell back to binary
		t.Errorf("empty source should fall back to binary, got %q", pkgs[2].Source)
	}
}

func TestParseDpkgQueryRefusesMalformed(t *testing.T) {
	// A line with the wrong field count is refused, never skipped — a dropped
	// inventory line corrupts the ground truth the instrument exists to be.
	if _, err := ParseDpkgQuery("openssl\t3.0.2\tamd64\n"); err == nil {
		t.Error("a 3-field line should be refused, not silently accepted")
	}
}

func TestParseOsRelease(t *testing.T) {
	out := `NAME="Ubuntu"
VERSION="22.04.4 LTS (Jammy Jellyfish)"
ID=ubuntu
VERSION_ID="22.04"
VERSION_CODENAME=jammy
# a comment
UBUNTU_CODENAME=jammy`
	r, err := ParseOsRelease(out)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.ID != "ubuntu" || r.VersionID != "22.04" || r.Codename != "jammy" {
		t.Errorf("parsed wrong: %+v", r)
	}
	if r.Get("UBUNTU_CODENAME") != "jammy" {
		t.Errorf("Get(UBUNTU_CODENAME) = %q", r.Get("UBUNTU_CODENAME"))
	}
	if _, err := ParseOsRelease("VERSION_ID=1\n"); err == nil {
		t.Error("os-release with no ID should be refused")
	}
}

func TestClassifyVersion(t *testing.T) {
	in := []ServiceVersion{
		{Service: "ftp", BannerVersion: "3.0.2-0ubuntu1.10", InstalledVersion: "3.0.2-0ubuntu1.10"}, // exact -> right
		{Service: "mysql", BannerVersion: "5.7.42", InstalledVersion: "5.7.42-0ubuntu0.22.04.1"},    // upstream prefix -> right
		{Service: "ssh", BannerVersion: "8.9p1", InstalledVersion: "1:8.9p1-3ubuntu0.6"},            // banner missed the epoch -> wrong
		{Service: "smtp", BannerVersion: "", InstalledVersion: "1.18.6"},                            // no banner version -> absent
		{Service: "http", BannerVersion: "2.4.52", InstalledVersion: ""},                            // claimed a version, package not installed -> wrong
	}
	got := ClassifyVersion(in)
	want := []VersionVerdict{VersionRight, VersionRight, VersionWrong, VersionAbsent, VersionWrong}
	for i := range want {
		if got[i].Verdict != want[i] {
			t.Errorf("%s: verdict %q, want %q", got[i].Service, got[i].Verdict, want[i])
		}
	}
	tally := TallyVersions(got)
	if tally.Right != 2 || tally.Wrong != 2 || tally.Absent != 1 {
		t.Errorf("tally = %+v, want right2 wrong2 absent1", tally)
	}
}

func TestCompareRelease(t *testing.T) {
	if v := CompareRelease("jammy", "jammy"); v != ReleaseMatch {
		t.Errorf("match: %q", v)
	}
	if v := CompareRelease("focal", "jammy"); v != ReleaseMismatch {
		t.Errorf("mismatch: %q", v)
	}
	if v := CompareRelease("", "jammy"); v != ReleaseUnresolved {
		t.Errorf("unresolved: %q", v)
	}
}

func TestDiff(t *testing.T) {
	unauth := []FindingKey{
		{"openssl", "CVE-2022-0778"},   // in truth -> TP
		{"mysql-5.7", "CVE-2023-1111"}, // not in truth -> FP (banner-inferred wrong package/version)
	}
	truth := []FindingKey{
		{"openssl", "cve-2022-0778"}, // same as unauth (case-normalised) -> TP
		{"samba", "CVE-2017-7494"},   // missed by unauth -> FN
		{"sudo", "CVE-2021-3156"},    // missed by unauth -> FN
	}
	a := Diff(unauth, truth)
	if len(a.TruePositive) != 1 || a.TruePositive[0].CVE != "CVE-2022-0778" {
		t.Errorf("TP = %+v, want 1 (openssl)", a.TruePositive)
	}
	if len(a.FalsePositive) != 1 || a.FalsePositive[0].Package != "mysql-5.7" {
		t.Errorf("FP = %+v, want 1 (mysql-5.7)", a.FalsePositive)
	}
	if len(a.FalseNegative) != 2 {
		t.Errorf("FN = %+v, want 2 (samba, sudo)", a.FalseNegative)
	}
}
