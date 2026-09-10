package credscan

import (
	"strings"
	"testing"
)

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

func TestCredentialedTruth(t *testing.T) {
	pkgs := []Package{
		{Source: "openssl", Version: "3.0.2-0ubuntu1.6"}, // below the fix -> vulnerable
		{Source: "sudo", Version: "1.9.9-1ubuntu2.4"},    // at/above the fix -> not
		{Source: "bash", Version: "5.1-6ubuntu1"},        // no advisory at all
	}
	fixes := func(release, pkg string) ([]AdvisoryFix, error) {
		if release != "jammy" {
			t.Fatalf("truth queried release %q, want jammy", release)
		}
		switch pkg {
		case "openssl":
			return []AdvisoryFix{
				{AdvisoryRef: "USN-5710-1", FixedVersion: "3.0.2-0ubuntu1.7", Comparator: "dpkg"},
				{AdvisoryRef: "USN-BAD", FixedVersion: "", Comparator: "dpkg"},         // empty -> skipped
				{AdvisoryRef: "USN-RPM", FixedVersion: "3.0.2", Comparator: "rpm-ish"}, // unknown -> skipped
			}, nil
		case "sudo":
			return []AdvisoryFix{
				{AdvisoryRef: "USN-5811-1", FixedVersion: "1.9.9-1ubuntu2.4", Comparator: "dpkg"},
			}, nil
		default:
			return nil, nil
		}
	}
	vulns := func(ref string) ([]string, error) {
		if ref == "USN-5710-1" {
			return []string{"CVE-2022-3602", "CVE-2022-3786"}, nil // one advisory, two CVEs
		}
		return nil, nil
	}
	res, err := CredentialedTruth(pkgs, "jammy", fixes, vulns)
	if err != nil {
		t.Fatalf("truth: %v", err)
	}
	if len(res.Keys) != 2 {
		t.Fatalf("truth keys = %+v, want 2 (openssl x2 CVE)", res.Keys)
	}
	if res.Keys[0].Package != "openssl" || res.Keys[0].CVE != "CVE-2022-3602" {
		t.Errorf("first key = %+v", res.Keys[0])
	}
	if len(res.Skipped) != 2 { // empty fixed_version + unknown comparator
		t.Errorf("skipped = %+v, want 2", res.Skipped)
	}
}

func TestBuildServiceVersion(t *testing.T) {
	installed := map[string]string{
		"openssl":   "3.0.2-0ubuntu1.10",
		"mysql-8.0": "8.0.35-0ubuntu0.22.04.1",
		"apache2":   "2.4.52-1ubuntu4.7",
	}
	// consistent with an installed candidate (upstream prefix) -> right, and picks it
	sv := BuildServiceVersion("mysql", "MySQL", "8.0.35", []string{"mysql-5.7", "mysql-8.0"}, installed)
	if sv.SourcePackage != "mysql-8.0" || sv.InstalledVersion != "8.0.35-0ubuntu0.22.04.1" {
		t.Errorf("consistent match wrong: %+v", sv)
	}
	if ClassifyVersion([]ServiceVersion{sv})[0].Verdict != VersionRight {
		t.Errorf("should classify right: %+v", sv)
	}
	// product maps to no installed candidate -> empty installed -> wrong
	sv = BuildServiceVersion("ftp", "vsftpd", "3.0.5", []string{"vsftpd"}, installed)
	if sv.InstalledVersion != "" {
		t.Errorf("no installed candidate should give empty installed: %+v", sv)
	}
	if ClassifyVersion([]ServiceVersion{sv})[0].Verdict != VersionWrong {
		t.Errorf("claimed version, package absent -> wrong: %+v", sv)
	}
	// installed but inconsistent -> reports the first installed, classifies wrong
	sv = BuildServiceVersion("http", "Apache", "9.9.9", []string{"apache2"}, installed)
	if sv.InstalledVersion != "2.4.52-1ubuntu4.7" {
		t.Errorf("inconsistent should still report installed: %+v", sv)
	}
	if ClassifyVersion([]ServiceVersion{sv})[0].Verdict != VersionWrong {
		t.Errorf("inconsistent -> wrong: %+v", sv)
	}
}

func TestReportRender(t *testing.T) {
	r := Report{
		Host:     "10.0.0.9",
		Release:  OSRelease{ID: "ubuntu", VersionID: "22.04", Codename: "jammy"},
		Packages: 512,
		Versions: ClassifyVersion([]ServiceVersion{
			{Service: "ssh", BannerVersion: "8.9p1", InstalledVersion: "1:8.9p1-3ubuntu0.6"}, // wrong
			{Service: "smtp", BannerVersion: "", InstalledVersion: "1.18"},                   // absent
		}),
		BandResolved:   "focal",
		ReleaseVerdict: CompareRelease("focal", "jammy"),
		Accuracy: Diff(
			[]FindingKey{{"mysql-5.7", "CVE-2023-1111"}},
			[]FindingKey{{"samba", "CVE-2017-7494"}},
		),
		TruthSkipped: []string{"empty fixed_version, USN-BAD / openssl"},
	}
	out := r.Render()
	for _, want := range []string{
		"right 0   wrong 1   absent 1",
		"band vote \"focal\"", "mismatch",
		"false positive 1   false negative 1",
		"mysql-5.7  CVE-2023-1111", // the FP is listed
		"samba  CVE-2017-7494",     // the FN is listed
		"is tuned against this sample",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n---\n%s", want, out)
		}
	}
}
