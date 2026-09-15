package credscan

import (
	"strings"
	"testing"
)

// The three attribution fields are target-controlled and, under ADR-095, are
// never overwritten by an inferred sweep once recorded. A host that reports a
// release outside os-release's token grammar is refused, not attributed.
func TestParseOsReleaseRefusesUnboundedAttributionTokens(t *testing.T) {
	ok := "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n"
	if _, err := ParseOsRelease(ok); err != nil {
		t.Fatalf("a normal os-release refused: %v", err)
	}
	for name, body := range map[string]string{
		"uppercase": "ID=Ubuntu\n",
		"space":     "ID=\"ubuntu linux\"\n",
		"slash":     "ID=ubuntu\nVERSION_CODENAME=../etc\n",
		"too long":  "ID=" + strings.Repeat("a", MaxReleaseTokenLen+1) + "\n",
		"quote":     "ID=ubuntu\nVERSION_ID='24\"04'\n",
		"non-ascii": "ID=ubuntü\n",
	} {
		if _, err := ParseOsRelease(body); err == nil {
			t.Errorf("%s: accepted a token outside [a-z0-9._-]{1,%d}", name, MaxReleaseTokenLen)
		}
	}
}

// `uname -r` is one target-controlled token that decides which installed kernel
// is matched (ADR-099): one line, bounded grammar, or the read is refused.
func TestParseUnameRefusesAnythingButOneKernelToken(t *testing.T) {
	for in, want := range map[string]string{
		"7.0.0-31-generic\n":              "7.0.0-31-generic",
		"  5.14.0-503.14.1.el9_5.x86_64 ": "5.14.0-503.14.1.el9_5.x86_64",
		"6.12.1+bpo-amd64\n":              "6.12.1+bpo-amd64",
	} {
		got, err := ParseUname(in)
		if err != nil || got != want {
			t.Errorf("ParseUname(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "\n", "7.0.0-31-generic\n7.0.0-30-generic\n", "Linux host 7.0.0-31-generic", "7.0.0-31-generic;echo", "../../x"} {
		if got, err := ParseUname(bad); err == nil {
			t.Errorf("ParseUname(%q) = %q, want a refusal", bad, got)
		}
	}
}
