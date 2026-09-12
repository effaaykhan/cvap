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
