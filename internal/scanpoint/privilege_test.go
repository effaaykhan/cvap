package scanpoint

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

const unprivilegedStatus = `Name:	cvap-scanpoint
Uid:	65532	65532	65532	65532
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
NoNewPrivs:	1
`

func writeStatus(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "status")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestAnUnprivilegedStatusPasses: every set empty and no_new_privs set is the
// one shape that is accepted.
func TestAnUnprivilegedStatusPasses(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the euid check fires before the status is read")
	}
	if err := CheckUnprivileged(writeStatus(t, unprivilegedStatus)); err != nil {
		t.Fatalf("an unprivileged status was refused: %v", err)
	}
}

// TestAnyCapabilityOrMissingNoNewPrivsIsRefused: a single bit in any set the
// process HOLDS is a refusal, permitted included - NET_RAW (bit 13) permitted
// is one setcap away from effective - and so is no_new_privs being clear,
// which is what would let an exec confer one.
//
// mutate:subject internal/scanpoint/privilege.go
// mutate:test    ./internal/scanpoint/ -run TestAnUnprivilegedStatusPasses|TestAnyCapabilityOrMissingNoNewPrivsIsRefused|TestAStatusMissingALineIsNotTrusted|TestABoundingSetAloneIsNotAPrivilegeOnceNoNewPrivsIsSet|TestEnsureNoNewPrivsReexecsExactlyOnce
// mutate:case    the held capability sets are parsed but a non-zero set is accepted
// mutate:old     if held[field] && n != 0 {
// mutate:new     if false && held[field] && n != 0 {
// mutate:case    no_new_privs is read but a clear value is accepted
// mutate:old     if val != "1" {
// mutate:new     if false && val != "1" {
func TestAnyCapabilityOrMissingNoNewPrivsIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the euid check fires before the status is read")
	}
	cases := map[string]string{
		"NET_RAW effective":         "CapEff:\t0000000000000000\n|CapEff:\t0000000000002000\n",
		"NET_RAW permitted":         "CapPrm:\t0000000000000000\n|CapPrm:\t0000000000002000\n",
		"CHOWN permitted":           "CapPrm:\t0000000000000000\n|CapPrm:\t0000000000000001\n",
		"an ambient capability":     "CapAmb:\t0000000000000000\n|CapAmb:\t0000000000000001\n",
		"an inheritable capability": "CapInh:\t0000000000000000\n|CapInh:\t0000000000000001\n",
		"no_new_privs clear":        "NoNewPrivs:\t1\n|NoNewPrivs:\t0\n",
	}
	for name, sub := range cases {
		from, to, _ := cutPipe(sub)
		body := replaceOnce(t, unprivilegedStatus, from, to)
		err := CheckUnprivileged(writeStatus(t, body))
		if !errors.Is(err, ErrPrivileged) {
			t.Errorf("%s: want ErrPrivileged, got %v", name, err)
		}
	}
}

// TestABoundingSetAloneIsNotAPrivilegeOnceNoNewPrivsIsSet: a full bounding
// set is what every process outside a --cap-drop ALL container has, and a
// non-root process cannot empty it. It says what an exec could at most confer;
// with no_new_privs set an exec confers nothing, so it is not a refusal.
func TestABoundingSetAloneIsNotAPrivilegeOnceNoNewPrivsIsSet(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the euid check fires before the status is read")
	}
	body := replaceOnce(t, unprivilegedStatus, "CapBnd:\t0000000000000000\n", "CapBnd:\t000001ffffffffff\n")
	if err := CheckUnprivileged(writeStatus(t, body)); err != nil {
		t.Errorf("a full bounding set with no_new_privs set was refused: %v", err)
	}
	// ... but the same bounding set with no_new_privs clear is exactly the
	// shape that can gain, and is refused.
	body = replaceOnce(t, body, "NoNewPrivs:\t1\n", "NoNewPrivs:\t0\n")
	if err := CheckUnprivileged(writeStatus(t, body)); !errors.Is(err, ErrPrivileged) {
		t.Errorf("a full bounding set WITHOUT no_new_privs was accepted: %v", err)
	}
}

// TestEnsureNoNewPrivsReexecsExactlyOnce: with the flag clear it re-execs (and
// a re-exec that returns is a failure); with it set it does nothing; and a
// process that already re-exec'd and still reads clear is refused, not
// re-exec'd again. The real re-exec is exercised end to end by the e2e harness,
// which runs the built binary on the host where the flag starts clear.
func TestEnsureNoNewPrivsReexecsExactlyOnce(t *testing.T) {
	clear := writeStatus(t, replaceOnce(t, unprivilegedStatus, "NoNewPrivs:\t1\n", "NoNewPrivs:\t0\n"))
	set := writeStatus(t, unprivilegedStatus)
	calls := 0
	fake := func() error { calls++; return nil }
	if err := ensureNoNewPrivs(set, false, fake); err != nil || calls != 0 {
		t.Errorf("flag set: err=%v reexecs=%d, want nil and 0", err, calls)
	}
	if err := ensureNoNewPrivs(clear, false, fake); err == nil || calls != 1 {
		t.Errorf("flag clear: err=%v reexecs=%d, want an error (a re-exec that returned) and 1", err, calls)
	}
	calls = 0
	if err := ensureNoNewPrivs(clear, true, fake); !errors.Is(err, ErrPrivileged) || calls != 0 {
		t.Errorf("flag clear after a re-exec: err=%v reexecs=%d, want ErrPrivileged and 0", err, calls)
	}
	if err := ensureNoNewPrivs(clear, false, func() error { return errors.New("exec: boom") }); err == nil {
		t.Error("a failed re-exec was not an error")
	}
	if err := ensureNoNewPrivs(writeStatus(t, "Name:\tx\n"), false, fake); err == nil {
		t.Error("a status with no NoNewPrivs line was trusted")
	}
}

// TestAStatusMissingALineIsNotTrusted: absence of a Cap line is not emptiness.
func TestAStatusMissingALineIsNotTrusted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the euid check fires before the status is read")
	}
	body := replaceOnce(t, unprivilegedStatus, "CapBnd:\t0000000000000000\n", "")
	if err := CheckUnprivileged(writeStatus(t, body)); err == nil {
		t.Error("a status with no CapBnd line was accepted")
	}
	if err := CheckUnprivileged(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Error("an unreadable status was accepted")
	}
}

func cutPipe(s string) (string, string, bool) {
	for i := range s {
		if s[i] == '|' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

func replaceOnce(t *testing.T, s, from, to string) string {
	t.Helper()
	i := indexOf(s, from)
	if i < 0 {
		t.Fatalf("%q not in status", from)
	}
	return s[:i] + to + s[i+len(from):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
