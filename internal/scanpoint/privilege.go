package scanpoint

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// ErrPrivileged means this process holds a privilege the Scan Point must not.
var ErrPrivileged = errors.New("scanpoint: this process is privileged")

// prSetNoNewPrivs is PR_SET_NO_NEW_PRIVS (linux/prctl.h).
const prSetNoNewPrivs = 38

// reexecMarker is set in the environment of the one re-exec EnsureNoNewPrivs
// may perform, so a kernel that did not honour the flag cannot loop it.
const reexecMarker = "CVAP_SP_NO_NEW_PRIVS_REEXEC"

// EnsureNoNewPrivs makes this process one that can never gain a privilege:
// no_new_privs set on every task it has and every process it will ever exec
// (ADR-110 P3, ADR-111). Call it first thing in main, before any other
// goroutine has done work.
//
// no_new_privs is a per-TASK flag, inherited by what a task clones or execs.
// A prctl from a goroutine marks the one OS thread it happens to be on; the
// Go runtime already has others, the main thread's /proc/self/status would
// still read 0, and an engine exec'd from another thread would inherit
// nothing (measured: the e2e harness's scan point refused itself with
// "no_new_privs is not set" after a successful prctl). So when the flag is not
// yet set, this locks the calling goroutine to its thread, sets the flag on
// that thread, and re-executes /proc/self/exe from it: execve replaces the
// whole process with a single task - the caller - which carries the flag into
// the new image and everything after. The re-exec'd process reads the flag as
// set and returns at once. A deployment that already set it (docker
// --security-opt no-new-privileges) never re-execs.
func EnsureNoNewPrivs() error {
	return ensureNoNewPrivs("/proc/self/status", os.Getenv(reexecMarker) != "", func() error {
		runtime.LockOSThread()
		if _, _, e := syscall.Syscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
			return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", e)
		}
		env := append(os.Environ(), reexecMarker+"=1")
		// #nosec G204 G702 -- this re-executes THIS binary (/proc/self/exe, a fixed
		// path the kernel resolves) with this process's own arguments passed
		// through unchanged; nothing here is parsed, chosen or constructed from
		// input. It is the same program image, now under no_new_privs.
		return syscall.Exec("/proc/self/exe", os.Args, env)
	})
}

// ensureNoNewPrivs is EnsureNoNewPrivs with the status file and the re-exec
// injectable. A re-exec that returns is a re-exec that failed.
func ensureNoNewPrivs(statusPath string, reexeced bool, reexec func() error) error {
	set, err := noNewPrivs(statusPath)
	if err != nil {
		return err
	}
	if set {
		return nil
	}
	if reexeced {
		// We already re-executed ourselves under the flag and it still reads
		// clear: the kernel did not honour it. Not something to retry.
		return fmt.Errorf("%w: no_new_privs still clear after re-exec; refusing to run where an exec could gain a capability", ErrPrivileged)
	}
	if err := reexec(); err != nil {
		return fmt.Errorf("scanpoint: cannot re-exec under no_new_privs: %w", err)
	}
	return errors.New("scanpoint: re-exec returned without replacing the process")
}

// noNewPrivs reads the NoNewPrivs line of a status file.
func noNewPrivs(statusPath string) (bool, error) {
	// #nosec G304 -- /proc/self/status in production; a parameter for tests.
	f, err := os.Open(statusPath)
	if err != nil {
		return false, fmt.Errorf("scanpoint: cannot read no_new_privs: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "NoNewPrivs:"); ok {
			return strings.TrimSpace(v) == "1", nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, errors.New("scanpoint: capability state has no NoNewPrivs line; refusing to assume it is set")
}

// CheckUnprivileged refuses to run as root or with any capability, and makes
// sure none can be gained (ADR-110 P3, ADR-111).
//
// The kernel packet ceiling holds only because nothing in the Scan Point's
// namespace can reach around it: CAP_NET_RAW opens an AF_PACKET socket that
// bypasses the tc egress hook entirely (measured: 1,724 raw frames on the wire,
// policer count 0). The deployment is TOLD to drop everything (INSTALL §6b);
// this is where the Scan Point checks that it did, instead of trusting that it
// was run as written.
//
// Two halves. What this process HAS: the inheritable, permitted, effective and
// ambient sets must all be empty, and the euid must not be 0. What it could
// GAIN: no_new_privs must be set (EnsureNoNewPrivs, run first, makes it so);
// with it set no execve confers a capability, setuid bit or file capability
// alike, whatever the bounding set holds. So the bounding set is not required
// to be empty: a non-root process cannot empty it (that needs CAP_SETPCAP),
// and it is full for any process started outside a `--cap-drop ALL`
// container - a developer's host, the e2e harness - where no_new_privs gives
// the same guarantee. The deployed container empties it anyway, and the safety
// gate requires that of the deployed shape.
//
// statusPath is /proc/self/status; a parameter so a test can hand it a file.
func CheckUnprivileged(statusPath string) error {
	if os.Geteuid() == 0 {
		return fmt.Errorf("%w: running as root (euid 0); run with a non-root --user", ErrPrivileged)
	}
	// #nosec G304 -- the path is /proc/self/status from cmd/cvap-scanpoint; the
	// parameter exists so a test can hand this a fixture, not so a caller can
	// pick a file. There is no user-controlled input on this path.
	f, err := os.Open(statusPath)
	if err != nil {
		return fmt.Errorf("scanpoint: cannot read capability state: %w", err)
	}
	defer func() { _ = f.Close() }()
	return checkStatus(f)
}

// held are the sets that say what a process has now; the bounding set is what
// it could at most gain, which no_new_privs makes unreachable.
var held = map[string]bool{"CapInh": true, "CapPrm": true, "CapEff": true, "CapAmb": true}

// checkStatus reads the Cap* and NoNewPrivs lines of a /proc/<pid>/status.
func checkStatus(r *os.File) error {
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		field, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch field {
		case "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
			seen[field] = true
			n, err := strconv.ParseUint(val, 16, 64)
			if err != nil {
				return fmt.Errorf("scanpoint: cannot parse %s %q: %w", field, val, err)
			}
			if held[field] && n != 0 {
				return fmt.Errorf("%w: %s is %s, not 0; run with --cap-drop ALL (ADR-110 P3)", ErrPrivileged, field, val)
			}
		case "NoNewPrivs":
			seen[field] = true
			if val != "1" {
				return fmt.Errorf("%w: no_new_privs is not set, so an exec could still gain a capability (ADR-110 P3)", ErrPrivileged)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scanpoint: reading capability state: %w", err)
	}
	for _, f := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs"} {
		if !seen[f] {
			// A status without the line is not a status that proved anything.
			return fmt.Errorf("scanpoint: capability state has no %s line; refusing to assume it is empty", f)
		}
	}
	return nil
}
