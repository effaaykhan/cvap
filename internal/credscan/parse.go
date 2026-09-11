// Package credscan is the credentialed validation instrument (ADR-075/076): it
// reads a Linux host's package inventory and release over SSH and measures the
// unauthenticated pipeline's findings against that credentialed ground truth.
//
// This package is pure and host-independent — parsers and comparison logic,
// fixture-tested. The SSH read and the store-backed matching are wired by the
// measurement command; nothing here opens a socket or holds a credential (the
// credential is the runtime's, ADR-027/076).
package credscan

import (
	"fmt"
	"strings"
)

// DpkgQueryFormat is the exact dpkg-query field format the instrument requests.
// SOURCE package first because advisories are keyed on the source package
// (advisory_fixed_packages.package_name, ADR-014), not the binary; the binary
// name and version are carried too so the read is legible to a human.
const DpkgQueryFormat = `${source:Package}\t${binary:Package}\t${Version}\t${Architecture}\n`

// DpkgQueryCommand is the full command the instrument runs over the session. It
// reads inventory and nothing else — no impact (non-negotiable #9).
const DpkgQueryCommand = `dpkg-query -W -f='` + DpkgQueryFormat + `'`

// Package is one installed package as the package manager reports it. Source is
// what advisory matching keys on; Binary/Version/Arch are the installed reality.
type Package struct {
	Source  string
	Binary  string
	Version string
	Arch    string
}

// ParseDpkgQuery parses the tab-separated output of DpkgQueryCommand. A line with
// the wrong field count is a REFUSAL, not a skip: a malformed inventory read is
// silent under-reporting, and the whole point of the instrument is to be measured
// against — a dropped line would corrupt the ground truth it exists to provide.
func ParseDpkgQuery(out string) ([]Package, error) {
	var pkgs []Package
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 4 {
			return nil, fmt.Errorf("dpkg-query line %d has %d fields, want 4: %q", i+1, len(f), line)
		}
		src := strings.TrimSpace(f[0])
		bin := strings.TrimSpace(f[1])
		// dpkg leaves ${source:Package} empty when the source name equals the
		// binary name; fall back so Source is always populated for matching.
		if src == "" {
			src = bin
		}
		pkgs = append(pkgs, Package{
			Source: src, Binary: bin,
			Version: strings.TrimSpace(f[2]), Arch: strings.TrimSpace(f[3]),
		})
	}
	return pkgs, nil
}

// RpmQaCommand reads the rpm inventory on a RHEL-family host — name, epoch:version-
// release, arch. EPOCHNUM prints 0 (not empty) when there is no epoch, so the version
// is always a well-formed rpm version the CompareRPM comparator (ADR-062) can read.
// A read, no impact (non-negotiable #9).
const RpmQaCommand = `rpm -qa --qf '%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\n'`

// ParseRpmQa parses RpmQaCommand output. rpm -qa lists BINARY package names; advisory
// data (ALSA) keys on those names, so Source and Binary are both the rpm name. Same
// refuse-don't-skip discipline as ParseDpkgQuery — a dropped line is silent
// under-reporting of the ground truth.
func ParseRpmQa(out string) ([]Package, error) {
	var pkgs []Package
	for i, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 3 {
			return nil, fmt.Errorf("rpm -qa line %d has %d fields, want 3: %q", i+1, len(f), line)
		}
		name := strings.TrimSpace(f[0])
		pkgs = append(pkgs, Package{
			Source: name, Binary: name,
			Version: strings.TrimSpace(f[1]), Arch: strings.TrimSpace(f[2]),
		})
	}
	return pkgs, nil
}

// OSRelease is what /etc/os-release reports — the EXACT release, not band-inferred
// (ADR-076). Codename is what advisory matching uses (hardy, jammy); VersionID and
// ID are carried for legibility and family.
type OSRelease struct {
	ID        string // "ubuntu", "debian", "rocky", ...
	VersionID string // "22.04"
	Codename  string // "jammy"
	raw       map[string]string
}

// Get returns any os-release key (uppercase), for keys OSRelease does not name.
func (r OSRelease) Get(key string) string { return r.raw[key] }

// IsRPMFamily reports whether the host uses rpm (RHEL family) rather than dpkg. It
// checks ID and ID_LIKE, so a derivative (AlmaLinux, Rocky) that sets ID_LIKE=rhel
// is recognised without an exhaustive ID list.
func (r OSRelease) IsRPMFamily() bool {
	hay := " " + r.ID + " " + r.raw["ID_LIKE"] + " "
	for _, k := range []string{"rhel", "fedora", "centos", "almalinux", "rocky", "suse"} {
		if strings.Contains(hay, k) {
			return true
		}
	}
	return false
}

// ParseOsRelease parses /etc/os-release (KEY=VALUE, optionally quoted). It errors
// only if ID cannot be found — a release with no ID is not a release this
// instrument can attribute, and guessing one is exactly the inference it exists to
// replace.
func ParseOsRelease(out string) (OSRelease, error) {
	r := OSRelease{raw: map[string]string{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue // os-release tolerates stray lines; only KEY=VALUE is data
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		r.raw[k] = v
	}
	r.ID = r.raw["ID"]
	r.VersionID = r.raw["VERSION_ID"]
	r.Codename = r.raw["VERSION_CODENAME"]
	if r.ID == "" {
		return OSRelease{}, fmt.Errorf("os-release has no ID field")
	}
	return r, nil
}
