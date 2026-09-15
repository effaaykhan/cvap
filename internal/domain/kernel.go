package domain

import (
	"regexp"
	"strings"
)

// KernelInstallState is what an installed package is, seen against the kernel
// the host is actually running (B36, ADR-099).
//
// A Debian-family host keeps every installed kernel ABI's packages side by side
// (linux-image-7.0.0-30-generic next to linux-image-7.0.0-31-generic) and never
// "upgrades" one into the other; rpm does the same with installonly kernel
// packages. Collapsed to the source package the advisory keyspace uses, an old ABI
// reads as `linux` at the old version — below every later USN — on a host that
// has long since booted the fix. Measured on .146 (ADR-093): 551 credentialed
// kernel findings, all false, one USN. Ubuntu's own OVAL resolves this against
// `uname -r`; so does this.
//
// The classification is pure and shared: the correlator and the credentialed
// instrument's ground truth both call it, so the two cannot disagree (§5.2).
type KernelInstallState int

const (
	// NotKernel is an ordinary package: match it exactly as before.
	NotKernel KernelInstallState = iota
	// KernelRunning is a kernel package at the running kernel's version: match it.
	// The reboot-pending host — running ABI-30 with ABI-31 installed — is this
	// state for its ABI-30 packages, and that is the real exposure, kept visible.
	KernelRunning
	// KernelInstalledNotRunning is a kernel package at some other version:
	// inventory, not a finding. Its code is on disk and not executing.
	KernelInstalledNotRunning
	// KernelUnknown is a kernel package on a read that did not carry `uname -r`
	// (a pre-B36 observation): it cannot be judged either way, and the honest
	// outcome is to judge nothing rather than raise 551 findings that may be false.
	KernelUnknown
)

func (s KernelInstallState) String() string {
	switch s {
	case NotKernel:
		return "not-kernel"
	case KernelRunning:
		return "kernel-running"
	case KernelInstalledNotRunning:
		return "kernel-installed-not-running"
	case KernelUnknown:
		return "kernel-unknown"
	}
	return "kernel-state-?"
}

// debianABI matches the ABI a Debian-family kernel binary package carries in its
// NAME — the "-7.0.0-31" of linux-image-7.0.0-31-generic, linux-headers-7.0.0-31,
// linux-modules-6.8.0-45-generic. Packages from a kernel source with no ABI in the
// name (linux-libc-dev, linux-image-generic, linux-firmware) upgrade in place like
// any other package and are not kernel packages here.
var debianABI = regexp.MustCompile(`-(\d+\.\d+\.\d+-\d+)(-|$)`)

// debianReleaseABI is the ABI at the front of a Debian-family `uname -r`:
// "7.0.0-31" of "7.0.0-31-generic".
var debianReleaseABI = regexp.MustCompile(`^\d+\.\d+\.\d+-\d+`)

// rpmKernelVersion is a version-release that is itself a kernel release
// (5.14.0-503.14.1.el9_5): the shape rpm's installonly kernel packages carry, and
// the shape kernel-srpm-macros (1.0-13.el9) does not.
var rpmKernelVersion = regexp.MustCompile(`^\d+\.\d+\.\d+-\d+`)

// ClassifyKernelPackage classifies one installed package against the running
// kernel. kernelRelease is `uname -r` as read on the host ("" when the read did
// not carry it); source is the package the advisory keyspace matches on; binary is
// the installed package's own name (rpm: the same as source); version is the
// installed version as the package manager reports it.
//
// The match is by SHAPE, not by substring (the security review measured the
// substring form calling "7.0.0-3" the running kernel of linux-image-7.0.0-31-
// generic): the binary's ABI segment must equal the release's ABI, and what
// follows it must be the release's flavour ("-generic", optionally followed by
// "-dbgsym" and the like) or nothing (the flavourless linux-headers-<abi>).
func ClassifyKernelPackage(kernelRelease, source, binary, version string) KernelInstallState {
	switch {
	case (source == "linux" || strings.HasPrefix(source, "linux-")) && debianABI.MatchString(binary):
		if kernelRelease == "" {
			return KernelUnknown
		}
		abi := debianReleaseABI.FindString(kernelRelease)
		if abi == "" {
			return KernelUnknown
		}
		flavour := kernelRelease[len(abi):] // "-generic", "-aws", "" for a flavourless release
		m := debianABI.FindStringSubmatchIndex(binary)
		binaryABI := binary[m[2]:m[3]]
		rest := binary[m[3]:]
		if binaryABI != abi {
			return KernelInstalledNotRunning
		}
		if rest == "" || rest == flavour || (flavour != "" && strings.HasPrefix(rest, flavour+"-")) {
			return KernelRunning
		}
		return KernelInstalledNotRunning

	case (source == "kernel" || strings.HasPrefix(source, "kernel-")) && rpmKernelVersion.MatchString(stripEpoch(version)):
		// RHEL family: the version-release IS the kernel release, and `uname -r`
		// is that plus ".<arch>" — one lowercase token, no further dots.
		if kernelRelease == "" {
			return KernelUnknown
		}
		vr := stripEpoch(version)
		if kernelRelease == vr {
			return KernelRunning
		}
		if strings.HasPrefix(kernelRelease, vr+".") && rpmArch.MatchString(kernelRelease[len(vr)+1:]) {
			return KernelRunning
		}
		return KernelInstalledNotRunning
	}
	return NotKernel
}

// rpmArch is the arch suffix of an rpm `uname -r`: x86_64, aarch64, ppc64le, s390x.
var rpmArch = regexp.MustCompile(`^[a-z0-9_]{1,16}$`)

// stripEpoch drops a leading "N:" epoch from a package version.
func stripEpoch(v string) string {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		return v[i+1:]
	}
	return v
}

// KernelReleaseValid bounds `uname -r` the way ReleaseTokenValid bounds the
// os-release fields (ADR-095): target-controlled text that reaches Core is a
// short token or the read is refused. Kernel releases carry '+' (a backport,
// a local build) and, unlike os-release IDs, may carry uppercase.
func KernelReleaseValid(v string) bool {
	if v == "" || len(v) > MaxReleaseTokenLen {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
			c == '.' || c == '_' || c == '-' || c == '+' || c == '~' {
			continue
		}
		return false
	}
	return true
}
