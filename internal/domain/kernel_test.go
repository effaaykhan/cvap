package domain

import "testing"

// The kernel matcher's blind spot (B36): a Debian-family host keeps every
// installed kernel ABI's packages side by side and never "upgrades" them, so an
// inventory collapsed to source packages reports `linux` at the OLD ABI's version
// too, and the exact matcher reads that as below every later USN. Measured on
// .146: 551 credentialed kernel findings on a host running the fixed kernel, all
// from leftover ABI-30 packages. Only `uname -r` says which kernel runs, and this
// classification is the one place that reads it — the instrument's truth and the
// correlator both call it, so they cannot disagree (§5.2).
func TestClassifyKernelPackage(t *testing.T) {
	cases := []struct {
		name                      string
		kernel, source, binary, v string
		want                      KernelInstallState
	}{
		// Ubuntu, running 7.0.0-31-generic. The ABI-31 packages are the running
		// kernel; the ABI-30 leftovers are installed and not running.
		{"ubuntu image, running", "7.0.0-31-generic", "linux-signed", "linux-image-7.0.0-31-generic", "7.0.0-31.31", KernelRunning},
		{"ubuntu unsigned image, running", "7.0.0-31-generic", "linux", "linux-image-unsigned-7.0.0-31-generic", "7.0.0-31.31", KernelRunning},
		{"ubuntu modules, running", "7.0.0-31-generic", "linux", "linux-modules-7.0.0-31-generic", "7.0.0-31.31", KernelRunning},
		{"ubuntu flavourless headers, running ABI", "7.0.0-31-generic", "linux", "linux-headers-7.0.0-31", "7.0.0-31.31", KernelRunning},
		{"ubuntu image, old ABI left behind", "7.0.0-31-generic", "linux", "linux-image-unsigned-7.0.0-30-generic", "7.0.0-30.30", KernelInstalledNotRunning},
		{"ubuntu modules, old ABI left behind", "7.0.0-31-generic", "linux", "linux-modules-7.0.0-30-generic", "7.0.0-30.30", KernelInstalledNotRunning},
		{"ubuntu headers, old ABI left behind", "7.0.0-31-generic", "linux", "linux-headers-7.0.0-30", "7.0.0-30.30", KernelInstalledNotRunning},
		// The reboot-pending case is the real exposure and must NOT be hidden:
		// the host runs ABI-30 with ABI-31 installed; ABI-30 is the running one.
		{"reboot pending: running old ABI", "7.0.0-30-generic", "linux", "linux-modules-7.0.0-30-generic", "7.0.0-30.30", KernelRunning},
		{"reboot pending: newer ABI installed, not running", "7.0.0-30-generic", "linux", "linux-modules-7.0.0-31-generic", "7.0.0-31.31", KernelInstalledNotRunning},
		// Same ABI, different flavour: installed, not what runs.
		{"other flavour at the running ABI", "7.0.0-31-generic", "linux", "linux-image-7.0.0-31-lowlatency", "7.0.0-31.31", KernelInstalledNotRunning},
		// HWE and cloud kernels: the source name varies, the ABI segment decides.
		{"hwe kernel, running", "6.8.0-45-generic", "linux-hwe-6.8", "linux-modules-6.8.0-45-generic", "6.8.0-45.45~22.04.1", KernelRunning},
		{"aws kernel, old ABI", "6.8.0-1015-aws", "linux-aws", "linux-image-6.8.0-1014-aws", "6.8.0-1014.15", KernelInstalledNotRunning},
		// Kernel-source packages with NO ABI in the binary name upgrade in place
		// like any other package: linux-libc-dev, the meta packages, firmware.
		{"linux-libc-dev is an ordinary package", "7.0.0-31-generic", "linux", "linux-libc-dev", "7.0.0-31.31", NotKernel},
		{"meta package is ordinary", "7.0.0-31-generic", "linux-meta", "linux-image-generic", "7.0.0.31.31", NotKernel},
		{"linux-firmware is ordinary", "7.0.0-31-generic", "linux-firmware", "linux-firmware", "20260101.1", NotKernel},
		// A package that merely starts with "linux" but is not a kernel source.
		{"linux-base is ordinary", "7.0.0-31-generic", "linux-base", "linux-base", "4.9", NotKernel},
		// RHEL family: rpm keeps kernel versions side by side too, and the version
		// IS the kernel release (uname -r minus the arch suffix).
		{"rpm kernel-core, running", "5.14.0-503.14.1.el9_5.x86_64", "kernel-core", "kernel-core", "0:5.14.0-503.14.1.el9_5", KernelRunning},
		{"rpm kernel-modules, older, installed", "5.14.0-503.14.1.el9_5.x86_64", "kernel-modules", "kernel-modules", "0:5.14.0-427.13.1.el9_4", KernelInstalledNotRunning},
		{"rpm kernel (meta name), running", "5.14.0-503.14.1.el9_5.x86_64", "kernel", "kernel", "0:5.14.0-503.14.1.el9_5", KernelRunning},
		{"rpm kernel-srpm-macros is ordinary", "5.14.0-503.14.1.el9_5.x86_64", "kernel-srpm-macros", "kernel-srpm-macros", "0:1.0-13.el9", NotKernel},
		// No kernel release read (a pre-B36 observation, or the instrument's
		// older shape): a kernel package cannot be judged either way.
		{"no uname: kernel package unknown", "", "linux", "linux-modules-7.0.0-30-generic", "7.0.0-30.30", KernelUnknown},
		{"no uname: ordinary package still ordinary", "", "openssh", "openssh-server", "1:9.6p1-3", NotKernel},
		// Anything else is an ordinary package.
		{"ordinary package", "7.0.0-31-generic", "openssh", "openssh-server", "1:9.6p1-3", NotKernel},
		// The security review's adversarial shapes: the match is by ABI segment
		// and flavour, never by substring, and only kernel sources qualify.
		{"prefix collision: 7.0.0-3 is not 7.0.0-31", "7.0.0-3", "linux", "linux-image-7.0.0-31-generic", "7.0.0-31.31", KernelInstalledNotRunning},
		{"running ABI as a trailing decoration is not the ABI", "7.0.0-31-generic", "linux", "linux-modules-6.8.0-45-generic-7.0.0-31", "6.8.0-45.45", KernelInstalledNotRunning},
		{"dbgsym of the running kernel", "7.0.0-31-generic", "linux", "linux-image-7.0.0-31-generic-dbgsym", "7.0.0-31.31", KernelRunning},
		{"flavourless release, flavoured binary", "7.0.0-31", "linux", "linux-image-7.0.0-31-generic", "7.0.0-31.31", KernelInstalledNotRunning},
		{"source that merely starts with linux", "7.0.0-31-generic", "linuxfoo", "linuxfoo-7.0.0-31-generic", "7.0.0-31.31", NotKernel},
		{"source that merely starts with kernel", "5.14.0-503.14.1.el9_5.x86_64", "kernelfoo", "kernelfoo", "0:5.14.0-503.14.1.el9_5", NotKernel},
		{"rpm uname with a non-arch suffix", "5.14.0-503.14.1.el9_5.SOMETHING.ELSE", "kernel", "kernel", "0:5.14.0-503.14.1.el9_5", KernelInstalledNotRunning},
		{"rpm uname naming no installed version", "9.9.9-1.el9.x86_64", "kernel-core", "kernel-core", "0:5.14.0-503.14.1.el9_5", KernelInstalledNotRunning},
	}
	for _, c := range cases {
		if got := ClassifyKernelPackage(c.kernel, c.source, c.binary, c.v); got != c.want {
			t.Errorf("%s: ClassifyKernelPackage(%q, %q, %q, %q) = %v, want %v",
				c.name, c.kernel, c.source, c.binary, c.v, got, c.want)
		}
	}
}

// The kernel release is target-controlled text that reaches Core; it is bounded
// like the os-release tokens (ADR-095) so a lying host cannot push a novel or
// unbounded value through the read.
func TestKernelReleaseTokenValid(t *testing.T) {
	for _, ok := range []string{"7.0.0-31-generic", "5.14.0-503.14.1.el9_5.x86_64", "6.8.0-1015-aws", "6.12.1+bpo-amd64"} {
		if !KernelReleaseValid(ok) {
			t.Errorf("KernelReleaseValid(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "7.0.0-31 generic", "7.0.0-31-generic\n", "Linux 7.0.0", "7.0.0-31-generic;id", "x/y",
		"7.0.0-31-generic-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"} {
		if KernelReleaseValid(bad) {
			t.Errorf("KernelReleaseValid(%q) = true, want false", bad)
		}
	}
}
