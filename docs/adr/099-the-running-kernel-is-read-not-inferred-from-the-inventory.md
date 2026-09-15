# ADR-099: The running kernel is read, not inferred from the inventory — `uname -r` is the third command, and a kernel package at any other version is inventory

**Status:** Accepted
**Date:** 2026-09-15
**Follows:** ADR-076 (the two read-only commands), ADR-087 (the rpm inventory), ADR-093 (the fleet
run that measured the defect), ADR-094 (the Phase 4 headline stated with the kernel class excluded).
**Closes:** B36 — the single largest measured error source in Phase 4, and the item that sat ahead of
any accuracy claim about credentialed findings.

## What was measured

ADR-093's ground truth: `.146` runs `7.0.0-31-generic`, is pinned to a snapshot with nothing
upgradable, and carried **551 credentialed kernel findings** — the CVE count of the one resolute
`linux` USN fixed at `7.0.0-31.31`, every one false. `.138` runs `7.0.0-30-generic` with `31.31`
installed and not yet booted, and carried the same 551, every one true. The matcher could not tell
the two hosts apart because nothing it read says which kernel is running.

The mechanism is Debian-family kernel packaging. The ABI is in the *binary* package name
(`linux-image-7.0.0-30-generic`, `linux-modules-7.0.0-30-generic`, `linux-headers-7.0.0-30`), so an
old ABI's packages stay installed beside the new one and never "upgrade" — they are removed by
autoremove, or not. The engine reports every binary under its *source* package, which is the key USNs
use and is right for every ordinary package; collapsed, `.146`'s inventory carries `linux` at
`7.0.0-30.30` as well as `7.0.0-31.31`, and `7.0.0-30.30` is below the USN. rpm has the same shape by a
different route: installonly kernel packages keep several versions side by side, and the version *is*
the kernel release. Ubuntu's own OVAL resolves both against `uname -r`. The backlog's unblocker asked
for a decision on the read set, then a rule: match kernel packages only at the running kernel's
version, hold the other installed versions as inventory.

Two things it would have been wrong to do. Collapsing to the newest installed version hides the
reboot-pending host — `.138` — which is the real exposure. And leaving the class excluded from the
headline indefinitely is §5.9: a gap disclosed twice and decided by nobody.

## Decision

**The read set is three commands.** `cat /etc/os-release`, **`uname -r`**, then `dpkg-query` or
`rpm -qa` (`credscan.ReadHost`). `uname -r` reads the kernel's own identity: no write, no impact
(non-negotiable #9), a single bounded token. `ParseUname` refuses more than one line or anything
outside `domain.KernelReleaseValid` — `[A-Za-z0-9._+~-]{1,64}`, the os-release grammar widened for
the `+` a backport or local build carries. A refusal, or a failed command, leaves the kernel
**unread** (`""`) rather than failing the read: Core's `KernelUnknown` is the designed "cannot say"
state, and the scan-safety audit measured that a fatal refusal let one in-scope host answering
`uname -r` with a paragraph blind the credentialed read of every host behind it in the job (host
jobs are not `reassign_safe`). The os-release refusal stays fatal because that value *keys* the
match; this one only filters one package class. ADR-095's two-site rule holds at Core: a value
that reached it outside the grammar is treated as unread too. The error names at most a token's
worth of the target-supplied value. `MaxPackages` (50 000) bounds the inventory at the read, where
a hostile host filling the 8 MiB stdout cap would otherwise emit an observation past the wire's
4 MiB message limit.

**The engine reports two more facts and decides nothing.** The `package` observation carries
`kernel_release` and, per installed row, `binary` — the installed package's own name, which is the
only place the inventory says which ABI a `linux` row belongs to. The engine still emits
observations only (non-negotiable #1); what a kernel row *means* is Core's.

**The decision is one pure function, and both readers call it.** `domain.ClassifyKernelPackage
(kernelRelease, source, binary, version)`:

| shape | state |
|---|---|
| Debian-family: source `linux*`, binary carries an ABI segment, and the binary names the running release (`-7.0.0-31-generic`) or ends with its ABI (`linux-headers-7.0.0-31`) | **KernelRunning** — matched |
| the same, at any other ABI or flavour | **KernelInstalledNotRunning** — inventory, raises nothing |
| rpm: name `kernel*`, version-release is itself a kernel release, and `uname -r` is it plus `.<arch>` | KernelRunning; otherwise KernelInstalledNotRunning |
| a kernel package on a read with no `kernel_release` (pre-ADR-099) | **KernelUnknown** — judged neither way |
| anything else, including `linux-libc-dev`, the `linux-image-generic` meta packages, `linux-firmware`, `kernel-srpm-macros` | **NotKernel** — matched as before, because these upgrade in place |

`correlate.evaluateCredentialed` and the instrument's `credscan.CredentialedTruth` both call it, so
the fleet path and the ground truth it is measured against cannot disagree about the kernel (§5.2,
two-writers-one-fact — avoided by having one). An installed-not-running or unknown kernel row is
also *not* "covered": an inferred kernel finding is left standing rather than refuted by a read that
judged nothing about it.

**A credentialed finding is the read's claim, so the read withdraws it.** Until now nothing closed a
credentialed finding: `closeRemediated` is keyed on re-observed endpoints, and a package finding has
none, so a package upgraded after its credentialed finding was raised — or a kernel rebooted onto the
fix — kept its finding open for ever, and `.146`'s 551 would have survived this ADR's matcher change
untouched. Now an open credentialed finding for a (package, cve) the current read no longer matches
is closed `remediated` with a transition stating the facts the loop established (which release and
kernel the read carried, which key it no longer matched) rather than a cause it did not. This is safe
for credentialed findings and would not be for network ones: a credentialed read is the whole
inventory (`ReadHost` refuses a partial or malformed one), so absence means gone, whereas an endpoint
not in a scan was merely not scanned.

The withdrawal is keyed to a **property**, not to a trigger, because the first two guards written
for it were keyed to the two triggers the first reviews reported and the security review then measured
three more ways "cannot say" was being spelled "remediated". The property: *this read produced a
positive judgement about the package, under a keyspace that knows it.* Concretely, a credentialed
finding on package P is withdrawn only when (a) the read no longer carries P at all — a credentialed
read is the whole inventory, so absence is removal — **or** P was judged: it had rows, at least one
was matched, and if any were kernel rows the running kernel was among them; **and** (b) the release
the read carries has at least one advisory fix row for P. So a read with no `uname -r`, a `uname -r`
naming no installed kernel (a container reporting its host's kernel, a custom build, one token from a
rooted host), and a release key the keyspace has no rows for (an upgrade whose advisories are not
imported, a host that renamed its release) all withdraw nothing — each was measured closing a true
finding before the rule was stated this way. The guard is by source, because `linux-libc-dev` shares
`linux` with the kernel rows. `MarkRemediated` reports whether it closed a row and the transition is
written only then; a reopen (`Upsert`'s `reopened`) writes its own `remediated → open` row, so the
history never ends on a remediation the host undid. The **newest** `package` observation in a host
group decides, not the first the sweep lists (oldest), since a read can now withdraw. The Debian ABI
match is by shape — the binary's ABI segment equals the release's and is followed by the release's
flavour or by nothing — not by substring, which called `7.0.0-3` the running kernel of
`linux-image-7.0.0-31-generic`.

What a lying host can do is unchanged in two directions and bounded in the third: it could always
hide a vulnerable kernel or invent one by lying in `dpkg-query` output, and it still can; it can now
also get its own earlier true claim withdrawn — by reporting a fixed version, which is the same lie —
but not by declining to answer, naming a kernel it does not carry, or renaming its release, because
those are "cannot say", and cannot-say is not remediated.

**What is not changed.** The source-package key stays: USNs are keyed on it and it is right for every
ordinary package. No inventory table is added; the observation is the inventory record, and the
console's credentialed section reads it. The reboot-pending case is a finding, on purpose.

## What was measured after

`TestALeftoverKernelABIIsInventoryNotAFinding` (integration, the shape `.146` carries — running
ABI-31 with ABI-30 rows beside it, one USN at `7.0.0-31.31`): no kernel finding at the fix; **one**
when the same inventory runs ABI-30; that one **remediated with a transition** when a later read
shows ABI-31 booted. `TestAReadWithoutTheRunningKernelJudgesNoKernelPackage`: a pre-ADR-099 payload
raises no kernel finding and still matches the ordinary packages beside it. `TestClassifyKernelPackage`
(24 shapes: Ubuntu generic/lowlatency/HWE/cloud, Debian, rpm, the meta and libc-dev packages, no
uname). `TestCredentialedTruth` extended with the same kernel pair, both kernels running in turn.
`TestCredentialedInventoryOverTheWire` asserts the engine's `kernel_release` equals the container's
own `uname -r`. Before the matcher change, the integration test raised one open kernel finding on the
host at the fix — the defect, reproduced, then fixed.

**Not re-measured on `.146` and `.138`.** The three owned hosts (`192.168.93.x`) are outside
`lab/scope.txt` today; the range is added deliberately for a session that needs it and removed after
(scope.txt's own note). The fleet re-run that would show 551 → 0 on `.146` and 551 → 551 on `.138`,
with the 551 on `.146` closing `remediated`, is the acceptance to run when the operator authorises the
range — the ADR-093 procedure, no harness. Until then the headline changes from "kernel class
excluded and named" to "kernel class judged against the running kernel; fleet re-measurement
pending".

## Consequences

- The Phase 4 headline no longer needs a carve-out: every credentialed finding is matched against
  what runs, with the reboot-pending host visible as the exposure it is.
- Every credentialed read now carries three facts the console can show: the running kernel, and
  which installed kernel versions are not it (the reboot-pending signal, for free).
- A months-old scan point build sends no `kernel_release`; Core judges its kernel rows neither way
  and says so in the debug log, rather than raising findings a newer build would not.
- `cvap-credscan --inventory-only` prints the running kernel beside the package count.
- Inside a container, `uname -r` reports the **host's** kernel (the e2e assertion shows it), so a
  containerised credentialed target's kernel packages all classify installed-not-running and the
  class is held as inventory rather than judged. A missed kernel finding on a container is a gap,
  and it is the same gap as before this ADR with the sign reversed (551 false findings became none
  judged); the container's kernel is its host's, and the host is where the finding belongs.
- Five tests pin the withdrawal on an asset that already carries the finding, counting history rows:
  `TestAReadWithoutTheRunningKernelWithdrawsNoKernelFinding` (no uname; a removed package still
  closes), `TestAUnameNamingNoInstalledKernelWithdrawsNothing`,
  `TestAReleaseChangeWithdrawsNothingTheNewKeyspaceCannotJudge`,
  `TestTheNewestPackageObservationDecides` and `TestACredentialedReopenIsRecorded`.
