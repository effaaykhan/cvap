---
name: adr099-kernel-read-findings
description: ADR-099 / B36 `uname -r` audit (2026-09-15) — the credentialed remediation loop closes findings a read JUDGED NOTHING about (no-uname and empty-keyspace, both reproduced); read set is otherwise clean
metadata:
  type: project
---

Measured against the uncommitted ADR-099 working tree (session 43, 2026-09-15), commit
2552d8b + working tree. Check these first on any change to `internal/correlate/credentialed.go`,
`internal/credscan/ssh.go` or `internal/domain/kernel.go`.

**The credentialed-remediation loop has no "judged nothing" guard**
(`internal/correlate/credentialed.go:126-141`). The kernel skip at :63-70 sets neither
`credVulnerable` nor `covered`, and its own comment says an unjudged finding is "left standing"
— but that protection is applied only to the INFERRED branch (`if !covered[f.Package]`), which
is after the credentialed branch's unconditional `continue`. Anything `f.Source == "credentialed"`
and absent from `credVulnerable` is `MarkRemediated` + a transition. Two reproduced triggers
(integration probe against the dev DB, via `go test -overlay` so the tree is untouched):
  - a read with NO `kernel_release` (`domain.KernelUnknown`, exactly the "months-old scan point
    build" ADR-099's own consequences bullet anticipates) closes a TRUE open kernel finding:
    step 1 `map[open:1]` -> step 2 `map[remediated:1]`, reason "a later credentialed read no
    longer matches linux CVE-2026-0001 (upgraded, removed, or not the running kernel)". Nothing
    about the host changed; only the scan point build did.
  - a release key the advisory keyspace has no rows for (pipeline lag, mid-re-import, a distro
    release not yet imported) empties `credVulnerable` and remediates EVERY credentialed finding
    on the asset: `open=1 remediated=0` -> `open=0 remediated=1` with an identical openssh version.
`covered[]` is NOT a usable guard for the kernel case: a real inventory carries `linux-libc-dev`
under source `linux`, which classifies `NotKernel` and sets `covered["linux"]=true`. The fix has
to be an explicit unjudged set (and a keyspace-populated predicate), not a reuse of `covered`.
Neither committed test covers it — `TestAReadWithoutTheRunningKernelJudgesNoKernelPackage` seeds
a fresh asset with no prior finding, so the closing path never runs. Same shape as
[[control-keyed-to-the-verdict]] and [[latent-limitations]].

**`ParseUname` puts the unbounded target value in its error**
(`internal/credscan/parse.go:200`, `%q` of `v` before the length check). `checkReleaseToken` at
:187 deliberately names the FIELD, not the value. The value can be up to `maxStdout` = 8 MiB on
one line; it reaches the scan point log via engine stderr (`internal/scanpoint/enginehost.go:352`,
Debug, 4 KiB per read). Low, one-token fix.

**A hostile/odd `uname -r` aborts the WHOLE job, not one target.** `ssh.go:113-120` fails the read
and `credhost.go:133-135` `return`s out of the per-target loop, so targets after the offender are
never read and the job is non-`reassign_safe`. ADR-099 chose "the refusal fails the read"
deliberately, but `domain.KernelUnknown` already exists for exactly this and would keep the job
alive. One in-scope compromised host can blind the credentialed read of every host behind it in
the job.

Measured and CLEAN, do not re-audit: the read set is three compile-time constants, `run()` is the
only executor and takes no target-derived string; the third session shares the SAME
`ctx = timeout+30s` (`credhost.go:124`) so the per-target credential-live CEILING is unchanged —
measured marginal cost of the `uname -r` session against the lab sshd is 3.0-4.0 ms of a ~93 ms
read (3.5%); the engine classifies nothing (it copies `read.KernelRelease`), `kernel_release` is
grammar-bounded at BOTH sites; `store.EngineHost` is still in `planner.dialsTargets`.

**Payload growth numbers** (measured on a real 1304-package dpkg inventory): `binary` per row
takes the payload 49.95 -> 77.50 bytes/package, x1.55 (not x2). A 3000-package host: ~150 KB ->
~233 KB. Caps: `TargetChunkBytes` 1 MiB (`internal/scanpoint/submit.go:59`) splits only BETWEEN
observations, and Core's ingest server sets no `MaxRecvMsgSize`, so gRPC's 4 MiB default is the
hard wall for one atomic `package` observation. Single-observation threshold moved ~84,000 ->
~54,000 packages. Worst case from the 8 MiB `maxStdout`: stdout->payload amplification 3.4x ->
5.0x (~28 MB -> ~41 MB), both already past the 4 MiB wall — the cap that is missing is on the
PAYLOAD, not on stdout.

`make safety` passes (exit 0) and does **not** drive credhost: `.github/scripts/safety_gate.py`
runs only `cvap-engine-discovery` and `cvap-engine-fingerprint`. credhost is still outside the
`enginerate`/`fragile` model — see [[credhost-fleet-path-findings]], unchanged by this work.
