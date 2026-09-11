# ADR-087: B26 closed — credentialed rpm-in-situ, the exit-criterion result, and the EVR bug the real advisory found

**Status:** Accepted
**Date:** 2026-09-11

Session 40's exit criterion was credentialed advisory-matching false positives ≤ 2% against the
unauthenticated baseline (65% partly-patched, 100% fully-patched, ADR-082/085), reported per host,
with `.146`'s fully-patched OpenSSH as the case that mattered most; and B26 (rpm in situ) closing if
AlmaLinux worked. Both are met. This records the result, the rpm bug the exercise caught, and —
plainly — what was built versus measured.

## Exit criterion, per host

| host | distro | credentialed findings | credentialed FP | unauth baseline |
|---|---|---|---|---|
| `.138` | Ubuntu 26.04, partly patched | 7 (all real) | **0 / 7 = 0%** | 65% |
| `.146` | Ubuntu 26.04, mid-state | 0 exposed | **0%** — **OpenSSH 16 → 0** | 100% |
| `.148` | AlmaLinux 10.2, fully patched | 0 | **0%** | (rpm/B26) |

Credentialed matching on the exact installed version carries **zero false positives** on every host —
the revision blindness that made unauthenticated matching 65–100% wrong (ADR-078) is gone, because the
exact version is read, not inferred. `.146`'s OpenSSH is the decisive case: 16 unauthenticated false
positives on a fully-patched package become **0** credentialed. FP ≤ 2% is met (0% throughout).

## B26 — rpm in situ, and the bug the real advisory caught

`.148` (AlmaLinux 10.2) was read credentialed over SSH through the agent/signing proxy (ADR-086):
1255 rpm packages, exact `epoch:version-release`, release read — rpm-in-situ proven on a real host.
The rpm comparator was validated against rpm's own rpmvercmp corpus and a live librpm oracle (ADR-062)
but, as B26 anticipated, **never against a real advisory on a real rpm host**. Doing so found a bug:

`version.Compare(SchemeRPM, …)` handed the whole `epoch:version-release` string to `CompareRPM`
(rpmvercmp), which treats `:` and `-` as ordinary separators. So a fully-patched host
(`0:9.9p1-25.el10_2.alma.1`) compared its epoch digit `0` against an epoch-less advisory fix's first
version segment `9` and read as *below* it — **56 credentialed false positives** on a host that is
fully patched. Fixed by `compareRPMEVR`: compare the epoch numerically first (absent = 0), then
rpmvercmp on version and release — the EVR layer rpm itself performs, wrapped around the unchanged,
validated rpmvercmp core. After the fix, `.148`'s credentialed truth is **0** (all three services at
their newest ALSA fix — verified correct), and the regression test covers both the false-positive
case and a one-revision-behind → vulnerable case. This is exactly the value B26 named: the comparator
against a real advisory, and it caught a real defect the corpus could not.

The ALSA ingest was kept to the guardrail — a thin OSV query for the three services (22 fixed-package
rows, `comparator='rpm'`, `distro_release='almalinux-10'`), not an Alma feed pipeline. A full ALSA
feed remains a separate knowledge task.

## What was built, and what was measured — stated plainly

- **Built and verified:** the agent/signing proxy (`CredAgent`, ADR-086) with the ed25519 zeroise
  guarantee, proven against all three real hosts (each read authenticated with the key held only in
  the runtime agent); the rpm inventory read and family detection; the EVR fix. All unit-tested and
  lint-clean.
- **Measured via the instrument, not yet the fleet path:** the per-host numbers above were produced
  by `cvap-credscan` (agent-authenticated) computing the credentialed finding set with the same
  exact-version matching the fleet correlation will use. The **production fleet engine** —
  `cvap-engine-credhost` emitting `package` observations through the wire contract, credential-grant
  delivery through dispatch, and correlation consuming those observations to activate ADR-077's
  dormant release-precedence — is **not built this session**. The matching correctness, the security
  design, and the rpm mechanism are proven; wiring them into the dispatch→observation→finding fleet
  path is the next increment. The exit-criterion numbers do not depend on which path computes them —
  the matching is identical — so they stand.
