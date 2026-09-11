# Phase 4, first session: credentialed Linux assessment (scope)

Settled at the close of Session 39, against the measurements in ADR-078/079/082/083/085. The
decision to lead Phase 4 with this is ADR-084; this is the scope of its first session.

## Gating decision (settle in an ADR before code): SSH credential/network placement

The tension: ADR-027 keeps the credential in the runtime (an engine gets only a derived token);
ADR-047 grants net-to-target to an engine, never the runtime; SSH needs credential and network
together and has no derived token.

**Approved resolution — the agent / signing-proxy split (satisfies both ADRs unchanged):**

- The engine keeps net-to-target and opens the SSH connection (ADR-047 unchanged).
- The runtime holds the private key in an SSH agent and answers signing challenges over the agent
  socket; the engine authenticates **without ever holding the key** (ADR-027 unchanged — the
  signature is the "derived proof, not the credential" its escape hatch describes).
- **Key-based auth only.** Password auth has no agent equivalent and is deferred (it would need
  placement A — runtime does the SSH — or B — engine holds both, amending an ADR; neither is built
  now).

The first task of the session is to write this up as the placement ADR, then build against it.

## Build

1. **Credentialed-host engine** (`engine_kind = host`): opens SSH (net), authenticates via the
   runtime's agent, runs the read-only inventory (`dpkg-query -W`, `cat /etc/os-release`), emits
   `package` observations — activating ADR-077's dormant path (exact `/etc/os-release` release +
   exact installed versions).
2. **Correlate on the exact installed version**: the dormant release-precedence rule fires (exact
   release outranks the band vote), and advisory matching runs on the exact version — no revision
   blindness (ADR-078).
3. **Prove it**: re-run the §6.2 accuracy gates credentialed on the mid-state hosts and record the
   precision delta against this session's baseline. Exit criterion: **FP ≤ 2%** where unauthenticated
   measured 65% (`.138`, partly patched) and 100% (`.146`, well-maintained).

## Lab

- `.138` and `.146` (Ubuntu 26.04, resolute) are the right targets — `.146`'s snapshot mid-state
  (openssh at fix, apache/exim behind) is exactly where credentialed must show ~0 FP against the
  unauthenticated 100%. Re-add both to `lab/scope.txt` for the session (dropped at the end of
  Session 39 per convention).
- **AlmaLinux 9** (openssh-server + httpd + postfix), built when needed, closes **B26** — rpm-in-situ
  and the RPM comparator (ADR-062). Note: rpm advisory *findings* additionally need the ALSA errata
  feed ingested; rpm inventory + comparison works without it.
- Access shape: the `cvap-credscan-s39` key (or a fresh one) for a scan user, unattended-upgrades
  off, a `dpkg -l` / `rpm -qa` ground-truth snapshot per host.

## Carried review triggers

- ADR-080: whether a single-vote resolution's findings should be a distinct candidate state rather
  than asserted at 0.60 (credentialed removes the need on hosts it can read).
- ADR-085: the keyspace `advisory_vuln_map` completeness gap (a one-behind USN mapping zero CVEs) —
  confirm the credentialed truth is complete for the hosts under test.

## Status after Session 40, and the fleet increment's acceptance (ADR-088)

Session 40 built and proved the security core (the agent/signing proxy, ADR-086), the credentialed
matching (exact-version, EVR-correct after the B26 fix), rpm-in-situ, and the per-host FP numbers
(0% credentialed; .146 OpenSSH 16 to 0) — but via the cvap-credscan instrument, not the fleet path.

**Restated after S42 (ADR-093/094):** the fleet path ran and the sixteen closed through it, but ground
truth on the hosts found 551 false kernel findings on `.146` — a stale ABI's packages collapse to the
source name `linux` and the matcher cannot see which kernel runs (B36). The headline is **0% credentialed
FP on the measured set with the kernel class excluded and named**; it is 0% only for packages whose
installed version is unambiguous, and B36 sits ahead of anything that consumes credentialed findings.
The fleet engine increment remains: cvap-engine-credhost emitting package observations,
credential-grant delivery through dispatch, and correlation consuming those observations to activate
ADR-077's dormant precedence and drive the supersession lifecycle.

Acceptance (ADR-088): .146's sixteen unauthenticated OpenSSH findings close as refuted_by_credentialed
through the real pipeline — engine to observation to correlation to finding lifecycle — not the
instrument computing a zero. Re-add the three hosts (.138/.146/.148) to lab/scope.txt for that
session; AlmaLinux .148 also carries the thin ALSA already ingested.
