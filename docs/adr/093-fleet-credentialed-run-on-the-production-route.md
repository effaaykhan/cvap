# ADR-093: The fleet credentialed run on the production route — the sixteen close, and the kernel matcher cannot see which kernel runs

**Status:** Accepted
**Date:** 2026-09-11
**Follows:** ADR-092 (frozen). ADR-092 proved the route on the lab's Debian container; this records
the first run of the same route against the three owned hosts on the operator's network, through
the deployed stack, with no harness on any leg — the run ADR-088 named and ADR-092 left open.

## What ran

Deploy stack (`-p cvap-deploy`) rebuilt on the S42 image; Core started with
`CVAP_CORE_SECRET_FILE_ROOT=/secrets/creds`; the scan point `realnet-scanpoint` on host networking
with `discovery`, `fingerprint` and `credhost` in its engine list. Policy `session24-realnet` at
`intrusive` with the ssh profile `realnet-ssh-cvapscan` (user `cvapscan`, `secret_ref` a file under
the resolver's root, mode 0600) authorised on it. Targets `192.168.93.138`, `.146`, `.148` as single
hosts in `lab/scope.txt` for the session, removed after.

Two passes, in the order the operator chose:

1. **Discovery/fingerprint first**, so the trust material is what CVAP observed, not an operator pin.
   The first fingerprint pass captured all three ed25519 host keys and `asset_identity_keys` stayed
   empty — the correlator recorded keys only on merge and new-asset verdicts, and every host here
   was an *attach* to an asset that already existed. Decision (below, §1): attach records the
   moderate keys too. The second pass recorded three.
2. **One `host` scan** over the three addresses. Measured, in order: `job.intrusive_dispatched`;
   `credential.granted` naming profile, scan point, three targets, `cred_user cvapscan`,
   `trust_source observed`; grant `170ab17d` issued 16:11:39.25Z, `cred_kind raw_secret`, expiry +10
   min; three `package` observations (738, 741 and 1255 packages), all accepted and correlated; the
   job completed and the grant **zeroised at 16:11:43.57Z**, 4.3 s after issue, on the attestation;
   the scan settled `completed` in the same transaction. No refusal, no `credentials_not_attested`.

## What the run measured

| | .138 (ubuntu resolute) | .146 (ubuntu resolute) | .148 (almalinux 10) |
|---|---|---|---|
| Release before → after | band vote 0.9 → `package_manager` **1.0** | band vote 0.9 → **1.0** | none → **1.0** |
| Family after | os-release 1.0 | os-release 1.0 | os-release 1.0 |
| Inferred advisory findings closed | 44: 13 refuted, 31 superseded | 44: **32 refuted** (16 openssh, 12 apache2, 4 exim4), 12 superseded | — |
| Credentialed findings open after | 603 (551 `linux`, 24 apache2, 6 perl, 6 glibc, 4 exim4, 3 openssh, 3 inetutils, 3 libssh2, 1 each gnupg2/curl/vim) | 576 (551 `linux`, 12 apache2, 5 libevent, 4 apr-util, 3 inetutils, 1 libidn) | **0** on 1255 packages |
| Open findings before → after | 46 → 605 | 622 → 578 | 1 → 1 |

**ADR-088's acceptance holds on the production route:** .146's sixteen inferred OpenSSH findings
moved `open → refuted_by_credentialed` at 16:12Z with a `finding_history` row from the correlator.
ADR-077 fired with ADR-090's fix in: all three releases are exact at 1.0, including the AlmaLinux
host that had no release at all. The fully-patched AlmaLinux host raised no credentialed finding,
so ADR-087's epoch fix holds on real data through the real path.

**Ground truth, taken on the hosts afterwards.** `.138` runs `7.0.0-30-generic` with `apt` listing
61 upgradable packages, among them `linux-image-generic 7.0.0-30.30 → 7.0.0-31.31`, apache2, exim4,
openssh, curl, glibc, perl, vim, gnupg and libssh2 — the credentialed finding set on `.138` names
those same packages. `.146` runs `7.0.0-31-generic`, is pinned to the `20260610` snapshot, and `apt`
lists nothing upgradable; its apache2 is `2.4.66-2ubuntu2.2` while the security pocket carries
`2ubuntu2.4`, so its twelve apache2 findings are real and the pin hides them from `apt`.

## The defect the ground truth exposed

`.146` carries **551 credentialed kernel findings and runs a kernel at the fix.** The 551 is exactly
the CVE count of the one resolute `linux` USN fixed at `7.0.0-31.31`. The engine reports every
installed binary under its *source* package — the key USNs use, and right for every ordinary
package — so `.146`'s leftover ABI-30 packages (`linux-image-unsigned-7.0.0-30-generic`,
`linux-modules-7.0.0-30-generic`, the zfs modules) arrive as `linux 7.0.0-30.30`, below the fix, and
match all 551. Debian-family kernels carry the ABI in the binary name; an old ABI's packages stay
installed beside the new one, never "upgrade", and are not the kernel that is running. On `.138` the
same 551 rows are **true**: it runs ABI 30 with 31 available. The matcher produces identical output
for the two hosts because nothing it reads says which kernel is running. The operator's hypothesis
(source-package keying collapses the ABI-versioned binaries) was tested rather than assumed and is the
mechanism; the diagnostic was one advisory's CVE count equalling the finding count, the ground truth
was `uname -r` and `apt` on both hosts. §5.11's shape: a matcher correct against its spec, wrong at
the seam where a host with two kernels on disk becomes one source name with two versions.

**Not fixed here.** Ubuntu's own OVAL resolves the kernel against `uname -r`. Collapsing to the
newest installed version is the wrong fix — it hides the reboot-pending case, which is the real
exposure. The right fix needs a third read-only command on the engine, and the engine's read set is
two (`cat /etc/os-release` plus `dpkg-query` or `rpm -qa`, ADR-076 and ADR-087; `credhost.go`'s
header says the same), so it is a decision for the operator: **backlog B36**. Until it lands, the `linux` rows on a
host that has rebooted into its newest kernel are wrong.

## Decisions

1. **An attach records the host's moderate keys — unless they contradict what the asset holds.**
   `internal/correlate` recorded identity keys only when a verdict was merge or new-asset. A host
   observed with a key and attached to the asset that already holds its address gained nothing, so
   ADR-091's observed-trust path — "every task must have a host key CVAP observed" — could never be
   satisfied for an asset that existed before its key was seen, which is every asset in an estate
   that was discovered before fingerprinting. Attach now records keys of strength ≥ 2.
   `TestAnExistingAssetGainsTheKeysItIsLaterSeenWith` measures it: zero keys after the keyless
   scan, two after the keyed one, and the asset then merges across a DHCP move on those keys.
   The review of this ADR found the shape that must NOT record: address handover. A different host
   on a reused lease, carrying a *different* SSH key from the same service, attaches — nothing
   agrees, and one moderate key alone decides nothing (ADR-007; `domain.Resolve`'s contested branch
   needs at least one agreeing key). Recording there would leave one asset holding two hosts' keys,
   and `SSHHostKeyFingerprintsAt` — ADR-091's observed-trust set — returns every live key on the
   asset at that address, so a credential would be presented to whichever machine answered. A key
   that contradicts a held key of the same type from the same service is left unrecorded and logged;
   the newcomer attaches by address exactly as before. Deciding that shape properly is a domain
   rule (queue it, or refuse the attach), not a recording rule: **B37** — the security review
   objects, rightly, that `contradictsHeld` is a conflict rule living in the wrong package; it
   decides only what evidence is copied, not the verdict, and it goes when B37 lands in `domain`.
   What the review then measured, and this ADR does not fix: **observed trust is first-seen trust.**
   An attacker who can answer for an address before CVAP has seen its key — a freed lease, ARP —
   presents a key of their own; it matches no asset, the sighting attaches, the key is recorded,
   and `SSHHostKeyFingerprintsAt` returns it as the trust root for that address. Before this change
   the same sighting recorded nothing and a credentialed job at that address was refused for want of
   an observed key; the same attacker at a fresh address always became a new asset with their key
   recorded. So the change extends first-seen trust from "addresses CVAP first met with a key" to
   "addresses CVAP met before it looked for keys" — which is every host in this run, and the reason
   the operator chose a discovery pass ahead of the credentialed one rather than a pin. ADR-091
   §4's answer to first-seen trust is the operator pin, which wins over observed material; the
   review's alternative — keys recorded on attach are inventory but not trust material until seen
   again — needs a provenance column and a decision, and is put to the operator below.
2. **The shared-database flake is resolved at the root, and the cause was named wrong.** The memory
   said the deploy Core planned the test suite's scans; the deploy Core has its own database
   (measured: its `APP_DATABASE_URL` names the deploy stack's postgres, not `127.0.0.1:5432`). The
   planner that took `test/e2e`'s seeded `pending` scans was `test/e2e`'s own Core, whose
   `PlanPending` plans every pending scan across tenants. Every job-carrying test seed now inserts
   its scan as `running` — the dispatch, store, correlate, load, e2e, credgrant, pool and corpus-ingest
   seeds — except `seedPolicyJob`, the one helper (24 call sites across the policy-enforcement and
   cancellation suites) whose tests must start from `pending` because `SetSafetyMode` refuses after
   start; those opt in before start. Nothing is stopped or pointed elsewhere.
3. **A job's tasks follow the job.** Nothing wrote `scan_tasks.status`; every task in the deploy
   estate sat `pending` under a completed job. The wire carries no per-task outcome — `JobTerminal`
   has `tasks_completed`/`tasks_failed` as counts and one `incomplete` flag — so Core decides from
   what it holds: a job that completed with its results whole completes its tasks; any other ending
   (engine failure, scope halt, lease loss, cancel, kill, or completed-but-incomplete) is judged
   task by task on whether an ACCEPTED observation was attributed to the task (a pending row was
   never attested complete and a quarantined one is withheld from the pipeline, so neither is
   coverage — the security review's probes showed both being counted) — completed if so, otherwise
   `failed` (engine or lease lost: "unreachable" and "never reached" cannot be told apart, and
   failed is what an operator investigates) or `skipped` (an operator stopped the job). The
   credentialed engine makes the per-task rule necessary: it aborts the whole job on the first
   unreachable host after emitting for the hosts before it, and those hosts were read. All of it
   rides the job's own holder predicate, so a non-holder that cannot end the job cannot end its
   tasks. `ExpireLeases` — the fourth writer of job status, and the door ADR-012 jobs go through —
   does the same: a lease-lost job's tasks are judged by observation; a re-queued `reassign_safe`
   job's tasks go back to `pending` with no `started_at`, because a `running` task under a `queued`
   job reads as a target being probed with no scan point holding it. `Jobs.Tasks` now says in its
   own comment that it returns every task whatever its status — the assignment is the whole job,
   and a status filter there would under-scan a re-claimed job. The runtime submits before it sends
   `JobTerminal`, but the two travel on different streams, so a terminal can land before the final
   chunk's ack and judge tasks whose results are still in flight; the same review drove that order
   and got a fully-scanned target recorded failed with nothing to revisit it. Ingest therefore calls
   `ReconcileTasksWithResults` after promoting a submission to accepted: a task the terminal wrote
   off becomes completed the moment its results are — failed tasks only, since a skipped one was
   stopped by an operator and ADR-024 wants that visible. Both reads over `observations` are bounded
   to the job's own window, because the table is partitioned by `observed_at` and the review's plan
   showed an unbounded EXISTS visiting every live partition per task inside the terminal's
   transaction. One trust the review flagged and this ADR keeps: a scan point's `completed` with
   `incomplete = false` marks every task covered without an evidence lookup — a scan point that
   lies here can fabricate observations as easily, and a completed discovery job with a down host
   has no observation for it and was still attempted. Two things this does not fix, both
   found by the scan-safety audit of the change: the scan point sends its single `JobProgress`
   AFTER `JobTerminal`, so `MarkRunning`'s `assigned → running` never matches in production and
   `running` is unreachable for the job and its tasks alike (**B38**, pre-existing); and the
   task-by-observation rule is a proxy — a target the engine touched without emitting anything
   reads as failed, which is the conservative direction.
4. **The acceptance was reopened before it was measured.** All twenty of `.146`'s
   `refuted_by_credentialed` rows had been closed at 09:50Z by the S41 instrument's package read — a
   harness submission with no grant row and no credential audit. `Supersede` touches only open or
   confirmed rows, so the production run would have closed nothing and the acceptance query would
   have gone green. The twenty were reopened with a `finding_history` row saying why, then the run
   closed them. Recorded as §5.13 in the session map: establish the before, do not assume it.
   That harness write is also the shape ADR-077 refused on principle — credentialed data entering
   the pipeline by a path no scan point can use. It was a one-session instrument, not a path: the
   tree holds one ingest client (`internal/scanpoint/submit.go`) and `cmd/cvap-credscan` writes
   nothing to the database, so no bypass is committed; what remains of it is the state it left,
   which this decision cleaned up.
5. **Recorded, not fixed:** B35 (the credentialed engine outside the rate and fragile model — does
   not block three lab VMs, blocks anything pointed at a real estate), B36, B37 and B38 above.

## What this does not discharge

- B35 and B36. No credentialed scan may be pointed at a customer's estate until B35 lands; the
  kernel rows are unreliable on rebooted hosts until B36 lands. B37 (address handover is attached,
  not queued) and B38 (progress after terminal) are recorded with their measurements.
- Whether a key first seen on an attach may be credentialed trust material on first sight, or only
  after a second sweep (or a pin). Observed trust at all is first-seen trust; the attach change
  widens where first sight can happen. Operator decision, with B37.
- The three inetutils findings on `.138` are not in `apt`'s upgradable list and were not verified
  either way.
- The dead scan-point rows (`hostnet-scanpoint`, two `lab-scanpoint`) still show in the fleet strip.
