# ADR-091: The credential grant crosses the wire — cred_user and known_hosts on the assignment, the secret on the grant, and the four things the route had to get right

**Status:** Accepted
**Date:** 2026-09-11
**Implements:** the increment ADR-088 and ADR-090 both name as their review trigger — the fleet path
from Core, through the dispatch stream, to a `cvap-engine-credhost` process that authenticates with
signatures from the runtime's agent (ADR-086). ADR-020, ADR-026, ADR-027, ADR-057 and ADR-086 are
frozen and unchanged; this is their first joint application.

Session 41's foundations commit built the route up to, but not across, the wire: the resolver, the
profile fields (migration 0042), engine selection, fingerprint verification. This ADR records the wire
change — `JobAssignment.cred_user = 8` and `known_hosts = 9`, both additive under ADR-022, authorised
by the operator for this session — and the dispatch, runtime and engine-host wiring that makes a host
job run credentialed end to end. Four things had to be right, and the operator named them before the
code was written; each is stated below with how it is measured rather than asserted.

## The wire

Two non-secret fields travel with the assignment. `cred_user` is the `username` column of the
credential profile; `known_hosts` is public key material by definition. The grant that follows the
assignment on the same stream still carries the only secret on the wire — the ed25519 private key,
`CredKind RAW_SECRET`, resolved from the profile's `secret_ref` at grant time and nowhere else.

Core sends the assignment and then its grant back to back on the outbound channel, in that order,
because the runtime drops a grant for a job it is not running. The runtime accepts a host job only
after validating both fields (below), enters it in the job table, and waits up to
`CredentialGrantWait` (30 s) for the grant before it spawns anything; a job whose grant never comes
fails `ENGINE_FAILURE` naming the missing grant rather than sitting on a lease it renews for work it
cannot start. The runtime builds the signing agent from the grant (ADR-086), hands the engine the
agent socket as fd 3 with `cred_user` and `known_hosts` in the job message, and closes its own copy
of that file once the child has its dup. The engine authenticates with signatures and reads
inventory; it never sees the key, and there is no field it could arrive in.

Each release is a `credential_grants` row (migration 0006 — the table existed with no writer) in the
same transaction as the lease, plus a `credential.granted` audit event. `zeroised_at` is set only
from the runtime's `credentials_zeroised` attestation on `JobTerminal`, and only for grants delivered
to the attesting scan point's certificate fingerprint (a same-tenant scan point cannot close the
record of a secret it never received by naming the job). This **narrows** migration 0006's comment,
which also names "Core observes the job terminate" as a trigger: a terminal without the attestation
leaves the row open, because NULL is the operator-visible "no confirmation" state and a row closed
on the terminal alone would hide exactly the case the column exists to show.

## 1. The fingerprint finding is a measured design change, not a convenience

The plan assumed the `ssh_hostkey` identity key discovery captures was a full host key that the
engine would match by public-key bytes. It is not: `internal/correlate/evidence.go` copies
`k.Fingerprint`, so what CVAP has observed for a host is its **SHA256 fingerprint**. Building the
fleet path against the real column is what showed this — the query for the observed key returned
fingerprint strings, and the engine's verifier as first written could not use them.

The change recorded here is that host-key verification accepts fingerprints as trust material
(`credhost.hostKeyCallback`, foundations commit): a fingerprint cannot be turned back into a key, so
it is matched by computing the presented key's own SHA256 fingerprint, which is a standard SSH trust
mechanism. The consequence is the reason to prefer it: **the fleet path verifies against exactly what
CVAP already observed**, on the unauthenticated scan that preceded the credentialed one, rather than
adding a capture step to discovery so that a full key exists somewhere to compare. This was
discovered by building, not designed — the fourth time in Phase 4 that an assumption about existing
data did not survive contact with it (§9 5.11 and 5.12 record two of the earlier ones). It is recorded
as a design decision so that a later reader does not "fix" the verifier back to full keys and
reintroduce the capture step. The measurement is `credhost_test.go` (a fingerprint accepts its key and
refuses another; a full line still works; nothing usable refuses), and on the Core side
`trustMaterial` refuses an observed value that is not a `SHA256:` fingerprint rather than composing
a line the engine's verifier would silently skip — the refusal lands where it is audited, not in
the engine.

**Precondition, stated so it is not assumed:** the observed source exists only where an
unauthenticated discovery scan has already captured the host key for that address in that tenant.
The fleet estate today has no `asset_identity_keys` rows at all, so on it every host job refuses
unless an operator pin is set; a discovery pass precedes the first credentialed one, or the
operator pins.

## 2. Stop, zeroise, submit — stated, and tested by severing

The terminal path's order is the ADR-020 / ADR-026 seam, and ADR-057 fixed it before it could bind:
**stop the engine, zeroise, then submit**. Zeroise precedes submission because the drain can block
for minutes against an unreachable Core and credential lifetime must not be tied to how long an
upload takes; submission follows regardless, because results are never discarded. Session 9's F9
finding was exactly this shape — both ADRs honoured at the store, and the process exiting before the
goroutine that would have honoured them ran — so the guarantee that matters is one layer below the
code path: what the engine can *do* at each instant.

Two things changed to make the order hold for a credentialed job:

- **The agent is inside the zeroise set.** `CredAgent` holds the one retained copy of the key
  (ADR-086); the `Credential` it was parsed from is a second array. The job's `zeroiseCredentials`
  and `credentialsZeroised` now cover both, agents first. Before this, zeroising the `Credential`
  alone left the keyring signing and the attestation answering true — the F9 shape again, one layer
  above where the key lives. `TestAttestationCoversTheAgentCopy` pins it, and the mutation the
  harness carries (`make mutate`) is this one: zeroise skipping the agent fails the sever test.
- **Closing the agent socket is the mechanism.** `CredAgent.Zeroise` closes the runtime end, so an
  engine still running loses the ability to obtain a signature at that instant, independently of
  whether it has yet been killed.

`TestSeveredCredentialedJobStopsThenZeroisesThenSubmits` severs a running credentialed job through
two doors — a `LeaseGrant LOST` from Core, and `shutdown()` (the F9 door, the process leaving) — with
a fake engine that holds the real agent socket and probes it: at `stop()` signing must still work
(the engine's grace to finish the observation in hand runs with its credential); at `results()`,
inside `terminate` before `Enqueue`, signing must already fail; afterwards exactly one submission is
buffered and the `JobTerminal` attests zeroised. The fake is deliberately slow to be reaped, so the
abort path's own zeroise is the only one that can precede the submission and the ordering binds on
it rather than on `runJob`'s deferred belt-and-braces. The two-line ordering mutation (abort
zeroising after `terminate`'s `Enqueue`, at both sites) was run by hand and fails at "signing still
worked when results() were gathered" in both severs; it is two-line, so the harness carries the
agent mutation instead, and this sentence is the record.

ADR-057's second clause — derive anything the submission needs from the credential *before* the
zeroise — is answered for the first credentialed engine: it derives nothing. The submission is the
engine's `package` observation and nothing credential-shaped comes back over the engine wire, so
the derivation seam stays unbuilt by decision, and `runtime.terminate`'s comment now says so
rather than describing a change still pending.

`TestEngineReceivesTheAgentSocketOnFD3AndCanSign` spawns a real child through the production
`engineHost` and has it sign over fd 3 holding no key, because the `ExtraFiles` plumbing is exactly
what a fake host would assert into existence.

## 3. The resolve-then-abort window is closed on both sides

The secret resolver decision left a window: a key resolved by Core and then not delivered. It is
closed at every exit, and the closure is measured.

**Core.** The resolved bytes exist in exactly one array, the `CredentialGrant.material` slice held by
a `pendingGrant`. The refusable steps — no resolver, no profile, no username, no trust material —
all run *before* `Resolve`, so after it only the grant row and the audit event remain, and both are
transaction errors. Every exit that is not a `Send` erases the array: the transaction rolling back
after `Resolve` (a deferred discard in `offerWork` over grants that were never queued), the
assignment being refused by a full outbound queue (its grant is discarded and never queued — a
dropped assignment must not be followed by its secret), the grant itself being refused, and a
grant still sitting in the outbound channel when the stream ends (`Connect` waits for the pump to
stop and drains both channels, erasing what it finds — the case the adr-compliance review found
the first version's sentence overstating). Once `stream.Send` returns, success or failure, the
send loop erases the material: the bytes are in the transport or never will be. `TestResolvedMaterialIsErasedWhenTheTransactionRollsBack` induces the
rollback from inside the resolver (it cancels the pass's context, so the next statement fails) and
`TestResolvedMaterialIsErasedWhenTheSendIsRefused` hands `offerWork` an unbuffered channel nobody
reads; both hold a reference to the slice the resolver returned and require it zeroed.

One defect was found by these tests rather than by reading: the first version's deferred discard
erased *every* grant when `offerWork` returned — which is before the send loop has dequeued it — so
the runtime would have received a grant of zeros. `TestHostJobTravelsWithItsGrantAndCoreErasesItsCopy`
reads the bytes at `Send` and caught it; a `queued` flag now hands ownership to the send loop.

**Runtime.** A grant that lands once the job is already on its terminal path is zeroised on arrival
rather than appended — the terminal path's own zeroise may already have walked the list, and material
appended after it would live for the process while the attestation reported nothing wrong
(`TestGrantArrivingAfterAbortIsZeroisedOnArrival`). A grant for a job not in the table is erased in
place, as before. A grant that arrives and is then refused before spawn — expired, a non-ed25519 key
`NewCredAgent` refuses (ADR-086), a stop that got there first — is covered by `runJob`'s deferred
zeroise, which runs on every path including panic.

## 4. `known_hosts` carries the operator-versus-observed claim, and TOFU is refused at both ends

There are two sources of a host key CVAP will trust and no third: **operator** — lines pinned on the
credential profile (migration 0042), a trust root chosen independently of what discovery saw — and
**observed** — the fingerprint CVAP captured for the target on an earlier scan. The operator pin wins
outright when present. Trust-on-first-use is not a mode.

What crosses the wire says which applied. `internal/hostkeytrust` is the one definition of the field's
shape, imported by both ends: a first line `# cvap-trust-source: operator` or
`# cvap-trust-source: observed`, then the material. The header is a known_hosts comment, so the
engine's parser — which knows nothing of it — reads the material and ignores the claim, while the
runtime requires it. Three refusals follow, each by name:

- **Core will not compose the TOFU shape.** `Compose` refuses an empty body, and the dispatch
  producer refuses the job (`job.credential_refused`, the job terminal `engine_failure`) when a task
  has no observed key and no pin covers it — never a per-host TOFU inside a job.
- **The runtime enforces the refusal on the claim, before any process exists.** `onAssignment`
  parses the header and refuses a host job with no `cred_user`, no header, an unknown source, or a
  header with no material, with the reason in `JobTerminal.detail`. A Core that composed such an
  assignment made a claim this runtime will not act on, and the refusal is audited on Core's side as
  a job that ended, in words, rather than one that never started.
- **The engine refuses again** if handed nothing usable (`hostKeyCallback`, unchanged) — the last
  line, not the control.

`hostkeytrust_test.go` pins the format and both refusals; `TestHostJobIsRefusedRatherThanDispatchedUncredentialed`
(dispatch, against a database) and `TestHostJobWithoutAcceptableTrustMaterialIsRefusedBeforeAnyProcess`
(runtime) are the two ends refusing, and `TestOperatorPinnedKnownHostsOutranksTheObservedKey` is the
pin winning with the audit event saying `operator`.

The `credential.granted` audit event records `trust_source` with the same word the wire carries, so
the auditor reads the claim Core made and the runtime reads the claim it enforced, and neither infers
it from the shape of the lines. A dedicated enum field would have been the cleaner encoding; the
authorised additive set was the two fields, and the header makes the existing string field
self-describing so the distinction is not lost. If a later additive field carries it, the header
stays for older runtimes — ADR-022's rule cuts that way.

## What the reviews measured, and what changed because of it

Three reviewers ran against the first version of this increment by probing rather than reading
(security-reviewer, scan-safety-auditor, adr-compliance), and the following were defects, each
measured and each fixed before this ADR was committed. They are recorded because every one of them
was invisible in the text and several were in code written minutes earlier:

- **A hostname host job bypassed both scope sites.** `planner.dialsTargets` did not list the host
  engine, so a hostname target was planned, both sites authorised the *string*, and the engine
  resolved the name itself and completed a TCP connect to an address no rule had seen. The
  allowlist's own comment said the cost of omission would be "a refused hostname rather than a
  scope bypass"; for an engine that dials, it was the bypass. One line, and
  `TestHostnameIsRefusedForTheCredentialedHostEngine`. This is the third time the `internal/scope`
  hostname limitation has gone live behind a new dial (§9 5.4).
- **Trust was pooled per job, not bound per host.** `hostKeyCallback` accepted any key in the job's
  material for any target, and an operator pin was passed verbatim for every task. With 32 targets
  per job that was a 32-key any-of set; with a fleet-wide pin it was the fleet. Now every line binds
  to the host in its first field and the callback checks the host it dialled
  (`TestHostKeyCallbackBindsTrustToTheHost`); Core composes, per task, only the pin lines covering
  that task and refuses a task none covers (`hostkeytrust.LinesCovering`, the "operator pin does not
  cover the target" refusal case). A bare fingerprint with no host binds to nothing.
- **A stored fingerprint could inject trust lines.** `asset_identity_keys.key_value` is unbounded
  text written from an observation a scan point submitted; a value that began with `SHA256:` and
  carried a newline composed a line for another host. A compromised scan point in one zone could
  poison a credentialed job in another. `trustMaterial` now admits exactly one token of one shape
  (the "observed key with an injected line" refusal case).
- **The agent goroutine panicked the whole scan point on the abort race.** `ServeAgent` read the
  agent's fields unlocked after `Zeroise` had nilled them; a job refused between `EngineFile` and
  the spawn — the runtime's scope refusal, reliably — killed every job on the scan point. The
  goroutine now holds its own references (`TestAgentZeroiseRacingItsOwnServeGoroutineDoesNotPanic`).
- **The engine end of the agent socket was inheritable.** No `SOCK_CLOEXEC`, so a sibling engine
  spawned for another job inherited a working signing oracle in 16 of 20 concurrent spawns. Fixed
  at the socketpair; `TestAgentSocketIsCloseOnExec`. `ExtraFiles` still delivers it to the one child
  it is meant for.
- **The runtime took delivery of the secret before checking scope.** Core checks scope first;
  the runtime did not, so a job it was about to refuse still built a keyring and opened a socket,
  and a dropped grant turned a scope disagreement into a thirty-second "no grant" failure.
  `authoriseAll` now runs before `awaitCredential`.
- **The grant record could be closed by a scan point that never received it.** `MarkZeroised`
  keyed on job only; now on `delivered_to_fingerprint` too, asserted in the wire test.
- **A grant queued when the stream died was never erased.** `Connect` now waits for the pump and
  drains both channels.
- **Core's clock behind the database stopped all dispatch for the scan point.** `expires_at` was
  computed from Core's clock and checked against the database's `issued_at`; an eleven-minute
  skew failed every pass silently. The expiry is now the database's `now()` plus the TTL.
- **A refusal record could be rolled back by a later job's error in the same pass.** The
  `job.credential_refused` events are now replayed in their own transaction when the pass fails.
- **`secret_ref` paths reached audit detail.** `credsource` errors now carry the errno and never
  the path; the sentence in §3 about the ref not reaching the log was false before this.
- **The grant's `scope` was enforced nowhere.** The runtime now refuses a grant whose scope does not
  cover every task.
- **The engine read had no deadline**, so a target that accepted the connection and stalled held
  the session and the credential open indefinitely. Each read is now bounded.

Recorded as gaps, not fixed here: the credentialed engine sits outside the packet-rate model
(`enginerate`, `fragile`, `max_concurrent_per_target` reach it as numbers it does not read; it opens
one SSH session per target back to back) — an SSH login and two reads against an embedded device
that runs sshd is not obviously inert, and ADR-048's "one model" now has an engine beside it. A
grant Core dropped still ends with `zeroised_at` set, because the runtime attests over an empty
list; `CredentialGrants.Unconfirmed` cannot tell "delivered and confirmed" from "never delivered".
A `JobTerminal` from a scan point that does not hold the job still files a
`credentials_not_attested` event attributed to the sender (noise, not a frame-up).

## What is refused, and why that shape

A host job is credentialed or it is refused. There is no uncredentialed host engine to fall back to,
and a job that quietly ran without the credential its policy authorised would be under-scanning that
looks like a clean run. Core's refusal is terminal (the same argument `refuseJob` makes: it is
refused identically on every poll, and a two-second loop that goes quiet after `MaxAttempts` takes
the reason with it), recorded as `job.credential_refused` with the reason, and the job's termination
reason is `engine_failure` — the "refused the job" half of that reason's definition, since nothing
about scope is wrong. A Core with no secret resolver configured (`CVAP_CORE_SECRET_FILE_ROOT` unset)
refuses every host job this way, naming the setting; `file://` is the only scheme and is lab-grade
custody by its own account (`internal/credsource`).

## Consequences

- ADR-088's "unexercised end-to-end" and ADR-090's review trigger are **still open** at the time
  this ADR is written. The tests above prove the route; nothing here proves the system (§9 5.11).
  What discharges them is a live run that has not yet happened: the three Phase 4 hosts re-added to
  `lab/scope.txt`, Core restarted on this build with a secret root, a host scan dispatched over the
  real stream with the grant travelling, `package` observations arriving through ingest, and
  `.146`'s credentialed resolution at 1.0 on live data. The fleet database today has zero host jobs,
  zero `credential_grants` rows and zero `asset_identity_keys` (adr-compliance measured it), so the
  run also needs a discovery pass or an operator pin first. Its numbers are recorded in their own
  ADR, not by editing this one.
- `CredentialGrantTTL` (10 min) bounds how long a grant may be used to *start* an engine; the
  runtime refuses to spawn against an expired one. A running job's credential lifetime is bounded by
  the job's own terminal path — lease, window, cancel, kill — not by the grant's expiry, and this is
  deliberate: killing an SSH session mid-inventory at an arbitrary instant is a partial scan that
  looks like a clean one.
- This is the system's first `RAW_SECRET` release. ADR-020 prefers mechanisms in which the secret
  never leaves Core — short-lived SSH certificates are its own example — and ADR-086 chose key-based
  auth without weighing them. Not revisited here: a certificate still needs a signing key at the
  scan point or a CA the targets trust, and neither exists in the lab. Recorded as the open question
  it is, not as a decision.
- Not built, and named so it is not assumed: password auth (no signing-proxy equivalent, ADR-086);
  `vault://` and `kms://` (the seam exists); choosing among several authorised profiles for one job
  (the earliest authorised is taken, deterministically); a health surface for `credential_grants`
  rows past expiry with no confirmation (`CredentialGrants.Unconfirmed` is the query; §6's standing
  requirement applies and this is the named deferral, unblocked by the ops handler that already
  serves `Observations.PendingOlderThan`).
- Review trigger: the live run's numbers; and the first non-ed25519 key an operator needs, which
  ADR-086 refuses and which would reopen the zeroise analysis rather than this ADR.
