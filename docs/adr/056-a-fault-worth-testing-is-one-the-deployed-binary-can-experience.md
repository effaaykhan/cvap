# ADR-056: A fault worth testing is one the deployed binary can experience

**Status:** Accepted
**Date:** 2026-09-05

## Context

Session 20 built the distributed fault-injection matrix the plan's §6.4 calls for: lease
expiry mid-job, partition-then-heal with a superseded epoch, clock skew, duplicate submission,
backpressure under saturation, and scan-point resumption. Every fault case is declared with a
sabotage it must kill (the six-case discipline from session 17), because a matrix in which only
one case can fail is one case.

Two questions recurred while building it, and both are decisions worth recording rather than
re-deriving the next time a distributed behaviour needs a test: **which faults are worth
testing at all**, and **where a case's sabotage has to live to test anything**.

## Decision

### A fault the deployed binary cannot experience is not worth testing

The controlling rule, and the one the next case that resists injection is argued against: a
test may only reach a fault through a seam the shipped binary also has. Concretely, **no
test-only build tag and no test-only branch in the production path.** A `-tags faultsim` that
let a test drive a branch production never takes would not be testing a fault — it would be
testing code that only exists for the test, and a branch reachable only under a build tag is
precisely the kind of divergence this matrix exists to catch. The faults are forced instead
through real seams: DB rows, real goroutines and transactions, the injectable `now func()
time.Time` clocks the runtime already carries, and real processes under the e2e harness.

Where a fault genuinely cannot be injected without a mechanism that exists only for the test,
the answer is to say so — not to build the mechanism. Clock skew is the worked example: the
scan point's clock is a real dependency (`Runtime.now`) at the integration seam, so F3 tests it
there; injecting skew into a *running* cvap-scanpoint would need a `CVAP_FAKE_CLOCK` env hook in
the code path the test guards, so F3 does not do it e2e and records why.

### An e2e sabotage only binds the code the test process runs

Discovered building it, and a permanent constraint on where a case's sabotage lives: the e2e
harness builds `cvap-core` and `cvap-scanpoint` as **separate binaries** with `go build`, a
subprocess that does not inherit `go test`'s `-overlay`. Mutation testing (`make mutate`) works
by overlaying a mutant source file, so **an overlay mutation cannot reach logic that runs inside
those binaries** — it mutates only what the test process itself compiles and executes.

The consequence is a rule for every e2e fault case:

- If the sabotaged decision runs in the **test process** (an out-of-band store call the test
  makes directly — F1b drives `ExpireLeases`, F3 drives `Renew`), the overlay binds and the
  e2e test carries the mutation.
- If the decision runs only **inside a built binary** (F2's `checkEpoch` executes in
  cvap-core's ingest service), no overlay can reach it. The logic's sabotage lives at the
  **unit/integration layer**, where the overlay bites; the e2e test is the end-to-end
  **observation** — that a real scan point over real gRPC produces the outcome — and carries no
  mutation. F2's quarantine logic is sabotaged on `TestSupersededEpochIsQuarantinedNotDropped`
  in `internal/dispatch`; the F2 e2e test observes it and says, in the file, that it deliberately
  has no mutation and why.

This is the same principle as the build-tag rule from the other direction: a sabotage the
deployed binary's test cannot experience tests nothing, so it is not written as though it does.

### Two cases are dropped, because reaching them would test the harness

Two ingest fencing branches are covered by unit tests and are **not** given a dedicated
integration or e2e fault case, because a real client cannot reach them:

- **An epoch Core never issued** (`checkEpoch`'s `epoch > current` arm). A real scan point can
  only ever hold an epoch Core granted it; constructing a higher one requires a harness that
  fabricates the wire, so a test of it is a test of the fabrication, not of a fault the system
  can suffer. This is the stronger of the two reasons.
- **A submission from the wrong holder** (`checkEpoch`'s holder arm). The holder is taken from
  the TLS peer certificate, never from the message (dispatch), so a real client cannot present
  another scan point's identity; the same "you would be testing the harness" reasoning applies.

Both remain exercised by `TestUnissuedEpochAndWrongHolderQuarantine` at the unit layer. They are
recorded here so the absence reads as a decision, not an omission — the way the plan's §6.5 gaps
are named rather than left for a reader to mistake for coverage.

## Alternatives considered

**A network-fault harness (toxiproxy / netem / iptables) for a "real" partition.** Rejected. A
scan-point partition is mechanically *it stops renewing while its work continues*, and every
fencing decision is made in Postgres against `clock_timestamp()` and `FOR UPDATE`. Cutting the
network exercises no code path that "stop renewing + the DB clock advances" does not, so it adds
a dependency and wall-clock cost for fidelity theatre. The partition is forced instead by the
real functions the sweep and reassignment call, which is what the existing lease-sever e2e test
already established as "the real mechanism, not a simulated one".

**A `faultsim` build tag to reach otherwise-hard branches.** Rejected, and it is the precedent
this ADR names. It is the exact shape — a branch the shipped binary never takes — that the
matrix is meant to catch.

**Making every e2e case carry its own overlay mutation.** Rejected as impossible rather than
undesirable: the overlay cannot reach a built binary, so such a mutation would sit in the file
looking like coverage while testing nothing — the vacuous gate the six-case rule exists to
refuse.

## Consequences

The matrix is layered by where each fault's decision runs. Store-level races (F1a completion,
F3 clock), in-process ingest (F2 logic, F4 resumption-vs-duplicate), and scan-point buffer logic
(F5 resume, F6a saturation) carry overlay mutations that bind. The e2e tests (F1b, F2, and the
process-restart limitation) are end-to-end observations; F1b and F3-style cases whose sabotaged
function the test drives in-process still carry mutations, while a case whose decision is only in
a binary does not. `make mutate` gains the new suites; `check_ci_parity` already requires
`make mutate` in CI, so the sabotages run there.

One limitation is pinned rather than fixed: a scan-point **process restart** loses the in-memory
result buffer (encrypted local durability is deferred, submit.go / §6.5). F5 tests the
resumption path within a live process — where the per-chunk ack proves authoritative, not
decorative — and states that the process-restart buffer loss is the documented gap, has no
in-process seam to sabotage, and is therefore observed, not asserted with a hollow mutation.

## Review trigger

The next distributed fault case that resists injection through a real seam. The answer is
argued against this ADR: find the production seam and test there, drop the case with its reason
if a real client cannot reach it, or — if neither holds — that is the point to decide
deliberately whether a new kind of harness earns its keep, not to reach for a build tag.
