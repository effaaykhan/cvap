# ADR-102: Three of ADR-101's claims were false, and the login 504 was an oracle

**Status:** Accepted
**Date:** 2026-09-21
**Supersedes:** the corrected claims of ADR-101. ADR-101's mechanism — two bounds, a context
deadline and `SET LOCAL statement_timeout` — stands unchanged and is confirmed by independent
measurement. What is withdrawn is three of the things it said ABOUT that mechanism, one of which
shipped as a user-enumeration oracle.
**Follows:** ADR-101, ADR-041 (pre-tenant resolution), ADR-100 (`identity.refused` in its own
transaction).

ADR-101 was written alongside the code it describes, by the same author, in the same session. Three
reviewers were then told to review by MEASURING rather than reading. They measured it wrong in
three places. This ADR records what they found, because a decision record that is believed and
false is worse than none — the next session reasons from it.

## 1. The login 504 was a user-existence oracle. Withdrawn.

ADR-101 said: *"A timeout is the one fault that carries no signal about the user — it is a property
of how long a statement took — so it is checked explicitly and answered 504, leaving the
anti-oracle default intact for everything else."*

False, and the reason is structural rather than statistical. `login` has three phases, and
`refuse(readErr)` returns at the end of phase 2. **Phase 3 — the write — is reachable only when
`readErr == nil`, that is, only for an existing, active, local-auth account.** So a 504 from that
branch means "this account exists".

Measured, by holding the row lock `Credentials.RecordFailure` needs and then attempting login twice
with a wrong password:

```
EXISTING user: 504 {"error":"timeout", ...}   (30.3s)
UNKNOWN  user: 401 {"error":"unauthorized"}   (0.3s)
failed_attempts 1 -> 1 ; audit auth.login_failed 1 -> 1
```

Two things make it worse than the latency differential that already existed:

1. **It is a clean positive.** No statistics, no timing measurement: the attacker repeats until one
   504 appears, and a 504 is always conclusive where a 401 never is.
2. **The probe is free.** `failed_attempts` did not move and no `auth.login_failed` row was
   written, because the timeout rolled the whole transaction back. It is the one probe that
   neither counts toward lockout nor leaves a durable trace — this finding and ADR-101's own
   refusal-rollback consequence compose into each other.

**Decision: the exception is withdrawn.** The login surface answers ONE status for every fault, in
every phase, as its anti-oracle default always said. The timeout is still metered and logged, so
the operator keeps the signal; the status code is the part an attacker reads.

**What this does not fix.** A phase-3-induced timeout still answers 500 where an unknown user gets
401. That differential predates ADR-101 and is not reachable by any change to the response: it
exists because the unknown-user path never opens a write. Closing it requires moving the
failed-attempt record and the audit event into their own transaction — which ADR-101 already filed
as the durable fix for a different reason. **That move is therefore not optional, and this is the
second independent argument for it.**

Related: `isInfrastructureError` enumerates the sentinels it treats as faults and DEFAULTS to
"refusal", so `ErrStatementTimeout` — added to the store by ADR-101 and not to that list — made a
phase-1 timeout answer *401 "Those credentials are not valid."* Measured under 16 concurrent
budget-length holders from another tenant: `401 ... (58.6s)`. That is exactly what the comment on
the next branch forbids. Both new sentinels are now listed explicitly.

## 2. "A transaction that times out COMMITS NOTHING" is false. Measured twice.

That sentence carried ADR-101's Consequences section, its lease-fencing argument, and the premise
of its refusal-loss section.

Sweeping the deadline across the COMMIT round trip, independently, twice:

| run | trials | err + rolled back | **err + DURABLE** | ok + durable | ok + LOST |
|---|---|---|---|---|---|
| review | 160 | 96 | **12 (7.5%)** | 52 | 0 |
| reproduction | 400 | 22 | **42 (10.5%)** | 336 | 0 |

```
store: commit: store: statement exceeded its time budget: timeout:
context deadline exceeded — yet the row is durable
```

When the deadline lands during the COMMIT round trip, the server commits and the client is told it
timed out. **`ok + LOST = 0` in both runs**, so the direction ADR-101 named as dangerous — a write
landing without its epoch check — remains unreachable, and the lease-fencing conclusion survives.
The sentence does not.

**Decision:** a timeout is *in doubt*, not *nothing*. Code that needs to know whether a write landed
must ask the database rather than infer it from the error. Recorded in
`internal/store/CLAUDE.md`, which is where the next author will look.

Concretely, and left open: a `Leases.Renew` that commits while Core answers the scan point as
failed leaves the database fenced to an epoch the scan point has abandoned; an `offerWork` that
commits while Core logs an assignment failure leaves a job leased to a scan point never told about
it. Both recover through lease expiry. Neither is "commits nothing".

### 2a. What commit-in-doubt does on the packet path, measured end to end

The scan-safety audit took the same window and drove it through dispatch. Sweeping the deadline
across the commit in 133 us steps, **51 of 240 trials committed while returning
`store: commit: store: statement exceeded its time budget`**. The round trip is ~6.8 ms wide on
this database — so for an arbitrary over-budget 30 s transaction the natural rate is ~0.02%, and it
widens with WAL and fsync latency.

**A scan the operator sees as failed, cannot cancel, and which put targets on a wire.** The chain,
measured, not reasoned about:

1. `PlanScan` returned `ErrStatementTimeout` with the plan **committed** — scan `running`, one
   queued job.
2. `PlanPending`'s error branch then ran `Scans.Fail` under its own healthy budget: scan `failed`,
   `scan.planning_failed` audit.
3. The operator's `Scans.Cancel` refused — `scan is not in a cancellable state` — because
   `Scans.Cancel` accepts only pending/planning/running.
4. `Jobs.Claim` excluded only `cancelled`/`killed`, and `Jobs.CancellableFor` matched only those
   two. So the job stayed claimable and was never covered by cancellation propagation.

Result on a live dispatch session: `assignment on the wire: job=... scan=<the failed scan>
targets=8 epoch=1 allowed=[192.0.2.0/24]`. **Eight targets, from a scan nothing but a kill switch
could stop** — and see §5a for what the kill switch does under the same conditions.

**A credential release recorded as delivered that was never delivered.** With a resolver returning
at `deadline − δ`, 4 of 9 trials committed while `offerWork` took its error branch: a
`credential_grants` row naming the scan point's fingerprint as recipient, a `credential.granted`
audit event, a job `assigned` with a live lease — and nothing on the wire. The grant material is
correctly discarded, and the non-`reassign_safe` job then dies at lease expiry with `lease_lost`.
The audit trail says a credential was released to a scan point that never received it.

**Decision:** `Jobs.Claim` and `Jobs.CancellableFor` now exclude `failed` scans as well. That is the
single change that makes the dispatch chain unreachable regardless of commit-in-doubt: a job whose
scan is failed has no business on a wire under any story, and one already dispatched is recalled
rather than merely withheld. The deeper fix — `PlanPending` re-reading the scan's state in a fresh
transaction before calling `Scans.Fail`, and every other caller that reads "error implies nothing
happened" — is filed as B52, because it is a pattern across call sites rather than one predicate.

Non-negotiable #7 is NOT violated by any of this: nothing was fenced wrongly, no write landed
without its epoch check, and no probe produced a half-renewed lease or two holders.

## 2b. The bound turned the in-flight scope check from fail-closed into fail-open

The worst of the findings, because it is a safety invariant rather than an availability one.

`scopeNarrowedForJob` returns "not narrowed" on any read error, deliberately: a database blip must
not self-abort every in-flight job and zeroise the fleet over a transient. ADR-101 made
`ErrStatementTimeout` a **systematic** member of that error set and said nothing about these two
branches.

Same job, same narrowed policy, one variable:

| condition | answer | elapsed |
|---|---|---|
| healthy database | `LEASE_STATE_LOST` — `target "192.0.2.7" is no longer in scope` | **6.5 ms** |
| `policy_scope_rules` over budget | **`LEASE_STATE_GRANTED`**, lease extended 60 s | **30.0085 s** |

The job's only target is excluded by the live policy, and it keeps its lease and keeps scanning.
Before the bound, a contended read blocked and eventually returned the *correct* refusal: the bound
converted "late and correct" into "on time and wrong". And the trigger is a property of the TABLE,
not of one job — one slow plan on `scan_policies`/`policy_scope_rules` fails every in-flight job's
re-check open simultaneously, which is the mass event the fail-open was written to prevent,
arriving from the other side.

**Decision: a blip fails open, a budget fails closed.** A timeout is not evidence that the scope is
unchanged; it is the database being unable to say, for a full budget, whether packets may still go
to this target. Non-negotiable #10 is not something to infer from a missing answer. Every other
read error still fails open and the next renewal asks again.

## 2c. One renewal could outlive the lease it renews

`onLeaseRenewal` runs three bounded transactions in series — `windowClosedForJob`,
`scopeNarrowedForJob`, `Leases.Renew` — each entitled to `dispatchBudget`. Measured with
`scan_policies` over budget: **60.037 s to answer one renewal, against `LeaseTTL` of 60 s.** The
lease died while Core was composing the answer about whether to extend it.

This is ADR-101's own finding recurring one level up: `dispatchBudget` bounds a statement group, and
nothing bounded the renewal. The ADR's justification for that number — "a handover, an ack and a
lease renewal are single-row statements" — is not true of a renewal.

**Decision:** the whole renewal takes `LeaseTTL/4`. `context.WithTimeout` keeps the earlier
deadline, so each leg still gets at most `dispatchBudget` and the whole gets at most a quarter of
the TTL.

## 2d. The background loops' first statement was unbounded

`db.ActiveTenantIDs` runs `db.pool.Query` directly — no `inTx`, no deadline, no GUC. Measured
blocked for **1m15s** with no error and no log line. It is the first statement of the dispatch
sweeper (ADR-012 lease expiry and `PlanPending`) and of the correlator, so one stall there freezes
lease expiry and the whole correlation pipeline indefinitely.

ADR-101 named exactly one unbounded exception and called it "a decision rather than an omission".
There were two. Now bounded at `PreTenantBudget`.

## 3. The budget table described code that did not exist

ADR-101 said `BulkBudget` goes to "exports, sweeps, the correlator, ingest". Measured: the CSV
exports ran on `db.Read` — the 30 s operator budget — and the dispatch sweeper takes
`dispatchBudget`, which is also the operator number. Only the correlator and ingest ever took bulk.
The same false claim appeared in four places, one of them the operator-facing
`bulk_budget_seconds` doc string on Health.

B50 had asked specifically for "a bulk-read bound of 120 s the CSV exports pass explicitly".

**Decision:** exports now take `BulkBudget`, which is what every text already claimed. The sweeper
keeps the operator budget — its statements are single-row — and all four texts now say so.

## 4. Two smaller corrections to ADR-101's text

- **The ADR-002 attributions are wrong.** ADR-002 is 53 lines and says nothing about `SET LOCAL`,
  transaction scoping, SQLSTATE 42501, or splitting `ErrTenantIsolation` from `ErrNotPermitted`.
  Both attributions belong to `internal/store/CLAUDE.md`.
- **The "five refusal paths" are three.** Items 4 (ingest) and 5 (`identity.refused`) were listed
  as exposed and then described as already correct — which they are. The genuinely exposed set is
  login, `changePassword`, and the OIDC state consume. As written, a reader fixing "the five paths"
  fixes two things that are not broken.
- **The OIDC hazard was overstated.** ADR-101 called the state-consume rollback the worst of the
  three because it RESTORES a redeemable single-use state. True at the store, measured exactly —
  the row returns and a second `Consume` succeeds. But driving the real handler shows the
  wrong-binding branch returns immediately after `Consume`, so no statement follows the `DELETE` on
  an attacker's path: the window is the COMMIT round trip, ~1 ms, not 30 s. The longer window
  exists only on the success path, where the holder is the legitimate user and the cost is a retry.
  Real, far smaller than stated, and worth correcting precisely because an over-stated risk in a
  decision record is how the genuine one gets deprioritised.

## 5. New decisions this review forced

**Out of connections is not a slow query.** `inTx` mapped a failed `pool.Acquire` through
`mapError`, turning pool exhaustion into `ErrStatementTimeout`. Measured with `MaxConns=1` and
another tenant holding the connection, a `SELECT 1` came back as:

```
store: acquire: store: statement exceeded its time budget: context deadline exceeded
```

— a 504 whose Health doc string tells the operator "each one names a statement that reached a plan
nobody measured. Profile it." The statement was `SELECT 1`, and it never ran. Worse, it is metered
against the tenant that WAITED, so the noisy tenant's load moves the victim's counter — the exact
cross-tenant signal ADR-101 made the meter per-tenant to avoid. New sentinel `ErrPoolExhausted`,
**503 `capacity`**, not metered as a query timeout.

**An anonymous caller must not move an operator's number.** `resolveTenant` puts the tenant in the
context BEFORE authentication, so an unauthenticated login request metered a real tenant's
`timed_out_requests` from 0 to 1, unbounded by repetition and poisoning `last_timeout_at`.
Anonymous timeouts now go to their own `timed_out_anonymous_requests`, documented as a load signal
that an attacker can drive and NOT a list of queries to profile.

**The pre-tenant path is bounded.** ADR-101 disclosed `resolvePreTenant` as unbounded; the review
measured `ResolveDomainTenant` blocking **28.1 s** under load, on every request including
unauthenticated ones. Go's `http.Server` `WriteTimeout` does not cancel a request context, so a
handler blocked before its first write is never cancelled. `PreTenantBudget` is 5 s — far below
`OperatorBudget`, because these are three single-row indexed `SECURITY DEFINER` lookups and
anything slower is a deployment in trouble.

**One helper, not thirteen branches.** The bound fired at sites ADR-101 never considered: the
session `Lookup`+`Touch` write that runs on EVERY authenticated request answered 500 unmetered, as
did all nine OIDC sites. `(*Server).internalError` is the flat-500 path with the one exception the
budget earns, so the next site added inherits it.

## 6. Why the original review missed all of this

Every finding above produces a correct-looking result at the `storeError` boundary and a wrong one
at the handler. ADR-101's four API tests drove `storeError` directly with a synthetic error against
a hand-built `&Server{}`; not one made a real handler time out. `internal/control/api/CLAUDE.md`
already states the rule that would have caught it: if the harness cannot express the attack, the
test cannot find it.

The store-side tests did not have this problem — they assert against the database, and they held up
under re-measurement.

## 6a. What the safety audit confirmed — the cheap confirmations

These were measured and hold, so they stop being open questions:

- **The correlator's atomicity claim is true.** 40 sweeps cut off at points spread across
  `resolveHost`: **zero partial states** — no observation resolved against an absent asset, never
  more than one open address interval, no identity key without a sighting, no closed interval left
  unreopened. A final clean sweep resolved all 42 observations. One of the 40 was a commit-in-doubt
  and was benign there, because the next sweep does the same thing again.
- **At-most-once accounting survives.** 30 cut-off sweeps over a growing backlog of expired leases:
  `lease_lost` failures always equalled `job.lease_lost` escalation audits (33 vs 33), zero
  mismatches, no job left `assigned` on a dead lease, none requeued that should not have been.
- **The START side fails closed.** With `policy_scope_rules` unreadable for 40 s the session
  dispatched **nothing** — the job was withheld, not dispatched with an empty or stale allowlist —
  and after recovery went out with `allowed=[192.0.2.0/24] rate=120`. `PlanScan` likewise left
  scans plannable rather than half-planned.
- **Zeroise ordering is unchanged, and the window is now bounded.** A released SSH private key sat
  in Core's heap for **30.052 s** under a stalled `credential_grants` write, where before the bound
  it was open-ended. Non-negotiable #8's ordering is untouched; what changed is that the window has
  a number. Nothing reached the wire during the stall and recovery was clean.

## 7. Still open

- The three refusal records (login, `changePassword`, OIDC consume) move into their own
  transactions. Now carries two independent arguments: the record survives a timeout, AND the
  unknown-user path opens a write, closing §1's residual differential.
- `mapError` uses `%s` on the pg detail for five cases, so `errors.As(err, &pgErr)` fails
  downstream and no caller can ever discriminate on SQLSTATE after the fact. Pre-existing.
- Ingest's `sub.lastAccepted` is assigned inside the closure and read on the `RETRY_LATER` path
  even when the transaction rolled back, so an ack can name a chunk that never committed. Measured
  inert — the scan point advances only on `ACCEPTED` and `resume()` rehydrates from the row — but
  it contradicts the comment two lines above it.
- 504 is not in the generated OpenAPI document; `errorStatuses` emits 400/401/403/500 for every
  route and says that set is "true of every endpoint by construction". It no longer is.
- **ADR-024's kill bound and `dispatchBudget` disagree, and the kill read joins `scan_jobs`.**
  Measured: healthy, a kill propagates in **1.94 s**; with `scan_jobs` over budget it was **not
  delivered at 240 s**, because `killCoversScanPoint` EXISTS-joins that table even for a
  tenant-scoped kill, and because the pump is one goroutine running kills, then cancellations, then
  `offerWork`, each now entitled to a full `dispatchBudget`. ADR-024 says 10 s and "not
  adjustable"; `dispatchBudget` is 30 s. The bound did not create this — an unbounded read was
  worse — but it put a number on the dispatch path and the number is 3x the one the kill switch is
  promised. Reconciling them needs ADR-024's own argument reopened, not a constant changed here.
- **A renewal whose write goes over budget is answered with silence** — no message sent, the scan
  point learns only from its own clock and self-aborts at TTL. Fencing intact, fails closed, costs
  a job.
- B48, the plan work, is untouched by any of this.
