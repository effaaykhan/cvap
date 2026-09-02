---
name: recurring-findings
description: Recurring security defect classes found in CVAP reviews, and the repo-specific constraints that shape acceptable fixes
metadata:
  type: project
---

Defect classes that recur in CVAP and are worth checking first in any review.

**1. Self-asserted trust fields.** The contract and code repeatedly let a scan point state
something about itself that Core must decide: `Hello.scan_point_id`, `Observation.zone_id`,
`Capability`, `EnrollRequest.hostname`, `RotateRequest.current_fingerprint`. ADR-008 is
explicitly honoured in one place (no `zone` on `EnrollRequest`) and silently defeated in
another (`Observation.zone_id`, which has no authenticated source). Sweep for this pattern
every time.
**Why:** a scan point sits in a network whose compromise the threat model assumes (ADR-020),
so anything it asserts is attacker-controlled input.
**How to apply:** for each scan-point-originated field, ask "what does Core do differently
because of this value, and is the peer certificate the real source?"

**2. Secrets leaking through generated `String()`.** `internal/logging` redacts by attribute
*key*, so `slog.Any("req", msg)` or `fmt.Errorf("%v", grant)` defeats it entirely. Generated
protobuf types implement `String()` and render every field. protobuf-go does **not** honour
the `debug_redact` field option in `String()`/prototext — verified by grep, most recently at
v1.36.11 — so a fix that only marks fields `[debug_redact = true]` is decorative without a
reflection-based scrubber. `internal/logging.Proto` is that scrubber. The two `.proto`
comments still name v1.36.6, the version the claim was first verified against; editing them
needs CVAP_ALLOW_PROTO_EDIT and is not worth a contract edit on its own.
**Why:** ADR-020 forbids credentials reaching any log; the redactor's own doc comment claims
no type holding credential material implements `String()`, which the generated code breaks.
**How to apply:** flag any code path that logs or wraps a whole proto message.

**3. Comments that overclaim a defence.** Several fields are documented as security controls
but are attestations or theatre (`current_fingerprint`, `Heartbeat.observed_rate_pps`). The
codebase gets this right once — `JobTerminal.credentials_zeroised` is explicitly labelled
"an attestation, not a control" — so the fix is to hold every other field to that standard.
Also appears as a *factually wrong mechanism story* attached to a control that is fine on its
own: `ca.CA.LogValue`'s comment claims fmt would otherwise "render the private scalar", but
fmt prints pointers at depth > 0 as addresses, so it would not. Verify the stated mechanism,
not just the conclusion — the next author generalises the story, not the code.
**Why:** a field documented as a defence gets relied on as one by the next implementer.
**How to apply:** ask whether the field stops an attacker who already satisfies the
surrounding control (usually mTLS); if not, say so in the comment.

**4. A defence enumerated as a denylist, with the escape one hop off the list.** Seen twice
in `internal/store`: the AST encapsulation guard forbids `pgx.Conn`/`pgx.Rows`/`pgx.Tx` but
not `pgx.Batch`, and `Conn.SendBatch(*pgx.Batch)` accepts caller-attached
`QueuedQuery.Query(func(pgx.Rows))` callbacks that pgx invokes with a live `pgx.Rows` —
`rows.Conn()` returns the pooled `*pgx.Conn`. Same shape in `.claude/settings.json`, where
`Read(**/.env.*)` was replaced by five enumerated filenames.
**Why:** these guards are written after a specific leak is found, so they encode that leak's
shape rather than the property. The next leak is a different type reaching the same value.
**How to apply:** for any denylist, ask what the *allowed* set is instead. In the store's
case: does the type accept a caller-supplied function or a type carrying one? Also check
what the AST guard structurally cannot see — it walks `*ast.FuncDecl` and `*ast.StructType`
only, so interface method signatures, type aliases and package-level vars are unchecked.

**5. `Conn.Exec` takes arbitrary SQL, so tenant scoping in this package is a convention
above the pgx layer, not an enforced property.** A bare `COMMIT` through `Conn.Exec` ends the
transaction while `Conn.done` stays false, which discards the `SET LOCAL` and lets a plain
`SET app.tenant_id` stick onto the pooled connection. `pgxpool.Conn.Release` destroys a
connection only when `TxStatus() != 'I'`, so a self-committed connection is recycled dirty.
**Why:** the package's whole claim is "the database does the clearing; we cannot forget it",
which holds for panic, cancellation, unread rows and rollback (all verified) but not for a
callback that ends its own transaction.
**How to apply:** when a design says a property is unrepresentable, find the arbitrary-input
surface — here, the SQL string — and check the property against it specifically.

**6. Schema-level assertions that assert everything except the one the object depends on.**
Migration 0015 asserts five properties of `tenant_for_scan_point` but not that its definer
can actually read past `FORCE ROW LEVEL SECURITY` on `scan_points`. It works today only
because the migration role is a SUPERUSER; with a non-superuser owner it raises 42704, which
turns the deliberately NULL-returning lookup back into the error oracle the ADR forbids.
**Why:** every table in this schema is `FORCE ROW LEVEL SECURITY`, so table ownership alone
does not let a `SECURITY DEFINER` function read it.
**How to apply:** for any `SECURITY DEFINER` function, check the definer role's attributes,
not just the function's, and check it under a non-superuser definer.

**7. A hand-written secret type that closes `String`/`GoString`/`LogValue`/`MarshalJSON` is
still not closed.** Verified empirically on `enrollment.PlaintextToken` at Go 1.25: `fmt`
consults `Stringer` only for `%v %s %q %x %X`, so **any other verb** (`%d %b %o %O %c %U %e
%f %g %t`) falls to reflection and prints the unexported string in full, via `badVerb`. And a
`PlaintextToken` held in an **unexported field of a containing struct** leaks under plain
`%v`/`%+v`/`%#v`/`%s`/`%q`, because `reflect.Value.CanInterface()` is false there so `fmt`
never calls `String()` at all. `go vet`'s printf check catches the wrong-verb case (constant
format strings only) and catches nothing in the unexported-field case.
**Why:** these types are the last line under ADR-020 once a value is past the key-based
redactor, and the doc comments assert "every rendering path is closed".
**How to apply:** demand `fmt.Formatter` (`Format(fmt.State, rune)`), which `handleMethods`
consults before any verb switch and so covers every verb, value, pointer, slice, map and
exported field. For the unexported-field case the only structural fix is to make the field a
type reflection cannot render — a `func() string` closure prints as an address at every verb.
`encoding/gob` is already safe (no exported fields); `text/template` `{{.Reveal}}` is not.

**8. Attacker-chosen asymmetric-crypto cost, performed before authentication.** In
`Enroll`, `ca.ParseCSR` (parse + `CheckSignature`) runs before the token is even shape-checked,
and `checkPublicKey` bounds RSA below (>= 2048) but not above — and it runs *after*
`CheckSignature`. Measured: a 16,323-byte CSR (under the 16 KiB cap) carrying a 65,000-bit
modulus costs ~38 ms per call versus ~30 µs for RSA-2048, so ~26 unauthenticated req/s
saturates a core. No private key is needed; a garbage signature still forces the modexp.
**Why:** the enrollment RPC is by design reachable pre-auth, and a byte-count cap does not
bound the *work* a parser is asked to do.
**How to apply:** for any pre-auth parser, ask what the most expensive input under the size
cap costs, order the cheap checks first, and put type/size gates before signature checks.

**9. Guards and assertions that structurally cannot fire.** `encapsulation_test.go` ends with
`if strings.ToUpper(string("resolveTenant"[0])) == string("resolveTenant"[0])` — two constants,
always false, dead. The same test only inspects four hardcoded names, while ADR-033 and
`internal/store/CLAUDE.md` both claim it "checks the class", so a fifth `Resolve*Tenant`
wrapper would pass. This project's own rule is that a gate which silently passes is worse than
one that fails, because the first gets trusted.
**How to apply:** for every mechanical guard, construct the violation it claims to catch and
run it. If it passes, that is the finding.

**10. `ON DELETE SET NULL` against a biconditional `CHECK`.** `enrollment_tokens` pairs
`(redeemed_at IS NULL) = (redeemed_scan_point IS NULL)` with
`FOREIGN KEY (tenant_id, redeemed_scan_point) ... ON DELETE SET NULL (redeemed_scan_point)`.
Deleting an enrolled scan point nulls one side and violates the check, so the DELETE fails —
verified on the dev database. Sibling tables declare `ON DELETE CASCADE` from the same parent,
so the schema clearly expects deletion to work.
**How to apply:** whenever a referential action mutates a column, check every `CHECK` that
mentions that column, and actually run the DELETE.

**11. Identity is resolved correctly and then the OBJECT is not bound to it.** Distinct
from #1 and worth its own sweep, because the code that gets #1 right often gets this wrong in
the same file. Dispatch resolves the scan point from the TLS peer certificate and refuses a
mismatched `Hello.scan_point_id` — and then passes `JobTerminal.job_id` / `JobProgress.job_id`
straight into `Jobs.Terminate` / `Jobs.MarkRunning` / `Leases.Release`, whose predicates are
`tenant_id = $1 AND job_id = $2` with no `scan_point_id` / `holder_scan_point` clause. Proven:
scan point B marks a job held by A `completed` and releases A's lease, so A self-aborts and the
scan silently under-reports. `Leases.Renew` is the counter-example done right — it takes the
holder from the session and puts it in the predicate.
**Why:** RLS bounds the *tenant*, and within a tenant every scan point sees the same rows, so
tenant scoping reads like authorisation and is not.
**How to apply:** for every store method reachable from a wire message, list the WHERE clause
and ask which of (tenant, actor, object state) it constrains. Anything that constrains only
tenant + object id is an intra-tenant IDOR.

**12. A normative MUST written into the contract AND the schema comment, and unimplemented in
the one function that could honour it.** `Observation.zone_id` carries "Core MUST validate this
against the zones assigned to the authenticated scan point ... MUST be quarantined" in
`ingest.proto`, and the same sentence again on `COMMENT ON COLUMN scan_points.zone_id` — and
`IngestService.toObservations` only `uuid.Parse`s it. The FK is `(tenant_id, zone_id)`, so any
zone in the tenant passes, and ADR-008's exposure derivation is rewritable by the scan point.
The enrolled zone was already in hand: `GetByFingerprint` returns `sp.ZoneID` and the caller
discarded it.
**Why:** in this repo the prose is written before the code, so a MUST in a comment reads as
implemented to the next reviewer.
**How to apply:** grep the proto and the migration comments for "MUST" and check each one has a
call site. Do it for the whole message, not just the fields the diff touched.

**13. Attacker-chosen values reaching a partition key, a typed column, or a global unique
index. Verified on the dev DB, all three.** `observed_at_unix` from the wire becomes the
`observations` partition key: one observation dated inside a future month lands in
`observations_default` and then `CREATE TABLE observations_2027_03 PARTITION OF observations`
fails with "updated partition constraint for default partition would be violated" — a
deployment-wide ingest outage from one field. `confidence` (CHECK 0..1, `numeric(4,3)`) and
`payload` (`jsonb`, so `""` is invalid) fail the whole chunk, and the handler answers
RETRY_LATER "keep the buffer", so an unparseable value becomes an infinite retry loop instead of
REJECTED_MALFORMED. `result_submissions_pkey` is `PRIMARY KEY (submission_id)` — **global**,
not per tenant, despite a sibling `UNIQUE (tenant_id, submission_id)` — so a scan-point-chosen
string collides across tenants and the loser is told REJECTED_DUPLICATE, clear your buffer.
**Why:** ingest is the first place untrusted input reaches typed columns; the store layer maps
every failure to a sentinel and the handler picks the ack from the sentinel, so a validation gap
becomes a wrong instruction to the scan point rather than a visible error.
**How to apply:** for each wire field, name the column, its type, its CHECK, whether it is a
partition key, and whether any unique index over it omits `tenant_id`. Validate in Go before the
INSERT so the failure is REJECTED_MALFORMED.

**14. A teardown that waits on a goroutine whose only exit the teardown blocks.**
`dispatch.Connect` runs `cancel(); wg.Wait()`, where the writer goroutine's exit is
`stream.Send` returning — and grpc-go's `writeQuota.get` selects on the *stream's* done channel,
which closes only when the RPC handler returns. Client calls `CloseSend()` and stops reading:
`receive` returns io.EOF, the writer is parked in `Send`, `wg.Wait()` never returns, the handler
never returns, the stream never closes. Demonstrated: `Connect` still had not returned 15 s
after half-close. The package's `fakeStream.Send` returns nil unconditionally, so the tests
cannot see it.
**Why:** cancelling a context *derived from* `stream.Context()` does not cancel the RPC.
**How to apply:** on any streaming handler, ask what unblocks each goroutine and whether the
handler returning is on that path. A test double whose Send never blocks is not evidence.

**15. A fan-out predicate narrowed without narrowing its inverse, so the measurement the
control depends on stops being satisfiable.** Session 8e replaced `KillSwitches.Live` (every
live kill to every scan point) with `LiveFor(scanPointID)` and left
`KillSwitches.Unacknowledged` selecting *every* recently-heartbeating scan point in the tenant
that has no ack row. Demonstrated: a zone kill covering 1 of 2 scan points, the covered one
acks, and `Unacknowledged` still names the uncovered one — forever, since it was never sent
the message it is being chased for. ADR-024's own argument is "a bound Core cannot measure is
not a control"; narrowing delivery without narrowing the expectation converts the measurement
into permanent noise, which is worse, because an operator learns to ignore it.
**Why:** delivery and acknowledgement are written in different functions and often different
sessions, and only one of them looks like "the change".
**How to apply:** whenever a "who receives X" predicate changes, grep for the "who still owes
X" predicate and diff the two by hand. The right fix is to define the coverage predicate ONCE
(a SQL function over `(kill_switch_row, scan_point_id)`) and call it from delivery, from the
claim block, and from the unacknowledged set — three copies of a scope test will drift.

**16. A safety predicate keyed on the CURRENT assignment, for a control whose whole premise is
that the current assignment is no longer trustworthy.** `LiveFor`'s scan-scope branch and
`Jobs.CancellableFor` both require `scan_jobs.scan_point_id = $sp AND j.status IN
('assigned','running')`. `Leases.ExpireLeases` sets `scan_point_id = NULL, status='queued'` for
reassign_safe jobs and `status='failed'` for the rest, so both predicates stop matching the
moment Core expires the lease. Demonstrated: `LiveFor=1 CancellableFor=1` before expiry, `0 0`
after, while the scan point may still be executing. The durable record of who held the job is
`job_leases.holder_scan_point`, which expiry does not clear.
**Why:** ADR-012 says the scan point self-aborts on renewal failure, so the code reads as
covered — but the kill switch exists precisely because self-abort cannot be relied on.
**How to apply:** for any "stop this" predicate, ask what Core does to its own rows when it
gives up on a job, and re-derive the predicate from a column that survives that.

**17. An acknowledgement table with no precondition, so the attestation can be filed before it
is asked for.** `CancelAcks.Record` checks only `epoch > 0`; it does not check that the job's
scan is `cancelled`/`killed`, that this scan point holds the job, or that the epoch matches the
live lease. `CancelAcks.Unacknowledged` keys on `(tenant, job_id, scan_point_id)` with no
`acked_at`/`lease_epoch` term. Demonstrated: a scan point acks its own job at a fabricated
epoch before any operator action, and when the scan is later cancelled it is already outside
the chase set. `ForScan` renders latency `-1ms` and nothing flags negative. Three separate
comments (proto `CancelAck.lease_epoch`, migration 0025, `internal/store/cancel.go`) promise
the epoch makes a stale ack *visible rather than counted*; no code reads it — class 12 again.
A foreign-job ack is also accepted, which does not hide the real holder (that join is correct)
but writes forged rows into an append-only table `cvap_app` has no DELETE on.
**Why:** the ack row is treated as a receipt, but nothing establishes that a request was ever
sent, so the receipt is unilateral.
**How to apply:** for every `*_acks` table, write the INSERT as `INSERT ... SELECT ... WHERE`
over the rows that prove the request was issued to THIS actor, and make the "unacknowledged"
query require `acked_at >= requested_at` and a matching epoch.

**18. Operator-supplied documents parsed unbounded, per poll, inside the write transaction.**
`dispatch.parseWindows` caps nothing (`MaxWindowedPolicies` bounds the row count, not the array
length), `windowClosedPolicies` re-parses every windowed policy on every 2 s poll for every
connected scan point, and it runs inside `offerWork`'s `s.db.Write` closure, so a pooled
connection and an open transaction are held for the whole parse. Measured: 122 ms for one
policy with 10,000 `"tz":"Europe/London"` windows; `time.LoadLocation` is ~6 µs on a hit and
~17 µs on a miss with embedded tzdata and is NOT cached by the stdlib.
**Why:** the sibling caps (`MaxScopeRulesPerAssignment`, `MaxWindowedPolicies`) make the file
look bounded, and the parse is cheap for the shape anyone tests with.
**How to apply:** for each parsed column, name the cap on the container AND on its contents,
ask how often the parse runs and whether a DB transaction is open across it, and check whether
an expensive resolver inside the loop (tz, regex, DNS) is memoised.

**Constraint on fixes:** `proto/` is frozen additive-only within a major version (ADR-022),
enforced by `buf breaking` with the FILE category and a baseline established at bd0e4f9.
So a proto finding almost never gets fixed by removing or retyping a field. Acceptable fixes
are: a normative comment stating what the receiver MUST do, a new field at a new number, or
a wrapper type in Go. Recommend fixes in that form or they cannot be applied.
