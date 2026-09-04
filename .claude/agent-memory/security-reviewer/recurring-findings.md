---
name: recurring-findings
description: Recurring security defect classes found in CVAP reviews (31 classes), and the repo-specific constraints that shape acceptable fixes
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

**19. A stop path that races the start path it is meant to stop, so the stop is recorded and
then forgotten.** `runtime.onAssignment` puts the job in the table and `go r.runJob`s it;
`runJob` only assigns `j.host` and `j.cancel` several statements later. A `CancelJob` or
`KillSwitch` on the very next stream message finds `j.host == nil`, skips the stop, zeroises,
sends `JobTerminal{CANCELLED}` + `CancelAck{tasks_halted:N}` — and `runJob` then spawns the
engine and scans every target. `engineHost.stop` DOES set `stopRequested` when `h.cmd == nil`,
but `engineHost.start` never reads it. Reproduced 5/5 with a shell "engine" that touches a
marker file.
**Why:** the abort path is written as "stop the thing that is running", and the window where
the job exists but the thing does not is invisible from either function alone.
**How to apply:** for every "stop X" path, ask what happens if it runs before X exists. The fix
is a start that refuses when the stop flag is already set, not a wider mutex.

**20. A secret holder REPLACED rather than retired, so the zeroisation attestation answers
about the replacement.** `Runtime.onCredential` does `j.cred = NewCredential(...)` with no
check and no `Zeroise()` of the previous holder. Two `CredentialGrant`s for one job (an SSH key
and an SNMP community, say) leave the first material resident for the life of the process while
`j.cred.Zeroised()` returns true and `JobTerminal.credentials_zeroised` is sent as true.
Demonstrated: the first grant's bytes are still readable after the terminal path ran.
**Why:** `Credential` is carefully closed against every rendering path, which makes the holder
look like the whole control; the *lifecycle* of holders is a separate, unwritten concern.
**How to apply:** for any field holding a zeroisable secret, grep every assignment to it, not
just the reads. An assignment that is not preceded by a retire of the old value is a leak, and
any derived attestation is then false rather than merely incomplete.

**21. Crash-safety ordering reasoned about for the FIRST write and wrong for the second.**
`SaveIdentity` writes key, cert, chain, identity-last, arguing that a crash leaves
`ErrNoIdentity` and re-enrols cleanly. True at enrolment. At ROTATION the identity file already
exists, so it gates nothing: a crash between the `key.pem` and `cert.pem` renames leaves a new
key beside an old certificate, `LoadIdentity` succeeds, `MutualTLS` fails with "private key does
not match public key", and ADR-018 has no re-enrolment path — the scan point is permanently
dead. Reproduced. The durable fix is one rename that swaps both (a combined PEM), or a
`.prev` pair to fall back to; the parent directory is also never fsynced after `Rename`.
**How to apply:** for any multi-file atomic-ish write, run the argument a SECOND time with the
files already present. The sentinel that gates the first write usually does not gate the second.

**22. A conformance suite claimed at N sites and implemented at N-1.** `internal/scope` was
extracted so Core and the runtime share one matcher, and four comments
(`internal/scope/scope.go`, `internal/scope/scopetest/cases.go`, `internal/dispatch/scope.go`,
`internal/dispatch/scope_conformance_test.go`, plus `internal/scanpoint/CLAUDE.md`) state that
BOTH call sites run the shared table. `grep -rn scopetest` finds only the matcher's own test and
the Core-side one. The scan point — the site ADR-024 added *because* Core cannot be trusted
alone — has no call-site test at all.
**Why:** sharing an implementation removes the drift the comments worry about and creates the
illusion that the call sites are covered too; the shared package's own test looks like coverage.
**How to apply:** when a doc says "both sides are tested against X", grep for X's importers and
count them. Class 9 with a different surface.

**23. Unbounded accumulation UPSTREAM of the bounded buffer.** `submit.Submitter` is carefully
bounded (soft 16 MiB / hard 64 MiB, refuse rather than drop) and `enginewire.MaxLine` bounds one
message at 4 MiB — but `engineHost.pump` appends every observation to a slice with no count or
byte cap, and `Enqueue` is only reached after the job ends. Measured: a shell "engine" put
187 MiB into the runtime, 3x the hard bound, against a 512 MB RSS ceiling — in the process that
holds every job's credentials. `Enqueue`'s `&& len(s.queue) > 0` then accepts it unconditionally.
**Why:** the bound is placed at the queue because that is where the ADR talks about buffering;
the producer is a subprocess parsing hostile input by design.
**How to apply:** for every bounded buffer, walk BACKWARDS to where the data is first held and
check for a cap there. A per-message cap is not a per-stream cap.

**24. A counter whose whole job is to record a FAILURE, written inside the transaction that
the failure then rolls back.** `api.login` calls `Credentials.RecordFailure` and immediately
`return errors.New("password mismatch")` from the `db.Write` closure; `DB.inTx` does
`if fnErr != nil { return fnErr }` BEFORE `tx.Commit`, so the deferred rollback discards the
increment. Measured on the dev DB: `failed_attempts = 0` and `locked_until = NULL` after 15
wrong passwords, and the 16th with the correct password returns 200. Identical shape in
`api.changePassword`. The lockout was a table, two constants, a correct single-statement
UPDATE and a call site — everything except a commit.
**Why:** the surrounding style in this repo is "the audit event goes in the SAME transaction
as the thing it records", which is right for success paths and exactly wrong for failure
counters, so the wrong version looks like the house style.
**How to apply:** for every write whose purpose is to record that something went wrong, trace
the enclosing transaction to its commit. If the same code path returns an error, the write is
gone. The fix is a separate short transaction (or a `RecordFailure` after `Write` returns),
not a wider one.

**25. A deliberately expensive pre-auth computation held inside a pooled database
transaction.** `verifyPassword` runs argon2id at RFC 9106's 64 MiB / t=3 / p=4 *inside*
`s.db.Write`, so each unauthenticated wrong-password attempt against a KNOWN email holds one
of the pool's 16 connections (`store.Config.MaxConns` default) for ~48 ms and 64 MiB.
Measured: 24 concurrent login attempts took an unrelated `SELECT 1` from 0.73 ms to 5.1 s.
Core is one process — dispatch, ingest, lease renewal and the sweeper share that pool — so the
consequence is a fleet-wide stall and, via failed lease renewal, scan-point self-abort
(invariant 8). Class 8 with the cost chosen by *us* rather than by the attacker, which is why
the "bound the input" reflex does not help.
**Why:** the KDF cost is a feature and the transaction is there because `RecordFailure` needs
one, so both halves read as correct in isolation.
**How to apply:** for any pre-auth handler, list what it holds while it computes: a pool
connection, a lock, a goroutine. Read the row, close the transaction, THEN hash. And check for
a rate limiter — this package has none anywhere.

**26. An oracle closed carefully at one layer and reopened by the status code the layer above
chooses.** `tenant_for_domain` returns NULL identically for unknown, suspended and closed, and
`resolvePreTenant` collapses every failure to one sentinel — genuinely non-distinguishing. Then
`resolveTenant` maps that sentinel to 404 while every live tenant's login refusal is 401, so
`POST /v1/auth/login` with junk credentials answers "does a customer exist at this hostname"
exactly. Measured: 401 vs 404. Same shape one level down: `login` collapses unknown-user and
wrong-password to one body, and the argon2 that only runs for a real user separates them by
28x in wall time (48 ms vs 1.7 ms). `TestLoginIsOneRefusalForEveryFailure` compares status and
body and passes.
**Why:** each layer's author verified the property at their own layer, and the ADR text
("indistinguishable by design") describes the resolver, not the response.
**How to apply:** state the oracle as an end-to-end experiment — two requests differing in one
secret — and compare *everything* observable: status, body, headers, Set-Cookie, and elapsed
time. A test that asserts an indistinguishability property and only diffs the body is class 9.

**27. A guard applied to the value going IN, defeated by a rewrite on the way OUT.**
`isSafeReturnPath` (`internal/control/api/oidc.go`) refuses `p[1] == '/' || p[1] == '\\'`
because a browser normalises `/\evil.test` to `//evil.test` and leaves the origin. It gates
what is STORED in `oidc_auth_requests.return_path`. The value is emitted by
`http.Redirect(w, r, req.ReturnPath, 303)`, and `http.Redirect` runs `path.Clean` on any
leading-slash URL — which PROMOTES a backslash into position 1. Measured: `return_to=/./\evil.test`
is accepted by the Go guard and by the column CHECK `^/[^/\\]`, and the callback emits
`Location: /\evil.test`. Same for `/a/../\evil.test`. The test for it is self-checking:
feed the emitted Location back through the guard that accepted the input; if it fails, that is
the finding, and no browser is needed to prove it.
**Why:** validation and emission are in different functions, and the stdlib's normalisation
sits between them, so neither author sees the transformation.
**How to apply:** for any validated string that is later handed to a stdlib formatter
(`http.Redirect`, `url.JoinPath`, `filepath.Clean`, `template.URL`), re-run the validator on
the OUTPUT. A guard that only holds on input is a guard on a value nobody uses.

**28. A pre-auth token that is single-use and unguessable, and not bound to the browser.**
The OIDC `state` is 256 bits from crypto/rand, hashed at rest, redeemed by `DELETE ... RETURNING`,
tenant-scoped by RLS — every property except the one CSRF needs. No cookie is set at
`/v1/auth/oidc/start`, so nothing ties the callback to the user agent that began the flow.
Measured: an attacker starts a login from their own client, has the victim's browser open
`/v1/auth/oidc/callback?code=…&state=…`, and the victim's browser receives a working session
for the ATTACKER's account (`GET /v1/auth/session` returns the attacker's user id and role).
In a vulnerability platform that is an operator entering scan credentials into an account the
attacker reads. OAuth 2.0 Security BCP §4.7 is explicit that `state` must be bound to the user
agent; replay protection and CSRF protection are different properties of the same parameter and
the codebase only implemented the first.
**Why:** "single-use" and "unguessable" feel like the whole of what `state` is for, and every
test that exercises start-then-callback uses two cookieless requests, so the property is
invisible from the suite.
**How to apply:** for any multi-step flow, ask what ties step 2 to the BROWSER that did step 1,
not merely to the server-side row. If the answer is nothing, write the probe where two different
clients do the two steps.

**29. A boolean guard that describes a DIFFERENT field than the one it guards.**
`resolveOIDCUser` links an account by email only when the IdP asserts `email_verified` — and
`tenant_auth_config.oidc_email_claim` lets an operator point the address at another claim.
`email_verified` is defined by OIDC Core 5.1 as a statement about the `email` claim, so with
`oidc_email_claim = 'upn'` the flag vouches for a value it says nothing about. Measured: a token
with `email: mallory@… (email_verified: true)` and `upn: op@…` links the attacker's subject to
the OPERATOR's account and returns the operator's session. Two separate defects in nine lines
(`oidc.go`, the `cfg.OIDCEmailClaim != "email"` block): the flag is decoupled from the value,
and when the configured claim is ABSENT the code silently falls back to the `email` claim the
operator overrode precisely because they did not trust it.
**How to apply:** whenever a check and the value it protects are named by different
configuration, write down what the check is defined to assert. If a config knob can move the
value and not the check, they are no longer the same fact.

**30. A transport check applied to N-1 of the N URLs in one untrusted document.**
`providerCache.get` loops over `authorization_endpoint` and `token_endpoint` demanding https,
and does not check `jwks_uri` — the one URL whose integrity every signature verification
depends on. go-oidc does not check it either. Measured: a discovery document naming
`jwks_uri: http://…` completes a login, so the signing keys arrive over cleartext and an
on-path attacker substitutes a key set and forges an ID token for any subject.
**How to apply:** enumerate every URL a fetched document can name, not the ones the code
happens to have variables for, and check the list against the scheme/host guard.

**31. A size bound at the fetch the author wrote, absent at the fetches the library makes.**
`exchangeCode` wraps the token response in `io.LimitReader(resp.Body, 1<<20)`. go-oidc's
`NewProvider` (oidc.go:312) and `RemoteKeySet.updateKeys` (jwks.go:315) both `io.ReadAll` with
no limit, through the same hardened client — whose `MaxResponseHeaderBytes` and `Timeout` bound
headers and time but not body size. Measured on the dev box: one UNAUTHENTICATED
`GET /v1/auth/oidc/start` against a 256 MiB discovery document = 2202 MiB TotalAlloc, HeapSys
2279 MiB, and it still returned 200; a padded JWKS at the callback = 2458 MiB. Core is one
process holding dispatch, ingest and lease renewal.
**Why:** the presence of a LimitReader in the same file reads as "bodies are bounded here".
**How to apply:** for every outbound fetch, name which of (dial, TLS, headers, body-time,
body-SIZE) is bounded, and check the ones the library owns by reading its source, not the
client config. A `*http.Client` cannot express a body-size cap.

**Confirmed-good patterns worth NOT re-deriving.** Two properties this review measured and
found correct, both of which earlier sessions got wrong: (a) the OIDC callback releases its
pool connection BEFORE the network round trip to the IdP — 40 concurrent callbacks parked in a
hanging token exchange moved an unrelated `SELECT 1` from 0.78 ms to 1.7-5.1 ms, i.e. no
starvation, which is class 25 correctly applied; (b) `OIDCAuthRequests.Consume`'s
`DELETE ... RETURNING` under READ COMMITTED gives exactly one winner — 4 concurrent callbacks
on one state, 6/6 rounds, one session each time. Do not re-litigate either without new evidence.

**Constraint on fixes:** `proto/` is frozen additive-only within a major version (ADR-022),
enforced by `buf breaking` with the FILE category and a baseline established at bd0e4f9.
So a proto finding almost never gets fixed by removing or retyping a field. Acceptable fixes
are: a normative comment stating what the receiver MUST do, a new field at a new number, or
a wrapper type in Go. Recommend fixes in that form or they cannot be applied.

**32. Verdicts parsed from a prose excerpt an attacker shapes.** `internal/rules` HTTP
evaluators (`httpResponse` in evaluators.go) reconstruct status and headers from the
fingerprint engine's *sanitised evidence excerpt* — one line, CR/LF collapsed to spaces —
not a structured field. The scanned host controls that byte stream. Measured (session 15
probe): a server MISSING `Strict-Transport-Security` that puts the token
`strict-transport-security:` inside another header value (e.g. `Server:`) makes
`http.missing_headers` see the header as present → true finding suppressed. `fmt.Sscanf(x,"%d")`
also parses leniently — `"3o1"` → 3, `"200OK"` → 200 — so a crafted status line shifts the
value across the 300/400 redirect band. Both directions (false negative and false positive)
reproduce. Documented as a latent limitation in ADR-050 with confidence 0.75, so it is a
known-and-accepted MEDIUM, not a surprise — but the class is: any evaluator that reads a
sanitised banner/excerpt instead of a structured field inherits the scanned host as an input
to its own verdict. The named fix is a structured `http` object on the service payload.
**Why:** the scanned host is attacker-controlled by CVAP's own threat model; prose heuristics
turn that control into control over the verdict.
**How to apply:** for each evaluator, ask "does this read a structured field or re-parse a
string the target chose?" If the latter, the target can force both a miss and a false finding.

**33. `certEvidence` nil-leaf panic is latent, not live.** `evaluators.go:certEvidence`
discards the `ok` from `leafOf` and dereferences the leaf pointer; called on a `ServiceObservation`
whose `TLS != nil` but `chain == []` it panics (reproduced). Currently unreachable — every
caller guards with `leaf, ok := leafOf(s); if !ok { continue }` before building the finding —
but it is one new cert evaluator away from a fleet-wide panic on an attacker-presented empty
chain. Note-level defensive fix: have `certEvidence` return early on `!ok`.
