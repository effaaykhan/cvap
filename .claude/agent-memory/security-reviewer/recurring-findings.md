---
name: recurring-findings
description: Recurring security defect classes found in CVAP reviews (114 classes), and the repo-specific constraints that shape acceptable fixes
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

**35. An "extract/move" whose deletion of the old copy never happened, leaving a stale file
that references the symbols the move removed — so the tree does not compile.** Session 22's
`96d1fdc` extracted the argon2id hasher into `internal/control/credential` and removed
`argonParams`/`argonMemory`/the constants from `internal/control/api/handlers_auth.go`, but
`internal/control/api/phc.go` (which USES `argonParams`/`argonMemory` in `decodePHC`) was never
deleted. The commit message AND the review task both assert "api/phc.go is deleted"; `git
ls-tree HEAD` shows the blob still present, and `go build ./...` fails from that commit through
HEAD with `undefined: argonParams` (11 errors), taking `internal/control/api` and everything
importing it — `cvap-core`, `cvap-cli` — down with it. The commit's claim that "the login
integration suite proves it" is therefore false: that suite is in package api and cannot
compile. Deleting the stale file (`git rm internal/control/api/phc.go`; nothing outside it
references `decodePHC`/`errBadPHC`/`b64`) restores `go build ./...` to exit 0 — verified.
**Why:** the diff of an extraction reads as clean — it removes functions and adds a package —
and you only see the defect if you notice it did NOT also delete the sibling file AND that the
sibling used the removed symbols. Reading cannot catch it; a build can, in one second.
**How to apply:** for ANY commit described as a move/extract/rename, run `go build ./...` (and
`go vet`) at HEAD before anything else. Do not trust the commit message's or the task's claim
that a file was deleted — `git ls-tree HEAD <path>` is authoritative. A red tree is the first
thing to establish, because every other property is moot if it does not compile.

**36. A module that loudly commits to "refusals, not truncations" and then silently truncates one field.** `knowledge/usn_ingest.py` (session 28) opens with a comment block arguing that every bound is a REFUSAL because a truncated advisory set is a silent false negative — and enforces that for notices (`MAX_NOTICES`, raises) and per-advisory packages (`MAX_PKGS_PER_ADVISORY`, raises) — but the CVE list is `[_bounded(c,64) for c in (...)][:512]`, a silent slice. An advisory with >512 CVEs drops the tail of its advisory→vuln_def mapping with no error, the exact silent-false-negative shape the module's own docstring exists to prevent. Impact is low here (fetch caps `limit` at 20 notices/call and a single USN rarely lists >512 CVEs; the fixed-package match keys on package/version, not CVE, so the finding still fires — only its CVE annotations are incomplete), which is why it is a Note not a defect. The pattern is the point: a stated doctrine defeated in one spot reads as compliant because the surrounding code obeys it.
**Why:** the refusal helpers (`_bounded`, `_read_capped`, the `MAX_*` raises) make the file look uniformly fail-closed, so the one `[:N]` slice hides in plain sight.
**How to apply:** when a module states a fail-closed doctrine, grep it for every bound — `[:`, `[...:...]`, `min(`, `head`, `truncate` — and check each is a raise, not a clip. Class 23/31 from the truncation side.

**38. A range/affected check whose empty sentinel means "unbounded" flips to match-EVERYTHING when the data is empty.** `internal/version` `AffectedRange.Vulnerable` treats `Fixed == ""` as "never fixed" (vulnerable from Introduced onward) and `Introduced == ""` as "from the beginning". The advisory matcher (`internal/correlate/advisories.go:68`) builds `AffectedRange{Fixed: fix.FixedVersion}` straight from `advisory_fixed_packages.fixed_version` and never checks it is non-empty. `fixed_version` is `text NOT NULL` (migration 0010) — but NOT NULL does not forbid `''`. Measured: `AffectedRange{Fixed:""}.Vulnerable(dpkg, x)` is `true` for every x tested (`0.0.1`, `999.999`, `5.0.51a-3ubuntu5`). So one empty `fixed_version` row in the (trusted, `cvap_knowledge_import`-written) keyspace raises a false advisory finding+CVE against EVERY scanned host running that product/release/package — the "a false finding loses the customer" precision failure, amplified across the fleet. Not attacker-driven (global content is trusted), so a Note, but the matcher is the right place to defend: skip a fix with an empty `fixed_version` (you cannot judge "below" a version that does not exist) rather than letting the sentinel open the range. Sibling gap: the seed-missing case disables the whole advisory path silently — `loadRules`' comment says "logged once by the caller" but no log exists at the `advisoryRuleID == uuid.Nil` branch (SweepOnce logs only on error), so a missing 0039 seed means zero advisory findings forever with nothing said (class 3/observability).
**Why:** a "" = unbounded convention is correct for range arithmetic and wrong for a fix version, and the two readings live in the same struct; the matcher trusts the content invariant instead of enforcing it.
**How to apply:** for any range/affected/expiry check with an empty-means-unbounded sentinel, ask what a row with that field EMPTY does — if it flips the predicate to match-all, require the field non-empty at the use site, not just NOT NULL in the schema.

**40. A file descriptor created without `CLOEXEC` and handed to ONE child is inherited by EVERY
other child spawned in the window.** `scanpoint.CredAgent.EngineFile` builds the signing socket with
`syscall.Socketpair(AF_UNIX, SOCK_STREAM, 0)` — no `SOCK_CLOEXEC` — and `os.NewFile` does not add it,
so the engine end is a plain inheritable fd from `EngineFile()` until `engineHost.start`'s deferred
close. Go's `forkAndExecInChild` does not close unlisted fds (it relies on every fd being CLOEXEC),
and `syscall.ForkLock` does not help a descriptor created outside it. Measured: an UNCREDENTIALED
engine started in the same dispatch pass saw the socket at fd 7 in 16-20 of 20 runs through the
production `engineHost.start`, and a holder of that fd enumerated the key and got a 64-byte
ed25519 signature over a chosen challenge. ADR-027's "engines never hold the credential" is about
the KEY; the socket is the credential's power, and it crossed to a process that was granted nothing.
**Why:** `cmd.ExtraFiles` is per-command and reads as the whole story, so nobody asks what the fd is
doing between creation and hand-off. The window is short in wall time and still wins the race,
because sibling engines start at the same instant by construction (one goroutine per assignment).
**How to apply:** for every fd handed to a subprocess, check the creating syscall for `SOCK_CLOEXEC`
/ `O_CLOEXEC` and measure with `ls -l /proc/self/fd` from an unrelated child. Test the concurrent
case, not the single-job case.

**41. Trust material composed per-HOST and consulted host-agnostically.** `dispatch.trustMaterial`
composes `"<addr> <SHA256:fp>"` per task into one blob for a job of up to 32 targets
(`planner.TasksPerJob`), and `credhost.hostKeyCallback` parses every line, ignores the host field
entirely, and accepts any collected fingerprint/key for any target. Measured: host A's key accepted
as host B; an operator pin written for 10.0.0.1 accepted at 192.0.2.99. So one compromised in-scope
host authenticates as any of its 31 neighbours in the same credentialed job, and the engine's
inventory for the impersonated host becomes attacker-chosen. Same shape one layer up:
`SSHHostKeyFingerprintsAt` looks up the address tenant-wide, so two zones with overlapping RFC1918
space contribute each other's keys. Compounding it, `key_value` is unvalidated `text` (no CHECK) fed
from an observation payload, and the `strings.HasPrefix(fp, "SHA256:")` guard added mid-review is a
PREFIX test on a value that may contain newlines — `"SHA256:legit\n10.9.9.9 SHA256:<attacker>"`
passes it and injects a trusted line for a host that had none.
**Why:** the composed line LOOKS host-scoped, so the binding appears to exist somewhere; and a
prefix check reads as validation of the whole value.
**How to apply:** for any trust store, ask what the verifier does with the SUBJECT field, and prove
it by presenting the wrong subject. For any single-line field built from stored text, assert the
absence of `\n` (and `\r`) at the composition site, not a prefix at the source.

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

**34. Security headers set at the JSON write, not globally — static/SPA path escapes them.**
`writeJSON`/`writeError` (`internal/control/api/errors.go`) set nosniff, X-Frame-Options,
Referrer-Policy and HSTS on every API response, and the CSV export re-sets nosniff by hand.
The SPA handler (`internal/control/api/spa.go spaHandler`) sets only Content-Type and
Cache-Control, so the operator UI shell and its JS/CSS are served with NONE of them, and
there is no CSP anywhere in the repo (grep confirmed). Session 19 shipped this; the new
`TestSPACatchAllServesWithoutShadowingTheAPI` asserts content-type and not-404, never a
security header, so it proved nothing about this. Probe: `spaHandler()` in an httptest with
the embedded dist under `-tags embedui` — real `index.html` and hashed assets return 200 with
all five header slots empty. Clickjacking impact is blunted because SameSite=Lax withholds
the session cookie from a cross-site iframe, so the framed app is unauthenticated; the live
gaps are CSP absence (no XSS containment on the one origin that executes script and renders
scan-target-derived data) and nosniff absence on served assets.
**Why:** the header-setting lives in the response helper, not in a middleware that wraps the
whole mux, so any handler that writes bytes directly (static files, future streaming/non-JSON
handlers) silently ships without them.
**How to apply:** whenever a new handler writes a body without going through `writeJSON`, check
which of the five headers it drops. The durable fix is a security-header middleware in
`Server.Handler()`/`mount`, not per-handler Set calls.

**37. The knowledge-import psql-via-stdin injection surface — measured safe, so bound the review.**
`knowledge/*_ingest.py` (usn, release, and session-34 `risk_ingest.py`) all build a SQL script
as an f-string and pipe it to `psql <db_url> -v ON_ERROR_STOP=1` over stdin, mixing `\copy`
meta-commands with `INSERT...SELECT`. The safe-by-construction rule, verified by measurement so
future reviews need not re-derive: (a) per-row attacker-controlled values (cve_id, score,
percentile, dates) reach Postgres ONLY through a `csv.writer`-quoted temp file + `\copy ... WITH
(FORMAT csv)`, never string-interpolated; (b) the only interpolated values are pack metadata
(feed name, source_url, fetched_at, source_version, score_date, staleness) through `_sql_lit`,
which wraps in single quotes and doubles internal quotes; (c) `{path}` is a server-side
`mkdtemp` path and `{count_expr}` a constant. Measured facts: psql keeps a `\!`/`\copy` embedded
via a newline INSIDE a properly-quoted string literal (it does NOT run it — tested against the
deploy container), and the deploy DB has `standard_conforming_strings=on`, which neutralises the
one theoretical break (a trailing backslash `'a\'` escaping the closing quote — only bites if
that GUC is off, pre-9.1 behaviour). Residual Notes, not defects: the db_url with an inline
password is passed as an argv (`["psql", db_url, ...]`), so it shows in the Core host's process
table — pre-existing across all three pipelines, prefer `-v`/PGPASSWORD/a service file; and one
poisoned feed row (bad `score::numeric`, out-of-`numeric(6,5)`-CHECK-range, or invalid
`::date`) aborts the whole import under ON_ERROR_STOP — a feed-integrity DoS on knowledge
freshness, acceptable under the refuse-not-truncate doctrine (ADR-069) given the HTTPS-fixed-host
trust boundary. Unlike class 36's `usn_ingest.py`, `risk_ingest.py`'s bounds all REFUSE
(`MAX_KEV_ENTRIES`, `MAX_EPSS_ROWS` raise before append; the gzip-bomb guard reads exactly
`MAX_DECOMPRESSED_BYTES + 1` and refuses — a correctly bounded read, not read-all-then-check).
**Why:** these pipelines look injectable at a glance (shell-adjacent psql, f-string SQL) but are
not; spending the review budget re-proving it each session is the waste this entry prevents.
**How to apply:** on a new/changed knowledge pipeline, confirm the three-part rule above holds
and that any NEW interpolated value is metadata through `_sql_lit` (not a per-row value); if a
per-row value ever gets interpolated, or a bound truncates instead of raising (class 36), THAT is
the finding.

**39. Authenticated/SSH read from an in-scope host with an unbounded sink and no read-phase timeout.** `internal/credscan/ssh.go` `run()` sets `sess.Stdout`/`sess.Stderr` to bare `bytes.Buffer`s and calls `sess.Run(cmd)`; there is no `io.LimitReader`/size cap and no ctx wiring for the command phase (ctx only guards dial+handshake in `dialContext`, `cfg.Timeout` only feeds `net.Dialer`/`ssh.ClientConfig.Timeout`). A compromised or hostile in-scope host answers `dpkg-query -W` with unbounded stdout → OOM, or trickles bytes forever → hang past the process timeout. This is the checklist's "unbounded read from a scan target is a DoS on your own fleet" for the first credentialed tool. Same class as 18/23 (unbounded parse) but on the credentialed-host read path. Rated Medium: operator-run single process, not the fleet, but the target is exactly the possibly-vulnerable host the tool exists to measure.
**Why:** the credscan instrument authenticates to hosts assumed possibly-compromised, so their command output is hostile input by design, yet the sink is unbounded and the read phase ignores the timeout.
**How to apply:** on any SSH/exec read from a scanned host, require an `io.LimitReader` (or MaxBytes cap that refuses, not truncates) on stdout AND stderr, and a deadline that actually interrupts the read (a goroutine closing the session on ctx.Done, since `ssh.Session.Run` takes no ctx).

**credscan credential handling verified clean (S39, ADR-075/076):** for future credscan reviews, these were checked and held — zeroise is guaranteed on every return path by `defer cred.Zeroise()` registered immediately after construction (the explicit zeroises on the authMethod/knownhosts error paths and post-ReadHost are redundant backstops); scope gate (`scope.Permits` on `target.Canonicalise(host)`) runs before credential construction and before any dial, and the SAME `canon.Value` feeds the gate, the dial, and the cred scope (no TOCTOU); host-key verification is mandatory (`ReadHost` refuses nil `HostKeyCallback`, no `InsecureIgnoreHostKey` anywhere, only caller passes `knownhosts.New`); commands are static constants (no shell interpolation of host/user/port); `AdvisoryKeysForAsset` carries an explicit `tenant_id = $1` predicate AND runs inside a tenant-scoped `Read` (RLS), joining global `vulnerability_defs` per the ADR-030 pattern — no cross-tenant path. Residual Notes only: `ssh.Password(string(cred.Reveal()))` and `ParsePrivateKey` copy material into ssh-lib buffers that outlive Zeroise (the documented ADR-038 caveat), and an env-var password (`CVAP_CREDSCAN_PASSWORD`) persists in the process environment for the whole run beyond the credential's own zeroise.

**S41 credential-grant path, measured clean (do not re-derive):** `logging.ProtoAttr` redacts
`CredentialGrant.material` (marked `debug_redact` AND a bytes field, so "[REDACTED]" either way),
including when the whole `CoreMessage` is passed; `make secret-logging` catches `slog.Any(msg)` /
`g.String()` / `GetMaterial()` at a logging call and passed on the production code. No path puts
material into an error, an audit detail or `JobTerminal.detail`: the only echo from `NewCredAgent`
is x/crypto's `ssh: unsupported key type %q`, which renders the PEM BLOCK LABEL, never key bytes.
`terminate()` zeroises before `results()`/`Enqueue` on every path, `Jobs.Terminate` and
`Leases.Release` are holder-qualified, `SSHForJob` / `SSHHostKeyFingerprintsAt` /
`CredentialGrants.*` are tenant-qualified under RLS, `credential_grants` has its policy and
composite FKs, and deleting a tenant with grants still cascades despite the `ON DELETE RESTRICT`
to `scan_jobs`.

**42. Evidence written on the branch that DISCLAIMS authority, read by a control that
REQUIRES it.** S42 made `DecisionAttach` record the observation's moderate keys
(`internal/correlate/correlate.go`, the `NewAsset || Attach` block). Attach is defined — in
`domain.Decision`'s own comment — as "weak evidence, the address alone ... never claims two
hosts are one". The keys it now writes land in `asset_identity_keys`, which is exactly what
`AssetIdentityKeys.SSHHostKeyFingerprintsAt` returns as ADR-091's *observed trust root* for a
credentialed SSH job, and exactly what `domain.Resolve` later reads as merge evidence. So a
decision that asserts nothing feeds two decisions that assert everything. Measured on the dev DB:
an attacker who answers for an address (ARP/DHCP) gets their chosen host key added ALONGSIDE the
real one at that address (`[SHA256:real SHA256:evil]`, zero resolution-queue items), and
`credhost.hostKeyCallback` accepts any fingerprint bound to the host — so host-key verification,
the one control that defeats an on-path attacker, is defeated. Planting an ssh key AND a TLS leaf
on a keyless asset then presenting both at the attacker's own address merges the attacker's host
onto that asset (1 asset holding both addresses). Both are regressions: under the pre-change code
the same inputs recorded nothing and produced 2 assets.
**The structural sub-bug that let it through:** `domain.Resolve`'s "disagreement is not outvoted"
branch is `if len(s.agreeing) > 0 && maxStrength(conflicts) >= maxStrength(agreeing)`. Weak keys
are deliberately NOT stored in `asset_identity_keys`, so an address-only attach has
`agreeing == []` by construction and the contradiction is dropped rather than queued. The guard
only fires when there is already agreement, which is the case it is least needed in.
**The half-fix, and why it is the wrong half.** A mid-review patch added `contradictsHeld` — an
attach will not record a key that differs from one the asset already holds at the same source.
That closes the "add a second key beside the real one" case and leaves the case the feature
EXISTS for wide open: an asset with no key yet (S42/ADR-093's own motivating state — every Phase 4
host) has nothing to contradict, so the first key to answer at its address is recorded and becomes
the trust root. Re-measured after the patch: attacker key still returned by
`SSHHostKeyFingerprintsAt`, and planting ssh+cert then answering at the attacker's own address
still merged their host onto the existing asset, 1 asset, 0 queue items. The generalisable
lesson: when a write is added to serve case X and a reviewer reports it is unsafe, check whether
the fix covers X itself or only the cases adjacent to it.
**Why:** the commit's own comment argues "safe by construction: Record's ON CONFLICT keeps a key
live on another asset where it is, and a key any live asset held would have made this a merge or
a queue". Both clauses are true and neither covers a key NO asset holds yet — a fresh
attacker-generated key. The safety argument was made about key COLLISION and the risk is key
ADDITION.
**How to apply:** for any write made on a "this is only weak/provisional" branch, grep for every
reader of that table and ask what the strongest claim any of them derives from a row. If one of
them is a trust root, the weak branch has to write somewhere the trust root does not read, or
not write. And for any "conflicting evidence queues" rule, check whether the conflict test is
gated on agreement existing.

**43. A "counts once per pass" dedupe whose clock is swapped for a finer-grained one, so the
unit the control is stated in stops existing.** ADR-094 gates the SSH trust root on
`sightings >= 2` and states "two observations of one key in one sweep count once", enforced by
`Record`'s `ON CONFLICT ... WHERE EXCLUDED.last_seen_at > asset_identity_keys.last_seen_at`.
That holds while the caller passes the SWEEP clock (`c.now()`, one value per tenant per pass).
A mid-review edit moved it to `h.seenAt` — the max `observed_at` of the ADDRESS GROUP — so one
sweep now carries as many distinct timestamps as it has groups. Measured: one scan in which the
attacker answers ssh+tls at the victim's address AND at its own (a minute apart in observation
time) reaches `sightings = 2` on BOTH keys in a SINGLE sweep, merges the two hosts into one
asset, and puts the attacker's fingerprint in `SSHHostKeyFingerprintsAt` for the victim's
address. Zero persistence, one scan. The second, cheaper variant needs no merge: `ListUnresolved`
is `ORDER BY observed_at LIMIT 500`, so when the 500-row cut falls inside a host's observations
the same key is recorded in two consecutive sweeps — measured, sightings 2 from one scan.
**Why:** "one sighting per sweep" and "one sighting per observation time" read as the same
sentence, and the ADR says both in different paragraphs.
**How to apply:** for any "at most once per X" rule implemented as a timestamp comparison, name
the exact expression the timestamp comes from and count how many distinct values one X produces.
If it is more than one, the control is stated in a unit the code does not have. And re-measure
every claim of this shape after ANY change to the value's provenance, including one made by a
concurrent agent mid-review.
**Closed (S42, in the same ADR):** the occasion is now the SCAN, not a timestamp —
`asset_identity_keys.last_seen_scan`, set from the observation's task via `Jobs.ScanIDForTask`,
and `Record` bumps only when the scan is DIFFERENT and later and the verdict is not a merge. Both
variants (cross-group and batch-cut) are one scan and count once; ADR-094 §1/§5 now *require*
observation time for `last_seen_at`, so do not read "sweep clock" above as the remedy.

**44. A counter that gates trust, incremented by the operation that consumes the trust.**
`Record`'s conflict branch bumps `sightings` for a key the same asset already holds, from EVERY
verdict — including the merge whose evidence is that very key, and without upgrading
`provenance`. So an attach-grade key (inventory, withheld from the trust root) is promoted to
trust material by being used as merge evidence: plant ssh+tls on a keyless asset at the victim's
address (sighting 1, withheld), then present the same two keys at the attacker's OWN address; the
merge bumps both to 2 and the attacker's fingerprint becomes the observed trust root at the
victim's address — measured, `prov=attach sightings=2`, one asset holding both addresses. The
attacker needs the victim's address for one sweep, not two, and the second "sighting" is
manufactured on hardware they own. `ForAsset` (merge evidence) and `LiveByValue` were never given
the provenance filter that `SSHHostKeyFingerprintsAt` got, so the strongest claim in the system —
a merge, "the one decision that cannot be undone" — still reads ungraded keys.
**Why:** the grading was added to the one reader the review named, and the other two readers feed
back into it through the counter.
**Partly closed (S42):** the promotion half is gone — a merge never bumps `sightings`
(`EXCLUDED.provenance <> 'merge'`) and `provenance` is never upgraded on conflict — so the
credential does not follow the merge. The merge itself on one-sighting attach-grade keys is still
open and stated so in ADR-094: B40 (grade `ForAsset`/`LiveByValue` or `Candidate.Keys`).
**How to apply:** when a field grades evidence, grep every reader (class 42) AND every writer of
the grade itself. Ask which operations can increment the counter and whether any of them already
depended on the thing the counter authorises.

**45. A migration adding a NOT NULL column with no default breaks the hand-written INSERTs the
Go store layer does not own — including the RLS gate's own fixture.** 0044 dropped the default on
`provenance` and made `last_seen_at` NOT NULL. Every `Record` call site was updated; the four SQL
seeds were not, and one of them is `internal/store/testdata/fixtures.sql`, loaded by
`rls_test.sql` under `ON_ERROR_STOP=1` — so `make rls-test` (in `make ci` via `db-gates`, and a
step in `.github/workflows/ci.yml`) aborts at the fixture, and the tenant-isolation sweep it
exists to make non-vacuous never runs. Verified by replaying the fixture's exact INSERT: `null
value in column "provenance" violates not-null constraint`. Fixed in-tree during the review.
**How to apply:** on any migration adding a NOT NULL/defaultless column, `grep -rn "INSERT INTO
<table>"` across `**/*.sql`, `test/`, `internal/**/testdata` and the load seeds — not just the Go
store package. A gate whose fixture fails is a gate that stops asserting.

**46. A grade assigned by the PATH the evidence took, when the attacker chooses the path.**
ADR-094 grades an identity key by the verdict that recorded it: `merge`/`new_asset` are
enrolment-grade (trust material at one sighting), `attach`/`unknown` are inventory until two
sightings. The whole control assumes the attacker's key arrives on an ATTACH — planted at the
victim's address. Measured: run the same attack in the other order and no attach is involved.
The attacker's own host is discovered normally at its OWN address (new asset, keys graded
`new_asset`, trust material at once); one appearance answering ssh+tls at a keyless victim's
address then MERGES the victim's address onto the attacker's asset (`AssetAddresses.Open`
closes the victim's hold), and `SSHHostKeyFingerprintsAt(victimIP, 22)` returns the attacker's
fingerprint immediately — one scan at the victim's address, no graduation, no persistence. The
ADR's closing claim ("the credential does not go to the attacker's machine until a second scan
sees their key at the victim's address") is false in that order. A second, slower route exists
too: attach at the victim's address (sighting 1), merge from the attacker's own address (no
bump), then a SINGLE-key attach at the attacker's own address — one moderate key alone does not
merge, so it attaches to the now-merged asset and bumps the counter on hardware the attacker
owns.
**Why:** the grade describes the last hop, and the attacker picks which hop that is. Grading one
reader (the trust root) while the merge rule reads the same keys ungraded lets the merge carry a
grade across addresses.
**How to apply:** for any per-path grade, enumerate EVERY path that produces the good grade and
ask which of them the attacker can walk on hardware they control. Then ask what carries the
grade somewhere else — here, a merge moving an address is what moves the trust root.
**Closed (S42):** the exemption was deleted — no verdict grade counts on one sighting; trust is two scans at the address in `asset_identity_key_sightings`.

**47. A refusal that parks the evidence forever, with no reader for the parking.** ADR-094 §4/§5
turn a same-service key contradiction at a held address into a QUEUE verdict, and `ListUnresolved`
then skips any observation with a pending queue item. Nothing resolves an item (no API, no
console, and `ResolutionQueue.PendingCount` has no caller in production code at all), so
"waits for an operator" means "never". Measured: a host CVAP fingerprinted once (OpenSSH 8.9p1)
that rotates its SSH host key — a reimage, or an attacker running `ssh-keygen -A` once — has
every later ssh observation parked; after three more scans reporting 9.0/9.1/9.2p1 the `services`
row still says 8.9p1 with the original `last_seen`, 3 observations unresolved, 4 queue rows,
forever. Pre-change baseline, measured by restoring the old attach-with-skip behaviour: 9.2p1,
0 unresolved, 0 queued. So the change converts "we record the service but not the key" into "we
stop seeing the service", and the trigger is under the target's control.
**Why:** the rule was justified by the address-handover case (a different host on a reused lease)
but fires identically on key rotation of the SAME host, which is far more common; and "queued for
an operator" was treated as a terminal state rather than a promise someone has to keep.
**How to apply:** whenever a review says "do not guess, queue it", find the consumer of the queue
in the SAME diff. If there is none, the refusal is a silent drop with extra steps — say so, and
check what stops being collected while the item waits.

**48. An exemption to a two-sighting rule, gated on a precondition that EXPIRES.** ADR-094 made
the observed trust root ask for two distinct scans at an address — except for a `merge`/`new_asset`
key at its own `first_seen_address`, which counts at once, on the reasoning that a new asset is an
"enrolment moment". The precondition for that verdict is "no live holder of this address", and
liveness is a 7-day window (`correlate.AddressWindow`, `AssetAddresses.CloseStale`, which keys on
`valid_from` — `TouchLive` rewrites it as last-seen). So the exemption re-opens on a timer:
measured, a healthy two-key host trusted at its address, quiet for 8 days, then ONE scan by whoever
answers there → `SSHHostKeyFingerprintsAt` returns the newcomer's fingerprint, the previous
occupant's key (still in `asset_identity_keys`, still `sightings=2` at that very address) is never
consulted because its asset no longer holds the address, no queue item is raised, and the handover
rule cannot fire because there is nothing live to contradict.
**Why:** "we have never seen anything here" and "we have not looked here lately" are different
statements, and only the first justifies trust-on-first-use. Aging is what makes `valid_to IS NULL`
honest for inventory; reusing it as the precondition for an enrolment moment imports its forgetting.
**How to apply:** for any "first time" exemption, find what makes the system believe it is the first
time and ask whether that belief decays. If it is a liveness window, the exemption recurs every
window. Prefer deleting the exemption (here: require two sightings always — the migration already
imposes exactly that on every pre-existing key) over dating it.
**Closed (S42):** `first_seen_address` no longer exists; the per-(key,address) sightings table replaced the scalar columns.
**Re-measured (S42, final):** the exemption was DELETED rather than dated — no provenance carve-out,
every key needs two scans at the address. Occupant trusted at an address, `asset_addresses.valid_from`
aged 9 days, `CloseStale` closed the interval, the newcomer answering there became a NEW ASSET with
`scans_seen=1` and `SSHHostKeyFingerprintsAt` returned `[]`; a second scan there returned its key,
which is the ADR's stated and accepted cost. The previous occupant's key keeps `scans_seen=2` at that
address but its asset no longer holds the address, so the join excludes it.

**49. A per-scope counter kept as ONE (scope, count) pair on the row.** ADR-094 fixed a
cross-address trust carry by adding `last_seen_address`/`sightings` to `asset_identity_keys` and
requiring `last_seen_address = $ip`. One row per key value (the partial unique index), so the key
counts at exactly one address at a time and a sighting elsewhere RESETS it. Measured on a legitimate
dual-homed host whose sshd answers on both scanned addresses: trust material at at most one of them,
ever; and when the two address groups' order alternates between scans (two jobs, two zones) it is
trust material at NEITHER after six scans, flapping in and out as the row moves. Compounded by
`Record`'s `EXCLUDED.last_seen_scan IS DISTINCT FROM ...` guard, which allows at most ONE update per
scan per key, so the second address group in the same sweep never even moves the row. Pre-change the
query returned any live key of the asset holding the address, so this is a REGRESSION, fails closed
(credentialed jobs refuse), and contradicts the ADR's stated cost of "one more sweep per host".
**Why:** the narrowing was correct — trust IS per address — but a scalar column can only remember
one scope, so "counted per address" became "counted at the last address".
**How to apply:** when a review narrows a trust check by a new dimension, ask what a subject with
TWO legitimate values of that dimension does. If the state is a scalar on the parent row rather than
a child table keyed by the dimension, the answer is usually "flaps, or never qualifies".
**Closed (S42):** the scalar columns were replaced by `asset_identity_key_sightings` (one row per key and address), so a dual-homed host counts at each address.
**Re-measured (S42, final):** a host answering ssh+tls at two addresses is trust material at BOTH
after two scans, in both group orders and with the order alternating between scans — `scans_seen`
reached 4 at each address over four scans, one asset, no flapping. The per-scan guard is now on the
(key,address) row, so two address groups in one sweep each move their own row.

**50. Parking keyed on the evidence that caused the refusal, while its siblings walk free.**
ADR-094 §4/§5 queue an address handover and skip re-listing "the observation" — but `Enqueue` writes
one row per (observation, KEY) and the weak `ip_window` key carries `ObservationID = uuid.Nil`, so
it lands with `observation_id` NULL. `ListUnresolved`'s anti-join matches on `observation_id`, so
only the KEY-BEARING observations are parked. Measured: a newcomer on a reused lease presenting a
contradicting ssh key on 22 plus an ordinary keyless service on 8080 has the ssh observation parked
and the 8080 observation attached to the PREVIOUS OCCUPANT's asset one sweep later, deriving a
service row (and findings) on the wrong host — the interleaving the queue verdict exists to prevent.
It also falsifies the ADR's B41 text, "nothing derives a service or a finding from a parked
observation": nothing derives from the parked one, and its siblings derive as usual.
**How to apply:** a host group is the unit of the DECISION but the queue is keyed by observation and
key. Whenever a verdict is meant to hold a whole group, check that every member of the group is
actually held, including the ones that contributed no key.
**Closed (S42, measured):** the queue branch now skips keys with `ObservationID == uuid.Nil` and
enqueues one `ip_window` item per REMAINING observation in the group, carrying that observation's id.
Measured: a newcomer with a contradicting ssh key on 22 plus a keyless service on 8080 parks BOTH
observations (2 queue items, 2 unresolved) and they stay parked across four further sweeps; no 8080
service row ever lands on the occupant's asset. The dedup (`NOT EXISTS ... observation_id IS NOT
DISTINCT FROM`) keeps the item count flat per sweep.

**51. A refusal rule justified by a RARE adversarial event that fires on a ROUTINE scheduled one.**
ADR-094 §4 turns "the asset holds this address and a same-service moderate key contradicts the one it
holds" into a QUEUE verdict, and the ADR describes the false-positive case as "a reimage or
`ssh-keygen -A`" (B41) — rare, adversarial-adjacent. The rule does not read key TYPE: a
`service_cert_fp` renewal is the same shape. Measured on the dev DB: a web host with a cert on 443 and
an ordinary keyless service on 80, scanned twice, then re-scanned after an ACME renewal — verdict
`queue` with the ADR-094 handover reason (not the pre-existing ADR-007 "not outvoted" one, confirmed
from `asset_resolution_queue.conflict_reason` and from `domain.Resolve` called directly), an item for
the cert observation AND an `ip_window` item for the keyless port-80 sibling, and after three further
scans the `services` rows are still the pre-renewal ones. Pre-change the same inputs had
`agreeing == []`, so the not-outvoted guard could not fire and the candidate fell through to
`attachable = append(...)` — an attach, services updating, key simply not recorded. So it is a
regression whose trigger is a 60-90 day cron on every TLS host in the estate, not a reimage. With B39
open (no resolver) the host is gone from the inventory permanently: stale findings stay open, new ones
are never raised, and the only signals are a WARN and Health's unresolved-observation count.
**Why:** the rule was designed against one key type (ssh host key, which really is rare to rotate) and
applied to the strength class, which includes the one credential in the estate that is *designed* to
rotate on a schedule.
**How to apply:** for any refusal keyed on "this evidence changed", enumerate the legitimate reasons
that value changes and their RATE. If one of them is automated and scheduled, the refusal is a
scheduled outage of whatever it gates. Ask it of every member of the class the rule matches on, not
of the example that motivated it.
**Half-closed (S42 final), and the half that is open is the general one.** The fix carves the
certificate out INSIDE the attach branch (`contradictsHostKey` routes only an ssh conflict to
`contested`; a cert conflict attaches and rides out in `Verdict.Contradicted` unrecorded). That
branch is reached only when `len(s.agreeing) == 0`. A host with ANY other agreeing moderate key —
an ssh+TLS Linux server, the ordinary shape — hits the older ADR-007 not-outvoted guard first
(`len(agreeing)>0 && maxStrength(conflicts) >= maxStrength(agreeing)`, 2 >= 2) and is still queued.
Measured both ways in one run: `domain.Resolve` returns `attach` for a TLS-only host and `queue` for
the same renewal beside a steady ssh key, and end-to-end the ssh+TLS host parked 8 observations / 8
queue items over four scans with `services` frozen at the pre-renewal versions. Not a regression
(ADR-007's guard predates the diff) but the ADR's §4 sentence "a renewed certificate attaches — the
same host" is false for most of the estate.
**How to apply (added):** when a carve-out is added to fix a measured case, find the FIRST guard in
the decision that can claim the same inputs. A carve-out in a later branch cannot reach anything an
earlier branch already matched — construct the variant that reaches the earlier guard and measure it.

**52. A counter that gates trust and only counts up, beside a relationship that expires.**
ADR-094 counts sightings per (key, address) in `asset_identity_key_sightings` and never decays them,
while everything around the count ages: `asset_addresses` intervals close after `AddressWindow`
(7 days) and `ip_window` is meaningless outside it. Measured: an attacker answers ssh+tls at a
victim's address for two scans (the ADR's accepted cost) and is trust material there; the address
ages out and a legitimate KEYLESS host holds it for two scans (trust root correctly empty); the
attacker returns for ONE scan — the two moderate keys merge back onto their old asset, `Open` takes
the address off the keyless occupant, `scans_seen` goes 2 -> 3, and `SSHHostKeyFingerprintsAt`
returns the attacker's fingerprint again after a single scan, months later, with no queue item raised
(a keyless occupant contradicts nothing). So the two-scan cost is paid ONCE per address, forever.
**Why:** the count is evidence about a moment, stored as a permanent property of a pair whose other
half is explicitly time-bounded.
**How to apply:** when a control is "N occurrences at scope S", check whether S itself expires. If it
does, the occurrences must expire with it — compare `last_seen_at` against the same window that
governs the scope, or reset the row when the scope relationship is closed.
**CLOSED (S42, final re-measure).** `Record`'s `DO UPDATE` now resets: `scans_seen = CASE WHEN
<row>.last_seen_at < EXCLUDED.last_seen_at - $9::interval THEN 1 ELSE ... + 1 END` with
`store.SightingWindow` (7d, `'168h0m0s'::interval` parses as 168:00:00 — checked). Measured end to
end through `SweepOnce`: attacker pays two scans, 60 days pass, a keyless host holds the address for
two scans (trust empty), the attacker returns for ONE scan -> merge back, `scans_seen` 2->1, trust
`[]`; a SECOND returning scan -> `scans_seen` 2, trust restored. The cost is charged again. Backdating
cannot evade it (ingest bounds `observed_at` to [now-90d, now+1h]; landing inside the 7d gap keeps
`last_seen_at` old, which the read filter then rejects). The other edge is real and DOCUMENTED in
ADR-094 §2: an estate fingerprinted less often than every 7 days can never reach 2 — measured, every
sighting restarts — which fails closed onto the operator pin.
**The prior (superseded) state of this entry:**
`SSHHostKeyFingerprintsAt` gained `s.last_seen_at >= now() - within` (`store.SightingWindow` = 7d),
but `Record`'s `DO UPDATE` is still `scans_seen = scans_seen + 1` with no reset, so the control the
code actually implements is "at least two sightings EVER, and the most recent one inside the window"
— and a single returning scan satisfies both. Measured end-to-end through `SweepOnce`: attacker pays
two scans at a keyless victim's address (trusted), 60 days pass, the interval is closed by
`CloseStale`, a legitimate keyless host holds it for two scans (trust root correctly empty), the
attacker returns for ONE scan → merge back onto their own asset, `Open` takes the address off the
occupant, `scans_seen` 2→3, `last_seen_at` = now, and the fingerprint is trust material again. Also
pinned at the store layer in 30 ms with four `Record` calls. Fix shape: make the update decay —
`scans_seen = CASE WHEN <row>.last_seen_at < EXCLUDED.last_seen_at - <window> THEN 1 ELSE
<row>.scans_seen + 1 END` — or delete the sighting when `CloseStale` closes the interval.
**How to apply (sharpened):** "N occurrences at a scope that expires" needs the occurrences to
expire too. A recency predicate on the LATEST occurrence is not decay: it re-arms on one event.
Write the check as "N occurrences inside the window", and test it by continuing the scenario past
the point where the window has lapsed rather than stopping at the lapse.

**53. A scope filter read from a field written ONCE, on a table whose upsert is DO NOTHING.**
`SSHHostKeyFingerprintsAt` scopes the trust root to the dialled port with
`k.merge_evidence_payload -> 'port' = to_jsonb($3::int)`, and the ADR states the property as "was
observed on the port the engine dials". `Record`'s insert is `ON CONFLICT ... DO NOTHING`, so the
payload is whatever the FIRST observation that recorded the key carried and is never updated, while
the sighting count is NOT port-scoped (it bumps from an observation on any port at that address).
Measured: a host serving the same host key on 2222 and 22, with the 2222 observation earlier in the
group, stamps the key row `port=2222` — after two scans `trust@2222` returns the key and `trust@22`
returns `[]`, so a credentialed job against that host is refused forever with "no observed ssh host
key", although every scan saw the key on 22. Fails closed, so availability not exposure; the defect
is that the query asserts "was FIRST RECORDED from this port", not what the ADR claims.
**How to apply:** whenever a filter reads a copied payload field, find the write and check whether it
can ever be corrected. If the write is `DO NOTHING`/insert-only, the filter is asserting a property of
the first sighting, not of the subject — say which one the control needs.
**Closed (S42 final):** the port moved into the sighting's PRIMARY KEY
(`asset_identity_key_sightings (tenant, key, address, port)`), `Record` takes it from the key's
SOURCE (`portOf("22/tcp")`, from `keysFrom`'s `fmt.Sprintf("%d/%s", port, proto)`) and the query
filters `s.port = $3`; the payload filter is gone. Measured: one key served on 2222 (observed first,
so it still stamps the key row's payload `port=2222`) and on 22 is trust material on BOTH after two
scans. No inflation through the new dimension — one scan serving one key on five ports plus a
duplicate 22 observation plus a 22/udp twin leaves every row at `scans_seen=1` (the
`EXCLUDED.last_seen_scan IS DISTINCT FROM` guard is per row, and 22/udp maps to the same row as
22/tcp). `Record` with port 0, -1, 65536 or 70000 inserts the key and no sighting, no constraint
violation.

**54. A test that asserts the PRECONDITION of its claim and stops one line short of the claim.**
`TestAnObservedKeyIsTrustMaterialOnlyAfterTwoScansAtTheAddress` documents, in its own doc comment,
"a sighting older than the address window no longer counts: the two-scan cost is not a one-time
payment". The body ages the sighting past the window, asserts the trust root is empty — true — and
ends. It never performs the RETURN that the sentence is about. One more `record(...)` with a fresh
scan id and a re-read would have failed: `scans_seen` 2→3, trust restored. The whole finding (class
52, still open) lives in the gap between the last assertion and the last clause of the comment.
**Why:** the aged state is easy to construct and easy to assert; the claim is about what happens
NEXT, which needs the scenario continued past the interesting moment.
**How to apply:** read every test's doc comment as a list of claims and, for each, find the
assertion that would be false if the claim were false. Watch specifically for claims phrased as a
NARRATIVE ("…left, and returned is not trusted on one scan") against a test that stops at the
middle clause. Same shape as class 9, one level up: there the guard could not fire; here the
assertion is real but is not the claim's.

**55. One relation named two ways: the DECISION compares on the scope a value was FIRST
recorded under, the CONTROL reads the scope it is seen under NOW.** ADR-094 scopes the ssh trust
root to the port of the SIGHTING (`asset_identity_key_sightings.port`, the port seen on this scan)
but `domain.compare` decides "same service, so this is a contradiction" from `ForAsset`'s `Source`,
which is derived from `merge_evidence_payload->>'port'` — the port of the observation that FIRST
recorded the key, never updated (`ON CONFLICT DO NOTHING`). When the two disagree the handover rule
silently does not apply to the port the credentialed engine dials. Measured: a host serving one key
on 2222 and 22 stamps its key row `port=2222`; a different host then takes the address and answers
22 only, with its own key — no conflict (different `Source`), no queue item, attach, key recorded,
and after two scans `SSHHostKeyFingerprintsAt(addr, 22)` returns BOTH fingerprints, so
`dispatch.trustMaterial` writes two known_hosts lines and the credentialed engine accepts either
host. ADR-094 §2 names the seam and calls its consequence inventory damage; the consequence is a
trust root.
**Why:** a scope was narrowed in the read path (sightings, per port-now) without narrowing the same
scope in the write/decide path (the key row's first-seen payload), so one word — "service" — means
two different things three files apart.
**How to apply:** when a control is scoped by X, grep every OTHER comparison that claims to be
"same X" and check it derives X from the same place. If one reads a copied payload and the other
reads live state, construct the subject where they differ (here: one key on two ports) and measure.
Fix shapes: return one candidate key per SIGHTING so `compare` sees the port under consideration;
and fail closed when more than one distinct fingerprint qualifies for one (address, port) — two
host keys at one address and port IS the handover signature.
**Backstopped, not fixed (S42 final, measured).** The second fix shape shipped:
`dispatch.trustMaterial` refuses at `len(fps) > 1` ("distinct ssh host keys qualify"), audited as
`job.credential_refused` and replayed in a fresh `db.Write` if the pass rolls back. Re-measured: a
host serving one key on 2222 (observed first, so the key row is stamped 2222) and on 22, then a
newcomer answering 22 with its own key, still records the newcomer's key on the occupant's asset
with no queue item, and `SSHHostKeyFingerprintsAt(addr,22)` returns BOTH after two scans each — the
refusal is what stops the credential, not the resolver. Root cause (compare reads the first-seen
payload port) open as ADR-094 B42. False-refusal risk checked and low: a legitimate rekey at the
same source is a contradiction and parks instead, and a key seen only on 2222 has no sighting at 22.

**56. A carve-out that removes a refusal also removes whatever ELSE that refusal was holding up.**
ADR-094 §4 forgives a contradicting CERTIFICATE at the asset's own address (a renewal), and the
S42-final fix moved the forgiveness ahead of ADR-007's not-outvoted guard so the common host (steady
sshd + renewed cert) stops parking. Correct for the renewal — and it deleted the second-scan parking
that was containing a handover. Measured end to end: a TLS-only occupant's address is taken by a
host that presents its own certificate on 443 (a same-service contradiction) and its own sshd on 22;
scan 1 attaches (nothing agrees, the cert conflict is cleared) and records the newcomer's host key on
the OCCUPANT's asset with provenance `attach`; scan 2 used to be contested — the newcomer's own key
now agreed, the stale cert still conflicted, 2>=2 — and now attaches as well, so `scans_seen` reaches
2 and `SSHHostKeyFingerprintsAt(victim, 22)` returns the newcomer's key. Zero queue items, and zero
log lines, because the same diff deleted the WARN that `contradictsHeld` used to emit. The credential
for the occupant is then handed to whoever took the lease.
**Why:** the guard being relaxed was load-bearing for a different scenario than the one being fixed;
"nothing agrees" and "everything agrees because I planted it last scan" are the same branch one scan
apart.
**How to apply:** for any refusal being relaxed, list every scenario that currently REACHES it, not
just the false positive that motivated the change — and for a rule applied repeatedly (a sweep), play
the scenario forward TWO iterations, because an attacker's first attach changes what agrees on the
second. Cheap containment when the decision genuinely cannot tell the two apart: let the attach stand
for inventory but refuse to MINT identity from it — on `DecisionAttach` with a non-empty
`Verdict.Contradicted`, skip the key-recording loop entirely. It costs the renewal case nothing (the
contradicted certificate is already skipped) and denies the handover its trust root.
**Closed (S42 final, measured), with the containment taken CONDITIONALLY — see class 57.** The
recommended skip shipped gated on corroboration: an attach with `len(Contradicted) > 0 &&
len(Corroborated) == 0` records nothing and logs a WARN. Re-measured on the exact scenario: TLS-only
occupant, newcomer with a new cert on 443 AND its own sshd on 22, two scans — one key on the asset
(the occupant's cert), `SSHHostKeyFingerprintsAt(victim,22)` empty, one asset, ZERO queue items,
zero unresolved. Two residuals worth carrying: (a) the same attacker who simply does not serve TLS
presents no contradiction at all, so its key is recorded on scan 1 and is the occupant's trust root
after scan 2 — measured, same two scans, so the fix removes one of two equal-cost routes and the
credential outcome is unchanged (that route is ADR-094's stated, accepted cost); (b) the detection
is filed in a WARN only — no queue item, no audit, no health counter — and the newcomer's services
still attach to the occupant. Do NOT "just queue it": the uncorroborated shape is exactly what a
TLS-ONLY host's ordinary ACME renewal looks like (nothing else can agree), so queueing would park
every such host, which is class 51 again.

**57. A refusal relaxed by "corroboration", where the attacker supplies the corroboration — one
scan earlier, or by echoing a public value.** ADR-094 §4's fix for class 56 records a contradicted
key (a renewed certificate) when something else AGREED with the asset, and retires the held one:
`domain.Resolve` fills `Verdict.Corroborated` from `s.agreeing`, `correlate.resolveHost` does
`Retire` + `Record`. Both routes to that agreement are open to the attacker. (1) MINT IT: a newcomer
at a TLS-only occupant's address that presents ONLY its sshd on scan 1 contradicts nothing, so its
key is recorded (`provenance=attach`); on scan 2 it presents the same key plus its own certificate,
its own planted key is the corroboration, the occupant's certificate is RETIRED and the attacker's
recorded — then one scan of the attacker's own host at its OWN address merges the two assets
(measured: 1 asset holding both addresses, 0 queue items, 0 unresolved). Under HEAD the attacker's
cert was skipped by `contradictsHeld`, so it never got a second key on the victim's asset and the
merge could not happen: newly permitted, and it widens ADR-094's already-open B40 (planted-key
merge) from keyless victims to every host whose only identity is a certificate. (2) ECHO IT: an
`ssh_hostkey` observation proves nothing — `internal/engines/fingerprint/ssh.go` abandons the
exchange after `SSH_MSG_KEX_ECDH_REPLY` and hashes the host-key blob, with no signature check ("an
exchange hash nothing computes"), and a host key is a public value anyone who has scanned the victim
holds. So replaying the victim's real host key gives corroboration on scan 1, and an
"established key" strengthening (require ≥2 sightings at this address) does not close that route.
Note the inversion: the key TRUSTED as corroboration (ssh) is the unverifiable one, and the key
treated as the CONTRADICTION (a certificate) is the one whose value does prove possession, because
the TLS probe completes a handshake.
**Why:** "something else agreed" reads as independent evidence, but agreement is computed against
rows the same attach loop wrote last scan, and against a value the target merely asserts.
**How to apply:** whenever a rule is relaxed "only when X corroborates", ask who wrote X and what X
proves. Trace X's provenance to the verdict that recorded it (if an attach can write X, one extra
scan buys the relaxation) and to the protocol that observed it (if the probe never verifies
possession, X is a public value, not a secret). Fix shapes, in order: require the corroborating key
to be established at that address (≥2 sightings, the same bar the trust root uses) — closes (1) at
a cost of zero to a legitimately scanned host; and state in the ADR, in the same register as "two
sightings verify nothing", that corroboration by an ssh host key is an echo, not a proof.

**Measured clean in the S42 ADR-094 re-review (do not re-derive).** Sightings cannot be inflated by:
the same scan swept twice (the batch cut — `last_seen_scan IS DISTINCT FROM` blocks it); two
observations of one key in one group (same scan, and a second scan in the same group is blocked by
`EXCLUDED.last_seen_at > ...`, since every Record in a group passes `h.seenAt`); `uuid.Nil` scan or
empty address (both return before the sighting insert); a key another asset holds live (the sighting
SELECT is qualified by `k.asset_id = $2`, and the key insert is DO NOTHING). A scan point cannot
forge the occasion: `IngestService.tasksBelongToJob` rejects a chunk whose observation names a task
outside the submitted job, so the scan id derived by `Jobs.ScanIDForTask` is the scan of the job the
scan point holds a lease on. C1/H1 both fail at the victim: whichever order the attacker enrols at
their own address and spoofs at the victim's, `SSHHostKeyFingerprintsAt(victim, 22)` is empty after
one scan at the victim, and later scans at the attacker's OWN address raise only the own-address
count. Tenancy holds: two tenants with the same RFC1918 address and different keys each see exactly
one sightings row under an unpredicated SELECT. `ListUnresolved`'s new anti-join does not starve the
500-row batch (the LIMIT applies after the filter) and uses
`asset_resolution_queue_pending_obs_idx` as an index-only scan. `refuseCredentialedJob`'s audit event
IS replayed in a fresh `db.Write` when the assignment pass rolls back (`dispatch.go`, the `refusals`
slice), which is class 31 applied correctly.
**Re-confirmed in the S42 FINAL pass (after the cert carve-out, the port key and the window):**
C1/H1 (one scan at the victim = `scans_seen=1`, trust empty; two = trusted, the stated cost); the
dual-homed host (ssh+tls at two addresses, four scans with the group order alternating —
`scans_seen=4` at each address, one asset, trusted at both); the keyless sibling (an ssh handover
parks 2 observations with 2 queue items, no new key, no service row for the newcomer's port, stable
across three further sweeps); the queue branch has no error path after `Enqueue` (it returns nil
immediately — refusal durability OK).
**One claim from that pass is now FALSE and the falsification is class 56.** "The cert-takeover
variant self-parks — a newcomer bringing a contradicting cert AND a new sshd attaches on scan 1 and
is contested by ADR-007 on scan 2, because its own key now agrees" held only while the cert carve-out
sat INSIDE the attach branch. Moving it ahead of the not-outvoted guard (the S42-final fix for class
51) removed the scan-2 parking, and the newcomer now attaches twice and reaches the trust root.
Re-measure any "it self-corrects on the next scan" conclusion whenever the guard that did the
self-correcting is reordered.

**Re-measured clean in the S42 THIRD pass (the corroboration fix), do not re-derive.** (a) The
cert-takeover of class 56 records nothing and reaches no trust root (above). (b) The renewal path
works end to end on BOTH verdicts: steady ssh + renewed cert at the held address retires the old
certificate, records the new one, 0 queued / 0 unresolved, and the host's next DHCP move merges on
ssh + the NEW certificate (1 asset) — and a host with a second steady cert on 8443, which reaches
the MERGE branch instead of the attach branch, retires and replaces the same way (`Verdict` carries
`Contradicted`/`Corroborated` on `DecisionMerge` too; that was added mid-review). (c)
`AssetIdentityKeys.Retire` is correctly scoped: `tenant_id`+`asset_id`+`key_type`+
`merge_evidence_payload->'port'`, measured not to touch another asset's key of the same type and
port, nor the same asset's key on another port; it is only ever called for `KeyServiceCert`
(the carve-out is `k.Type == KeyServiceCert`), so no ssh key can be retired by it. A key whose
payload carries no port is never retired — unreachable from correlate, which always has one.
A retired key is not tombstoned: `Record`'s `ON CONFLICT ... WHERE valid_to IS NULL` inserts a new
row, so a victim's retired certificate returns as a fresh row the next time it is observed.


**58. A refusal held in PER-CONNECTION MEMORY, with a reconnect path that rehydrates from a
store that was never told.** `IngestService.handleChunk` set `sub.quarantined` on a struct that
lives for one gRPC stream; the ledger row's `status` was written only by `Begin` (chunk 0) and
`Complete` (final chunk), and `RecordChunk` never touched it. A quarantine raised on chunk 1 was
therefore invisible to `resume()`, which reads the ledger — so a scan point sent the offending
chunk, hung up before `final`, reconnected, and the terminal promotion read "accepted" and
promoted the offending observations into the finding pipeline. Measured on all three content
guards (the ADR-095 `package` gate, the ADR-008 zone check and `tasksBelongToJob`); only the
epoch check self-healed, because its condition is DURABLE and re-evaluates identically on the
resumed stream. Fixed by `store.Submissions.Quarantine`, an UPDATE on every chunk after the
first.
**Why:** the code's own comments said "quarantine is sticky" and "quarantine carries across
streams"; both were true only for a quarantine raised on chunk 0, and the shipped test only ever
sent one stream.
**How to apply:** for any flag that means "we refused something", ask where it lives between two
network round trips and what the RECOVERY path reads. The discriminator is a probe that ends the
stream WITHOUT the terminal message and reconnects — assert on the ledger row and the row state,
not on the ack.

**59. Two refusals in one transaction: the second one's ROLLBACK discards the first one's
record.** Class 3, new shape. After the fix for class 58, `Submissions.Quarantine` is written
inside the chunk's `db.Write`, and `toObservations` runs AFTER it and returns `errMalformed` — a
refusal, deliberately a sentinel so the transaction rolls back. A scan point that appends one
observation with `confidence: 2.0` to the chunk carrying its gate violation therefore gets
REJECTED_MALFORMED and leaves the ledger at `accepted`, with no `result_submissions` row, no
audit event and nothing on the quarantine queue: the attempt is measurable only on the wire.
Measured 2026-09-12: `ledger=accepted` after the violation, `ACCEPTED` after the reconnect.
**Why:** the repo's own rule (internal/store/CLAUDE.md) is that a refusal must not ride a
transaction that a later refusal aborts; the fix for one refusal was placed upstream of another.
**How to apply:** after adding any refusal RECORD inside a `db.Write`, enumerate every `return
err` below it and classify each as fault (must roll back) or refusal (must not). Where the abort
is unavoidable, the record has to move to a fresh transaction — the precedent is ingest's own
ledger-conflict resume.

**60. A hostile-input guard written as a byte-substring match on the ENCODED form.** ADR-095's
review produced a fix for "a NUL escape fails at the jsonb column and answers RETRY_LATER for
input that can never succeed": `bytes.Contains(payload, []byte("\\u0000"))` in
`toObservations`. That matches the raw wire bytes, so a JSON string whose DECODED text is the six
characters backslash-u-0000 (encoded on the wire as backslash-backslash-u-0000) matches too — and
that text survives the fingerprint engine's `sanitise`, which only replaces bytes below 0x20.
A single hostile banner therefore returns REJECTED_MALFORMED for the WHOLE submission, which
tells the scan point to clear its buffer: up to 5,000 observations covering 32 hosts discarded,
with no ledger row, against ADR-026's "results are always stored, never discarded". Measured
2026-09-12: one such observation among five, `ack=REJECTED_MALFORMED`, `ledger=<no row>`.
**Why:** the quantity the column rejects is a property of the DECODED value; the check was
written against the transport encoding, where an escaped backslash is indistinguishable from an
escape.
**How to apply:** any validation of attacker-supplied JSON must run on the decoded value (or
track escape state), never on `bytes.Contains` over the raw payload. And any refusal that
discards a whole submission needs the blast radius named: one host must not be able to void a
32-host job.

**61. A quarantine scoped to the SWEEP BATCH, not to the thing it protects.** ADR-094 parks a
contested host group: `correlate.resolveHost`'s queue branch enqueues an item per observation in
`h.obs`, and `Observations.ListUnresolved` then excludes observations that HAVE a pending item.
The park therefore covers exactly the observations that happened to be in that sweep's 500-row
batch (`correlate.Batch`). Any observation of the SAME scan at the SAME address that arrives in a
later sweep re-groups alone, carries only `ip_window`, finds the address holder, and ATTACHES —
writing the newcomer's services onto the previous occupant's asset, which is the back door the
branch's own comment says the whole-group park closes. Measured 2026-09-12: one host answering on
521 ports at a held address with a contradicting host key on 22 parked 500 observations and
raised one `identity.contested` event, then the next sweep attached the remaining 21 and wrote 21
service rows onto the occupant's asset. Fully target-controlled: a group larger than `Batch`
cannot fit in one sweep, so the overflow always attaches.
**Why:** the exclusion that makes the re-sweep a no-op (and the new audit event fire once) is
per-observation; the property being protected is per-ADDRESS. Any filter that parks "the rows I
just saw" leaks the rows I did not.
**How to apply:** when a guard parks a SET, ask what identifies the set (address, asset, job) and
whether the park is expressed in those terms or in terms of the rows in hand. Probe by delivering
one member of the set a sweep/batch later than the rest — the batch limit makes that free.

**62. A health aggregate that filters out the rows it cannot interpret, with the UI chip keyed
off the filtered count.** `ResolutionQueue.PendingAddresses` counts
`DISTINCT observed_payload ->> 'address'` under `WHERE ... observed_payload ? 'address'`, and
`Health.tsx` colours the row green when that count is 0 while printing the unfiltered item count
beside it. `Enqueue` writes `{}` when a key carries no payload, so those items vanish from the
address count: 141 of 348 pending rows in the dev database (40%, all written the previous day by
the pre-ADR-094 code path, `observation_id IS NULL`) are exactly that shape. A tenant whose
pending items are all of that vintage reads "0 hosts · N items" in the OK colour.
**Why:** two numbers describing one queue, derived by different predicates, presented as one
sentence — and the reassuring one is the one that can silently drop rows.
**How to apply:** any `count(DISTINCT payload->>'x') ... WHERE payload ? 'x'` needs a third
number for the rows the filter dropped, or a COALESCE to a column that is always present
(`key_value` here). Also measure the cost: `count(DISTINCT expr)` sorts the WHOLE row (jsonb and
all) — 100k items took 296 ms and spilled 115 MB of temp per call, versus 79 ms / 2 MB for
`SELECT count(*) FROM (SELECT DISTINCT expr ...)`, on a table an attacker can grow and an
authenticated endpoint reads.

**63. A "did the rightful holder answer" fact read from a table only the SUCCESS path writes.**
ADR-096's rotation refuses when the held SSH key "has answered at the address since the newcomer's
first sighting", and measures it with `AssetIdentityKeys.LastSeenAt` over
`asset_identity_key_sightings`. That table is written only by `Record`, which runs only on an
attach/merge — so every scan that PARKS (and a park is exactly what a contested address does),
and every attach that takes the `uncorroborated` branch, leaves no trace there at all. Measured
2026-09-12: victim answers port 22 with its own key on the scan between the newcomer's two
sightings, the group parks because the attacker contradicted a second port, and the next scan
classifies a rotation with `held key seen since=false` — the victim's key retired, and the
attacker's key the trust root one scan later. The same blindness covers THIS scan: the held key
present in `observed` on the very scan being resolved does not stop the classification either
(`rotation()` never looks at `agreeing`).
**Why:** the evidence for "they were here" lives in the queue items (key value + observation +
observed_at) and in the observations themselves; the sightings table is a record of DECISIONS, not
of sightings, and the two diverge precisely when the decision was "do not decide".
**How to apply:** when a rule says "X was not seen", find the write path of the table that would
have recorded X and ask which branches skip it. If any branch that skips it is reachable by the
same attacker, the fact is a free lunch. Read both sides of a comparison from the SAME source —
here `KeyScansPending` already reads the queue for the newcomer; the held key needed the same
query, not a different table.

**64. Continuity/corroboration facts satisfied by the VICTIM's own concurrent answers.**
ADR-096 attaches a contradicting SSH host key as a "rotation" when the service surface and OS hint
are continuous — facts measured over the whole address GROUP, which contains the legitimate host's
observations as well as the attacker's. Measured 2026-09-12: an attacker who holds ONLY tcp/22 at
an address (victim still answering 443 with its own certificate and product) gets
`services continuous=true` from the victim's own banner, supplies `OS agrees=true` from its own
port-22 banner, and re-roots the ADR-091 trust material to its key in three scans. The ADR's risk
section prices the attack as "holds the address while the occupant is SILENT, answers on every
port, reproduces the OS hint" — none of which was needed.
**Why:** an aggregate computed over a set that mixes trusted and untrusted members is evidence
about the set, not about the member under scrutiny.
**How to apply:** for any "the rest of the host still looks the same" test, ask which observations
in the set the attacker had to produce. If the corroborating ones are the victim's, the test
measures the victim's liveness, not the attacker's cost — and a live victim makes it EASIER, which
inverts the intent. Cross-check the ADR's stated attack cost by building the cheapest attacker that
still passes, not the one the ADR describes.

**65. A write that silently does nothing on conflict, after an irreversible write that assumed it
would succeed.** `AssetIdentityKeys.Record` is `ON CONFLICT (tenant_id, key_type, key_value) WHERE
valid_to IS NULL DO NOTHING` and returns nil either way. ADR-096's rotation calls `Retire` (closes
the held key) and then `Record` (the newcomer). When the newcomer's value is already live on
ANOTHER asset — the attacker enrolled it on their own host first, or a cloned VM template shares a
host key — Retire succeeds, Record no-ops, and the asset ends holding NO SSH key, while the
`identity.rotated` audit event lists the key under `"recorded"`. Measured 2026-09-12; the trust
root then reads empty and `dispatch.trustMaterial` refuses the credentialed job (fail-closed), so
the cost is a durable denial plus an audit record that states the opposite of what happened.
**Why:** `DO NOTHING` turns a uniqueness violation into a silent no-op, and a two-statement
"replace" has no transaction-level guarantee that the second half happened.
**How to apply:** any `DO NOTHING` upsert that a caller treats as "the row now exists" must return
`RowsAffected`; a caller that already destroyed the old value must abort (and let the queue keep
the refusal) when it gets 0. Assert on the row, not on the returned error.

**66. A close-out verb scoped to the ADDRESS when the classification was scoped to one KEY.**
`ResolutionQueue.CloseRotated` closes every pending item at the address naming the asset as
`state='rotated', resolved_asset_id=<asset>`. A rotation classified for one key on one port
therefore closes items parked for contradictions it never examined. Measured 2026-09-12: six items
closed, of which two were the classified newcomer's — the rest included the VICTIM's own key items
and a second-port contradiction. The observations re-enter the sweep and re-park (nothing is lost),
but the queue's history now asserts a classification that was never made, and the re-park raises a
fresh `identity.contested` for an operator who already saw one.
**Why:** the release has to be at least as wide as the park (the park is per-address) but the
DECISION was per-key; using the park's scope for the decision's outcome relabels other people's
refusals.
**How to apply:** when a carve-out closes a queue, diff the set it closes against the set the
decision actually covered, and give the remainder its own state (or leave it pending).

**67. A trust exclusion keyed on the VERDICT LABEL, defeated by declining the verdict.** ADR-096's
fix for #64 was `SSHHostKeyFingerprintsAt ... AND k.provenance <> 'rotation'` — a key recorded by a
rotation is never credentialed trust material. Measured 2026-09-12: an attacker who deliberately
FAILS the classification (change one product banner) keeps the group parked; a park touches no
address, so after `AddressWindow` `AssetAddresses.CloseStale` closes the occupant's interval, the
next sweep finds no candidate by key OR by address, `Resolve` returns `DecisionNewAsset`, and the
attacker's key is recorded with provenance `new_asset` — which the exclusion does not cover. Two
scans later it is the trust root at the victim's address. Worse, it is the INEVITABLE end state of
any park that outlasts the window, not a corner case: `Services.ProductsSince(now-window)` returns
nothing once the occupant's service rows stop being touched, so `servicesContinuous` can never pass
again either. Cost: hold tcp/22 for 7 days plus two scans — cheaper than passing the test, so the
control creates an incentive to fail it.
**Why:** the label records WHICH BRANCH wrote the row, and an attacker chooses the branch. The fact
that matters is a property of the evidence (this key was first seen while a contradiction was
pending at this address), not of the verdict that happened to record it.
**How to apply:** for any exclusion written as `provenance <> X` / `source <> X` / `reason <> X`,
enumerate every other value the same attacker can steer the row to, and time-travel: run the
scenario past every window the code owns (`AddressWindow`, `SightingWindow`, a partition drop) and
re-measure. The two cheapest probes are "decline the classification and wait" and "let the park
outlive the window".

**68. A park whose escape hatch is corroboration, at an address where corroboration is public.**
ADR-096 parks a weak-only sighting at a contested address (`c.PendingContested &&
len(corroborated)==0`). Measured 2026-09-12: one AGREEING moderate key defeats it — the occupant's
own TLS leaf fingerprint or SSH host-key fingerprint, both readable by anyone who can reach the
host — and the newcomer's services were written onto the occupant's asset while the contradiction
was still pending, bumping the echoed key's sighting count on the way through.
**Why:** the park exists because identity at the address is an OPEN QUESTION; an echo of a public
value is not an answer to it, and `agreeing` does not distinguish "the host answered" from "someone
replayed what the host says".
**How to apply:** a guard of the form `if <contested> && <nothing agrees>` is really `if
<contested>` with an attacker-controlled escape. Either drop the escape or require the corroborator
to be ESTABLISHED (two scans) *and* absent from the pending items at that address.
*Fixed and re-measured 2026-09-12:* `Candidate.PendingContested` now parks EVERY sighting short of
a merge, the occupant's own agreeing key included — the single-echo straggler parks and writes no
service. What still walks through is a MERGE-grade echo (two agreeing moderate keys): measured, the
newcomer's service row landed on the occupant's asset. That half is conceded as B40/B44 — but see
#72: only the SSH half of the echo is actually free, because a TLS leaf fingerprint costs the
victim's private key.

**69. A down migration that rewrites a refusal marker to "the nearest older word".**
`0045_rotation_states.down.sql` does `UPDATE asset_identity_keys SET provenance='attach' WHERE
provenance='rotation'` so the enum can be rebuilt. Measured 2026-09-12 on a scratch round-trip: a
down+up cycle leaves every rotation-recorded key reading `attach`, and the trust-root exclusion that
was the entire control silently stops applying. The relabel is a true statement of lineage and a
false statement of trust.
**Why:** enum removal forces a value rewrite, and the natural choice is the semantically closest
surviving label — which for a refusal marker is always the permissive one.
**How to apply:** when a down migration rewrites rows carrying a value some query REFUSES on, the
safe rewrite is the one that keeps refusing: close the row (`valid_to = now()`), delete it, or move
it to a state nothing trusts. Round-trip the migration with rows present (scratch DB + `for f in
migrations/*.up.sql`) and re-run the security query afterwards, not just the schema diff.
*Fixed and re-measured 2026-09-12:* the down now `UPDATE ... SET valid_to = now()` before the
relabel. Scratch round-trip with rows present: the key comes back `attach` AND retired, the trust
predicate returns 0 rows before and after a fresh one-sighting re-record, so the key needs two new
sightings to matter again. The queue-item half (`rotated` -> `merged`) still asserts an operator
decision that never happened; `resolved_by` stays NULL, which is the only tell.


**70. A guard that keeps the ROW alive without keeping the FACT alive — the fix one layer below
the decision.**
The fix for #67 was `AssetAddresses.CloseStale` skipping an address with a pending item naming its
holder (`internal/store/identity.go`), so the contested interval never ages out. Re-measured
2026-09-12, end to end: the interval does stay `valid_to IS NULL` — and the attack is unchanged.
`domain.Resolve` does not ask "is the interval open"; it asks
`holdsAddressInWindow(c, now, window)`, i.e. `AddressLastSeen` (= `asset_addresses.valid_from`,
rewritten only by `TouchLive` on an attach) within `AddressWindow`. A park touches no address, so
after 7 days the holder stops being "at the held address", `atHeldAddress` is false, the whole
ADR-096 branch — handover, rotation classification and `PendingContested` alike — is skipped, and
the newcomer is `DecisionNewAsset` with `new_asset` provenance. Domain probe, same inputs, one
field changed: held 1h ago + pending item -> `queue`; held 8d ago + pending item -> `new_asset`,
reason "no candidate matched any observed key". The pending flag is COMPUTED and handed to the
decision (`candidatesFor` sets `PendingContested` from `LiveHolder`, which has no window) and then
read only inside the branch the window already closed.
**Why:** a relationship is stored in two places — the row's existence and a freshness timestamp on
it — and the guard was added to the one the attacker was not using. "The row survives" and "the row
still counts" are different claims, and only the second is a control.
**How to apply:** when a fix extends the LIFETIME of a row, find every predicate that decides
whether that row still COUNTS (a `last_seen >= now-window`, a `scans_seen >= N`, a decay reset) and
check the fix reaches all of them. Then re-run the original end-to-end scenario past the window —
the store-level assertion ("the interval is still live") passes while the decision-level assertion
("the trust root is still empty") fails, and only the second one is the finding.

**71. A park with no expiry, no operator verb, and now no way to age out.**
Same change, other direction. With #70's `CloseStale` skip in place a pending item pins its address
for ever: measured 2026-09-12, one drive-by SSH contradiction against an SSH-ONLY host freezes that
host permanently — every later sighting parks (`PendingContested`), `services` stops at the
pre-attack row, `asset_identity_key_sightings` stops bumping, and after `SightingWindow` the
address's trust root is empty, so credentialed work refuses for ever. Cost per scan while frozen:
+2 pending items, +1 `identity.contested` event, +2 unresolved observations, unbounded. Nothing can
clear it: the rotation classifier needs the newcomer on two scans (it never returns) and needs
`Services.ProductsSince(now-window)` to be non-empty (the frozen rows age out), and B39's operator
verb does not exist. A merge-grade host (two agreeing moderate keys) is not frozen — it merges
straight through the park, which is #68's other half.
**Why:** a refusal that is correct at the moment it fires becomes a denial of service when nothing
bounds it and nothing can retract it. "Fail closed" needs an owner.
**How to apply:** for every park/quarantine/lockout, ask three questions and measure each: what
clears it, how long can it last if the attacker never returns, and what does the protected subject
lose per scan while it lasts. If the answer to the first is "an operator verb we have not built",
the change is not shippable without a bound (an expiry, an auto-close, or a re-derivation path).

**72. A stated weakness that is stronger than stated — measure the library, not the intent.**
Backlog B44 says "the SSH and TLS fingerprint engines record the host key and the certificate
without completing the exchange that proves the peer holds the private key", and ADR-096 leans on
it ("every identity key this build can observe is an ECHO") to justify parking the occupant's own
agreeing sighting. Measured 2026-09-12: true for SSH (`internal/engines/fingerprint/ssh.go` reads
the host-key blob out of `SSH_MSG_KEX_ECDH_REPLY`, hashes it, and abandons — the signature field is
never parsed), FALSE for TLS. `dialTLS` calls `tls.Client(...).HandshakeContext`, and Go verifies
the server's key-exchange signature / CertificateVerify even under `InsecureSkipVerify` (which
skips chain building and hostname matching only). Probe: serve the victim's DER with the attacker's
private key -> `tls handshake: tls: invalid signature by the server certificate: ECDSA verification
failure`; the observation is never produced. `service_cert_fp` is `Chain[0]`, so the key that
matters is the one that was proved.
**Why:** a security note written from the code's intent ("this engine does no verification") can be
wrong about what the standard library did anyway, and an overstated weakness misdirects the fix and
understates the value of evidence the system already has.
**How to apply:** before writing or accepting "X is not verified", run the negative case. For TLS,
present a certificate with the wrong private key; for SSH, corrupt the signature field. A backlog
row that names a missing check is a claim about behaviour and should be measured like one.

**73. An expiry that re-arms itself from the evidence it just released.**
The fix for #71 was an expiry: a contest whose last contradiction is older than the window closes
(`ResolutionQueue.CloseExpired`, state `expired`) on the next agreeing sighting, and "the parked
observations re-enter the sweep". Measured 2026-09-12: they re-enter, re-group at the same address,
contradict the same live key, and are parked AGAIN — with `enqueued_at = now`. Freshness is read
from `enqueued_at` (when the row was written), not from `observed_at` (when the host was seen), so
replaying a week-old observation mints a brand-new contest. One packet bought three measured cycles
of freeze -> one attach -> re-freeze, and the cycle only ends when the observation ages out of
`observedWindow` (90 days). The shipped test ran the release sweep and asserted only `assets == 1`
and `rotatedEvents == 0`, both true either way (#57's shape).
**Why:** closing a refusal record and releasing the input that caused it are two different acts. If
the released input is re-judged by the same rule, the system oscillates instead of converging, and
the bound the ADR advertises ("a window, not for ever") is not the bound that exists.
**How to apply:** for any close/expire/release verb, sweep ONE MORE TIME with no new input and
assert the terminal state (`pending = 0`, `unresolved = 0`), not just that nothing new broke. Then
ask what stops the released input from recreating the state that was just closed — an age check on
the EVIDENCE (`observed_at`), a "do not re-enqueue what was expired" guard, or resolving the
observation rather than releasing it.

**74. Freshness keyed on "the asset does not hold this key" instead of "this key contradicts".**
`ResolutionQueue.ContradictionLastSeen` decides whether a contest is still fresh by taking
`max(enqueued_at)` over pending items whose key is not `ip_window` and not live on the asset. A park
enqueues EVERY key in the group, and a park records nothing — so any key the occupant starts
presenting after the contest began (TLS enabled on 443, a renewed certificate, a second sshd on
2222) is permanently "not held", counts as a contradiction, and refreshes the contest on every
scan. Measured 2026-09-12: one drive-by packet plus the victim's own new certificate = 21 scans
over 42 simulated days, 43 pending items, 43 unresolved observations, zero expiries, the 443
service row never written. The victim freezes itself with its own evidence, and the attacker is
long gone. A key on a port the asset holds nothing for contradicts nothing under `domain.compare`,
which is the definition the freshness read should have used.
**Why:** "not recorded" and "in conflict" coincide only while the recording path is open; the park
closes it, so the two definitions diverge exactly when the guard matters.
**How to apply:** when a store read is named after a domain concept (contradiction, conflict,
disagreement), diff its SQL predicate against the domain function that defines the concept. Here:
same type AND same source/port AND a different live value — not `NOT EXISTS (live key with this
value)`.

**75. Two "independent" sites where the second is reached only through the first, and a guard that
compares normalised data to raw text.**
ADR-096 §3 claims two sites keep a contested address from ageing out: `AssetAddresses.CloseStale`
skips it, and `domain.Resolve` extends the hold via `Candidate.PendingContested`. They are not
independent — `PendingContested` is set only for the address's `LiveHolder`, so if the first site
closes the interval the second is never consulted. And the first site compares the queue item's
payload address as TEXT (`observed_payload ->> 'address'`) against `host(a.ip_address)`, while
every other site casts to `inet`. Measured 2026-09-12: with the payload address written
`2001:0db8:0077:0000:0000:0000:0000:0020` (or `10.77.6.010`) the skip never matches, the victim's
interval ages out, the contradicting host becomes a SECOND asset at the victim's address and its
key lands in `SSHHostKeyFingerprintsAt` — the ADR-091 credentialed trust root — after two scans.
Canonical spelling of the same scenario: one asset, empty trust root. Not reachable from a
well-behaved scan point (`target.Canonicalise` normalises task targets) but ingest checks payload
addresses only for `package` observations, so a compromised scan point or a future engine that
reports a learned address reaches it.
**Why:** a defence-in-depth claim is only true if either site alone holds; and inet data compared
as text has as many spellings as the sender chooses.
**How to apply:** for each "two sites" claim, delete site 1 on paper and check site 2 still fires.
For any address/identifier compared in SQL, compare in the TYPED domain (`= a.ip_address` with the
text cast on the other side, or a normalised column written at insert) — and remember a bare
`::inet` cast on stored text raises 22P02 on garbage, which in a per-tenant sweep query is its own
denial of service, so normalise at write time.

**76. A carve-out in the decision that the freshness read does not repeat — the victim's own
scheduled renewal sustains the refusal.**
`domain.Resolve` at a held address moves a same-service CERTIFICATE change out of `s.conflicts`
into `Contradicted`: an ACME renewal is a renewal, not a different host. `ResolutionQueue.
ContradictionLastSeen` — whose doc comment claims to be "domain.compare's definition of a
conflict" — has no such carve-out: same type, different value, same payload port, live key. So a
renewed certificate IS a contradiction to the freshness read and IS NOT one to the decision.
Measured 2026-09-12 on the dev DB: one drive-by packet on tcp/22, attacker gone the same day, the
victim renews its certificate once inside the window — 21 scans over 42 simulated days, 43 pending
items, 43 unresolved observations, 22 `identity.contested` events, ZERO expiries, `services.last_seen`
frozen at day 0. The park prevents the renewal ever being recorded, so the new value stays
"different from the held one" for ever and re-parks itself on every scan. Control with a steady
certificate expired on day 8, as designed. This is defect #74 one level down: #74's fix replaced
"not held" with "different value, same port", which is exactly what a renewal is.
**Why:** a carve-out is part of the definition. A second site that re-implements the relation
without the carve-out implements a different relation with the same name — and the direction of
the divergence decides whether a bounded refusal becomes unbounded.
**How to apply:** when a store read is named after a domain relation, enumerate every EXCEPTION the
domain applies to that relation (here: cert-at-held-address, key-from-another-port, key-the-asset-
does-not-hold) and check each one is in the SQL. Then measure the refusal's expiry with the
NON-ADVERSARIAL event that the exception exists for — a scheduled renewal, an upgrade, a reimage —
not only with the attacker's input.

**77. A per-service measurement map keyed on the service, with two contradicting values on one
service.** `Continuity.Keys` is `map[string]KeyContinuity` keyed on `k.Source` ("22/tcp"), and
`correlate.continuityFor` writes one entry per contradicting key — so two host keys contradicting
on one port share whichever measurement was written last. Measured 2026-09-12 (`internal/domain`,
pure unit): a key seen on ONE scan attaches as a rotation on a second key's two-scan history,
`RotationScans` defeated, and the `identity.rotated` audit event lists both as "recorded" while the
apply loop's second `Retire(type, port)` closes the first one in the same transaction. The ADR's
own rule refuses "two keys answering on one port" when one of them is the HELD key; two
CONTRADICTING keys on one port is the same shape and is not refused. Contrast: a contradiction on a
port with no measurement fails closed ("no measurement for 2222/tcp") — the collision case is the
one without a guard.
**Why:** a map keyed on a value that is not unique across the set silently discards measurements,
and the discarded one is the one that would have refused.
**How to apply:** for any `map[X]Y` built by a loop, ask whether two elements can share X. If they
can, either key on the full identity (source+value) or refuse the multi-valued case outright.

**78. `inet` equality includes the netmask, so `host()`-identical addresses are different keys.**
Measured 2026-09-12: a payload address of `10.44.3.10/24` beside `10.44.3.10` produced TWO live
`asset_addresses` rows that both render `10.44.3.10`, on two assets, coexisting under migration
0031's partial unique index on `(tenant_id, ip_address)`. Every ADR-096 by-address read
(`PendingAtAddress`, `ContradictionLastSeen`, `CloseStale`'s `q.address = a.ip_address`,
`CloseExpired`, `CloseRotated`) keys on that same inet value, so a `/24` spelling routes around the
whole contest. NOT a trust-root takeover: `credgrant` parses the target with `netip.ParseAddr` and
queries the bare `/32`, so the second asset's key never qualifies — fail-closed. Reachable only
from a compromised scan point or an engine that reports a learned address (`target.Canonicalise`
normalises task targets, and ingest checks payload addresses only for `package` observations).
Separately: a payload address `::inet` cannot parse (`not-an-address`) errors `LiveHolder`, the
group is logged and skipped — the tenant is NOT stalled — but the observation stays unresolved for
ever and keeps its slot in the `Batch = 500` `ListUnresolved` window.
**Why:** "normalise at write time" (#75) is only half the job; `inet` is not a host address, and the
uniqueness the schema advertises is uniqueness of (address, masklen).
**How to apply:** normalise to `host(x)::inet` / `set_masklen(x, 32|128)` at every write of an
address the identity model keys on, or reject a non-bare address at ingest. Check the partial
unique index actually constrains what you think it constrains before leaning on it.

*(#78 follow-up, 2026-09-12: the fix normalises at every WRITE — `groupByAddress` canonicalises
with `netip.ParseAddr(...).Unmap()`, `Open`/`LiveHolder`/`TouchLive`/`Enqueue`/`Record` wrap
`host($n::inet)::inet` — and is measured correct for new rows. It does NOT normalise rows already
in the table: migration 0045's backfill writes `r.a::inet` unwrapped, so a legacy payload of
`10.44.3.10/24` backfills as `/24` and matches no by-address read, and no migration rewrites
existing `asset_addresses.ip_address` / `asset_identity_key_sightings.address`. A masked live
address row is invisible to `LiveHolder` and to `Open`'s closeOthers — measured 2026-09-12 — so
the second live holder it was meant to prevent opens beside it. When a fix normalises at write,
ask what the already-written rows do.)*

**79. A "different from what the asset holds" relation evaluated against a SET that can hold two
values for one slot — the victim's own key becomes the contradiction that sustains its own park.**
`ContradictionLastSeen` calls a pending item a contradiction when the asset holds a live key of the
same type and payload port with a DIFFERENT value. An asset can hold TWO live `ssh_hostkey` rows
for one port: `correlate.resolveHost`'s new-asset/attach record loop writes every moderate key in
the host group, and a group is by ADDRESS only — two hosts answering one address in one sweep (two
zones with overlapping RFC1918 space, a batch-overflow deferral, a correlator that was down, or one
hostile SSH answer) puts two different keys on port 22 on one asset, no park, no announcement.
From then on the OCCUPANT's own key is "different from" the other held row, so every park the
occupant's own scans raise re-arms `ContestFresh`, `CloseExpired` never fires, `CloseStale` skips
the address for ever, and no observation at that address ever correlates again. Measured
2026-09-12 on the dev DB, both by new asset and by attach to a TLS-only asset: 21 days of the
occupant alone = 21 pending items, 21 uncorrelated observations, 0 expiries, empty trust root at
the address, `services.last_seen` never moving. One hostile observation, permanent, and with no
operator verb (B39) nothing can clear it. Counterfactual measured in SQL: adding `AND NOT EXISTS
(live key with the SAME value)` drops the 21 matching items to 0.
**Why:** `x <> held` is a refusal predicate only while `held` is single-valued. The moment the slot
holds two values, every value in it contradicts the other and the refusal feeds itself — and the
party who suffers is the one still telling the truth.
**How to apply:** for any predicate of the form "differs from what we hold", find the uniqueness
that makes "what we hold" one value and check the schema enforces it (here there is no unique index
on `(asset, key_type, port) WHERE valid_to IS NULL`, only on key VALUE). If it is not enforced,
either enforce it, or exclude the rows whose value the asset itself holds. And check the write
path: `domain.rotationFailures` already refuses to CLASSIFY two keys on one port, while the record
loop happily RECORDS them — a guard on the decision is not a guard on the write.

**80. An operator-facing note that states the opposite of what the code does, inside the change
that measured why.** ADR-096 and `internal/correlate/CLAUDE.md` say expired evidence STAYS OUT of
the sweep (releasing it re-parked itself with a fresh timestamp — one packet, a freeze renewed for
ever), and `ListUnresolved` implements that. `CloseExpired`'s doc comment, the expiry block in
`resolveHost`, and — worse — the `identity.contest_expired` audit event's `note` field all say the
parked observations "re-enter the sweep". Measured: they never do. The operator reading the event
while asking "where did seven days of this host's inventory go" is told the opposite of the truth,
and the next maintainer who "fixes" `ListUnresolved` to match the comment reopens a hole the ADR
says was measured.
**Why:** a comment is a claim about behaviour; an audit-event note is a claim made to the person
who has to act on it.
**How to apply:** when a change turns on a distinction between two states (`rotated` releases,
`expired` does not), grep every string that describes the outcome — comments, audit `note` fields,
API docs — and check each against the state it actually describes.

**81. A carve-out that suspends an ageing rule with no freshness bound of its own — the hold
outlives the reason for it, and a THIRD party inherits it.** ADR-096 stops a contested address
ageing out at two sites: `AssetAddresses.CloseStale` skips an interval while a pending item names
its holder, and `domain.Resolve` treats `c.PendingContested` as extending the hold
(`holdsAddressInWindow(...) || c.PendingContested`). Neither is bounded by the freshness the
DECISION uses (`domain.ContestFresh`), so a park that has gone stale still freezes the interval for
ever. Measured 2026-09-12 on the dev DB, two consequences from one root cause: (a) a genuine
different host on a reused DHCP lease — ADR-094's own headline shape — parks on every scan for
ever (pending 1→2→3, one `identity.contested` per scan, the address still LIVE at 21 days, the
newcomer never becomes an asset, reason "not a rotation: services not continuous", which can never
pass again once the gone occupant's products age out of the 7-day window), where before this change
`CloseStale` closed the interval at 7 days and the newcomer became a new asset; and (b) a THIRD
host that contradicts nothing (TLS-only) attaches to the dead occupant's asset on the address
alone 21 days later, writes its 443 service row onto it, expires the park, and `Open`/`TouchLive`
RESETS the interval to now — so the wrong asset is "here now" again and keeps accreting the third
host's inventory. That is ADR-007's wrong merge, reached through an ageing rule that was suspended
and never resumed.
**Why:** "do not age this out while X is pending" is only safe while X is still true of something.
A pending row is a fact about the past; the decision reading it had a freshness test and the
housekeeping that protects it did not.
**How to apply:** whenever a change adds "skip the sweeper for rows in state X", ask what ends X,
and check that the ONLY thing that ends it is not the return of the party the park is protecting
(see 82). Measure the third-party case explicitly: park an address, age everything a few windows,
then present evidence that neither agrees nor contradicts and see whose asset it lands on. A
`ContestFresh`-bounded carve-out (and an inventory-only provenance for the newcomer, which this
same diff already invented for rotations) gets the safety without the freeze.

**82. A close-out that only the party the refusal protects can trigger.** `CloseExpired` runs from
`resolveHost` only on an ATTACH to the contested asset — i.e. only when the address holder comes
back and its own evidence agrees. The classification route out (`CloseRotated`) needs
`servicesContinuous`, which needs the holder's service rows inside the window. So every escape from
the park is keyed on the occupant returning; a decommissioned host whose IP is reused, or a host an
attacker has replaced, never returns, and the park is permanent with no operator verb (B39).
**Why:** an expiry is only an expiry if time alone can fire it. "Expires on the next agreeing
sighting" is a conditional release, and the condition is exactly what the failure mode removes.
**How to apply:** for every park/lock/quarantine, list the transitions out and strike the ones that
need the victim to act. If nothing time-based remains, it has no expiry however the ADR words it.

**83. A backstop uniqueness index keyed on data the submitter spells.**
`asset_identity_keys_one_live_per_port_uidx` is `UNIQUE (tenant_id, asset_id, key_type,
(merge_evidence_payload -> 'port')) WHERE valid_to IS NULL AND merge_evidence_payload ? 'port'`,
and the payload is the scan point's raw observation JSON, copied verbatim. Measured 2026-09-12:
a payload spelling `"Port": 22` is decoded by Go case-insensitively (so `keysFrom` still derives
`Source "22/tcp"` and the sighting still lands at port 22, making the key credentialed trust
material) while jsonb `? 'port'` is FALSE — the row is outside the index, invisible to `Retire`,
`LastSeenAt` and `ContradictionLastSeen`, and `ForAsset` derives `Source ""` so `compare` can never
call anything a contradiction of it. One such observation gives an asset two live SSH keys on one
port, both trust material at the dialled port. The same divergence with `"protocol": ""` (held
Source `"22/"`, observed `"22/tcp"`) makes the resolver decide ATTACH for a key the index then
REFUSES: measured `store: conflict: asset_identity_keys_one_live_per_port_uidx`, which aborts the
host's whole `db.Write` — the address `Open` in the same transaction was lost — leaving the host
uncorrelated for ever with only an ERROR log. Related: the index key is NARROWER than the
comparison it backs (port, not port+protocol), so a cert on `443/udp` beside one on `443/tcp` is
"no contradiction" to `domain.Resolve` and a unique violation to the database (measured; today
unreachable only because every engine hardcodes `"tcp"` and the field is `omitempty`).
**Why:** a constraint is a backstop only if its key is derived by code you control. Here it is
derived from attacker-or-sensor-supplied JSON, and Go's case-insensitive field matching means the
application and the database disagree about what the row says.
**How to apply:** when a migration adds a constraint over a jsonb expression, ask who wrote that
jsonb and whether any other reader of the same fact uses a different extraction. Prefer a real
column written from the function's own normalised argument (`Record` already takes `port int`).

**84. A queue row that names nobody, in a queue whose every close-out is keyed to a named party.**
ADR-096 drops `asset_resolution_queue_candidates_non_empty` so two hosts answering one port at an
address nothing holds can be parked as "unplaceable" with `candidate_asset_ids = '{}'`. Every
close-out — `CloseExpired`, `CloseRotated` — and every freshness read requires
`$asset = ANY(candidate_asset_ids)`, so nothing can ever close such a row, and there is no operator
verb. Measured 2026-09-12: 2 unplaceable items still pending after 60 days; an asset that later
claimed the same address was correctly NOT frozen by them (good) and its interval aged out normally
(good) — but `contested_addresses` reports that address for ever, `resolution_queue_pending` never
returns to 0, the Health chip is permanently amber with nothing an operator can do, the two
observations are permanently uncorrelated, and each further scan of the address adds two more items
plus an audit event, unbounded.
**Why:** dropping a NOT-EMPTY check on a column that every state transition joins against creates
rows outside the state machine. They are not wrong, they are unreachable.
**How to apply:** when a CHECK is dropped to admit a new shape, enumerate the writes that read the
column it guarded and give the new shape its own transition (here: an absolute expiry — an item
naming nobody loses nothing by expiring, since nobody was going to be chosen).

**85. Two branches for one shape, and the cheaper branch grants more trust.** ADR-096 gives a
same-service SSH key contradiction at a held address two possible outcomes: a ROTATION attach
(provenance `rotation`, excluded from `SSHHostKeyFingerprintsAt` for ever) and a LAPSE
(`DecisionNewAsset`, provenance `new_asset`, credentialed trust material after two sightings).
The lapse is tested FIRST, so whenever it qualifies it preempts the branch that withholds trust.
Measured 2026-09-12 in `domain.Resolve`, one input differing: held key last sighted 2 days ago →
`attach` + `Rotated` (trust never); 7 days + 1 h ago → `new_asset` + `Lapsed` (trust at the next
scan). End to end: occupant attaching at the address every scan, its key's sighting 9 days old,
attacker answering only tcp/22 → new asset on the attacker's 2nd scan, address transferred,
`SSHHostKeyFingerprintsAt` returns the ATTACKER's fingerprint on the 3rd.
**Why:** the lapse's staleness test reads the key's last sighting, not the relation the verdict
claims has lapsed (the address hold). `holdsAddressInWindow` was never consulted, so "the occupant
has lapsed" was asserted about a host that had attached a minute earlier. A key sighting goes stale
on its own (an SSH fingerprint comes from an occasional intrusive pass, not every scan), so the
precondition is the normal state of a live host.
**How to apply:** when a decision names a party as gone, check that the freshness it reads is the
freshness of the RELATION it is about, and that the branch order cannot let a trust-granting
outcome preempt a trust-withholding one for the same evidence. The fix measured green here:
`len(agreeing)==0 && !holdsAddressInWindow(c, now, window) && occupantLapsed(...)` — both shipped
integration tests still pass; only the domain test's own fixture (address attached one minute ago)
had to be aged, which is how you know the test was asserting the defect.

**86. An early `return` inside the candidate loop, before the verdict switch orders the answers.**
`domain.Resolve` scores every candidate and then lets a `switch` apply ADR-007's precedence
(contested > qualified > attachable). The lapse branch returns from inside the loop. Measured
2026-09-12: observed = the mover's ssh key on 22 + its cert on 443 + the address; asset A holds
BOTH observed keys (two independent moderate keys = a merge under ADR-007); asset B holds the
address with a stale key sighting. Verdict: `new_asset`, `Lapsed = B` — A's merge-grade match
discarded, in either candidate order. A DHCP host that moved therefore evicts the occupant and
creates a keyless duplicate: `Record` is `ON CONFLICT ... DO NOTHING` for a value live on A, so the
new asset holds the address and no keys, and every later scan attaches to the duplicate. The same
branch also ignores `KeyContinuity.NewKeyHeldElsewhere`, which the sibling rotation branch refuses
on for exactly this reason ("would retire the held key and record nothing").
**Why:** a branch that returns skips both the precedence rule and the sibling branch's guards.
ADR-096's own bound — "asked only when the first verdict named exactly one candidate" — does not
hold, because a contested verdict's `Candidates` lists only the contested candidates and the
qualified ones are invisible to the caller.
**How to apply:** in a resolver with an ordered verdict switch, a new outcome belongs in the
scored set, not in a `return`. Probe it with TWO candidates, one of each shape, in both orders.

**87. A canonicalisation guard whose claim is wider than its parser.** `groupByAddress` now does
`netip.ParseAddr` and the comment says "strict (no leading zeros, no mask, no zone)". Measured
2026-09-12: `netip.ParseAddr("fe80::1%eth0")` SUCCEEDS and `String()` keeps the zone, while
`host('fe80::1%eth0'::inet)` is a Postgres syntax error — so every by-address read and write in the
host's transaction fails, the group is never resolved, and the ERROR repeats once per sweep for the
90 days the observation stays inside `observedWindow`. `ListUnresolved` is `ORDER BY observed_at
LIMIT correlate.Batch (500)`, so ~500 such observations (a scan point's payload field, unvalidated
at ingest) pin the head of the batch and stop correlation for the whole tenant.
**Why:** the guard was written to close a spelling attack and its comment states a property the
parser does not have. The residual class is not benign: it is a permanent per-tenant detection
denial with no queue item and no Health signal, only a log line.
**How to apply:** for any "we normalise it here" guard, test the classes the NEXT layer rejects
(`ip.Zone() != ""`, `Is4In6`, unspecified/multicast) and prefer refusing at ingest so the store and
the resolver share one grammar. A host group that cannot be written is worse than one refused: the
refusal is visible.

**88. A refusal whose own park freezes the freshness that a later eviction reads — so the attacker
manufactures the precondition, and the slower path grants MORE authority than the fast one.**
ADR-096 parks every sighting at a contested address, the occupant's own included, and the park
path returns before `Open`/`TouchLive`. So the occupant's address interval and its `services.last_seen`
both freeze at the instant of the contest. One window later the lapse branch reads
`!holdsAddressInWindow` — which by then means "the contest is a week old", not "the occupant is
gone" — and `ProductsSince(now-7d)` is empty, so the rotation classification can no longer pass.
Measured 2026-09-12 end to end: victim answering tcp/80 (nginx) and tcp/22 (OpenSSH, key
established); attacker takes tcp/22 with a *different* banner so continuity fails; one window of
parking; then `new_asset` for the attacker, the victim's interval closed under it, the victim's own
nginx:80 row rewritten onto the attacker's asset, and the attacker's key recorded `new_asset`
provenance — which `SSHHostKeyFingerprintsAt` does NOT exclude — so it is the credentialed trust
root (and `dispatch.trustMaterial`'s only known_hosts line) on the next scan. Counterfactual
measured the same day: with nothing contradicting, nine simulated days of the victim's keyless
tcp/80 answers renew the hold indefinitely (each attach `TouchLive`s it), so ADR-094's "wait for the
address to lapse" price is unpayable against a live host. The contradiction is what makes it payable.
**Why:** two ways in. (a) The gate's freshness is measured on a relation the refusal itself stops
updating — "outside the window" ends up meaning "the park is a week old". (b) The two outcomes for
one shape are graded the wrong way round: passing the classification (2 scans, mimic the banner)
gives inventory only, because a rotation-recorded key is excluded from trust; failing it (one
window, no mimicry needed) gives inventory AND trust. The attacker picks, and the cheaper forgery
buys more.
**How to apply:** when a decision says a party has lapsed, ask what wrote the timestamp it reads and
whether the adversary's own action stopped that write. And compare the authority of every outcome a
single shape can reach: if the harder-to-forge path is the one that withholds trust, the rule is
inverted. Measured fix, one line, both shipped lapse tests and the rotation test still green:
record a lapse's keys with a provenance the trust root excludes —
`if v.Lapsed != uuid.Nil { from = store.KeyFromRotation }` in the attach/new-asset recording block
of `correlate.resolveHost`. Inventory still moves; trust stops. A "make the lapse smarter" fix
(refuse it while any product the asset has ever answered with still answers at the address) also
closes it but turns the shipped reused-lease test into a permanent park, because on banner data
"the occupant is still there" is indistinguishable from "the newcomer reproduces its banners".

**89. A trust exclusion added to ONE reader of a table and not to its sibling reader, which was
written to enforce "the same bar".** ADR-096 gave `SSHHostKeyFingerprintsAt` its
`AND k.provenance NOT IN ('rotation','lapsed')` predicate — a rotation/lapse moves inventory, never
credentialed trust. `AssetIdentityKeys.EstablishedAt`, whose own doc comment says "the same bar the
trust root sets" (same table, same `scans_seen >= 2`, same window), did NOT get it. Measured chain,
four scans after a rotation attach: the attacker's key is recorded `rotation` and the trust root is
correctly `[]`; one scan in which they simply DO NOT answer 443 bumps that key to two sightings
(nothing contradicts, so the plain loop records and the sighting counts); the next scan's renewed
certificate is then "corroborated by an established key", the victim's cert is retired and the
attacker's is recorded with provenance `attach`; presenting both keys at an address the attacker
owns merges their host onto the victim's asset (1 asset, both addresses live). ADR-096 names that
exact outcome as what the establishment gate prevents ("two moderate keys on the asset ...
mergeRule's bar at any address the attacker controls") — and the gate is satisfied by the very key
it was protecting against. Credential exposure stays closed (the ssh key is still excluded), so the
loss is asset identity: cross-host finding attribution, and an attacker-controlled moderate key of
trusting provenance living on the victim's asset.
**Why:** the exclusion was designed as a property of the TRUST ROOT QUERY rather than of the ROW,
so every other reader of the row keeps the old semantics; and the two readers sit 200 lines apart
with near-identical SQL, which reads as already consistent.
**How to apply:** when a new provenance/label means "this row is not evidence", grep every reader
of the table and make the exclusion a property of the row (a view, a generated column, or a
`trusted` predicate used by all of them) — not a clause in the one query that prompted it.
`AND k.provenance NOT IN ('rotation','lapsed')` in `EstablishedAt` was measured to break the chain
at step one and to kill EXACTLY ONE shipped test — the one whose fixture asserts the certificate
replacement — while `TestACorroboratedRenewalRetiresTheOldCertificate` and
`TestAPlantedKeyCannotCorroborateItsPlantersCertificate` still pass. A one-test-killed-and-it-is-the
defective-fixture result is the strongest line a review can produce; get it with `go test -overlay`.
The deeper fix is that such a key must stay in `ForAsset` (so contradictions of it are still seen)
while being excluded from the `agreeing` set `mergeRule` counts.

**90. A uniqueness BACKSTOP whose unit is coarser than the decision layer's conflict unit, so the
write the database refuses was never even a conflict upstream — and the group is retried for ever
with no park, no asset and no signal.** Migration 0045's
`asset_identity_keys_one_live_per_port_uidx` is `(tenant_id, asset_id, key_type,
merge_evidence_payload -> 'port')` — one live key per (asset, type, PORT). `domain.Resolve`'s
conflict unit is the key's `Source`, `fmt.Sprintf("%d/%s", port, orDefault(protocol,"tcp"))` — per
(type, port, PROTOCOL) — and `twoValuesOnOneService` keys on `type|source` too. Measured: two
service observations at one address, port 22, protocols "tcp" and "udp" (or "tcp" and "TCP") with
different ssh fingerprints → `Resolve` returns `new_asset` with NO contest → the plain recording
loop writes both → `store: conflict: asset_identity_keys_one_live_per_port_uidx` → the whole
`resolveHost` transaction aborts → 0 assets, 0 queue items, both observations permanently
`asset_id IS NULL` and STILL returned by `ListUnresolved` on every subsequent sweep. So one payload
field buys a permanent silent detection gap for the host plus permanent occupancy of the head of
`ORDER BY observed_at LIMIT 500` — exactly the hazard `groupByAddress`'s new netip refusal was added
to prevent, reintroduced through the key path. `protocol` is unvalidated free text on the wire
(`services.protocol` is `text NOT NULL`, no CHECK, no enum); today's engines hardcode "tcp", so the
trigger is a compromised or modified scan point, which ADR-020 assumes.
**Why:** the index was written from the ADR's sentence ("one live key per asset, type, port") and
the domain from the evidence model ("a key from a second sshd on 2222 says nothing about 22"), and
nobody diffed the two units. `Retire` and `LastSeenAt` key on port alone as well, so the store side
is internally consistent — which is what makes it look right.
**How to apply:** for every new unique index, write down the tuple and then write down the tuple the
decision layer uses to detect the conflict that index backstops. If the index is coarser, the
refused write is unreachable from the decision layer and arrives as an abort. Also: normalise the
field at the parse boundary where its sibling is already normalised (lowercase + allowlist
`tcp|udp|sctp`, refuse the group otherwise, beside `groupByAddress`'s netip refusal), and make a
group whose write the store REFUSES park or count rather than retry silently for ever.

**91. Two guards whose preconditions are each other's consequence, so the pair is unbounded while
each looks bounded.** ADR-096 added a queue guard to `AssetAddresses.CloseStale` (do not age out an
address while a pending item younger than the window names the holder) and `ExpireUnplaceable`
(close a pending item once none of its candidates still HOLDS the address). Each is bounded on its
own; together the item keeps the address held and the address being held keeps the item unclosable.
Measured: `valid_from = now - 30 days`, one pending item enqueued 24 h ago naming the holder, four
ageing passes with a fresh park every "six days" → live address intervals stays 1, pending grows
1→5, `ExpireUnplaceable` closes nothing on any pass. Age every item past the window and `CloseStale`
closes the interval on pass 1 and `ExpireUnplaceable` closes all five on pass 2. So the ADR's
"bounded by freshness on both sites" is bounded by the ATTACKER STOPPING, not by a window — and for
the `twoValuesOnOneService` shape there is no classification path at all (`Resolve` returns before
continuity is measured), so the only exit is an operator verb (B39) that does not exist. Effects: a
genuine newcomer at that address is never inventoried, a live occupant's inventory freezes, and
`asset_resolution_queue` grows without bound (N items per contested host per scan, never closed) on
a table `/v1/health` scans on every poll.
**Why:** each guard was added to close a separately measured hole, in different functions, and each
one's own freshness term reads as the bound. The mutual dependency is only visible if you write the
two predicates side by side and ask who keeps each one's precondition true.
**How to apply:** whenever an expiry is conditioned on a state change, ask what prevents that state
change — and if the answer is the row being expired, the pair has no exit. A total cap
(`valid_from >= now - k*window`) or an "re-raised for k windows with no classification" escape is
the fix; the store-level probe is instant (seed the row ages by hand, call `ExpireUnplaceable` then
`CloseStale` in one `db.Write`, print live-address and pending counts per pass) and needs no sweep.

**90 (update, S42 commit 30bd17d).** The ABORT half is fixed: `keysFrom` now normalises through
`normProtocol` (absent/tcp any case → tcp; udp; sctp; else no key) and demands an exact `port` key,
so the group no longer wedges the batch. The UNIT MISMATCH is not: the sighting row is
`(tenant, identity_key_id, address, port)` with **no protocol column**, and
`SSHHostKeyFingerprintsAt` (the ADR-091 credentialed trust root, dispatch/credgrant.go:241) matches
`s.port = $3` only. So a service observation claiming `"protocol":"udp"` on port 22 lifts a key
whose Source ("22/udp") contradicts nothing the asset holds on 22/tcp — no conflict, no park, no
contest — and after two scans its sighting at (address, 22) is indistinguishable from a tcp one.
Measured on the dev DB: established ssh-only host, attacker adds a udp claim → 2 fingerprints
qualify at 22 → `trustMaterial` refuses every credentialed job there for ever (no operator verb,
B39); host with no established tcp ssh key (TLS-only, or its key is `rotation`/`lapsed` and
excluded) → the udp-claimed fingerprint is the SOLE trust root and is written into `known_hosts`
for the tcp/22 dial. `Retire(type, port)` is port-only too (measured: closed both the tcp and the
udp key in one call), which both hides the second key from the rotation audit event and creates a
laundering step — a retired `rotation`/`lapsed` key re-observed at a now-empty Source is re-recorded
with `attach` provenance, which nothing excludes.
**How to apply:** when a key's identity is a tuple, check that EVERY read that spends its trust
uses the same tuple. Here: add `protocol` to `asset_identity_key_sightings` and to the trust-root
and `Retire` predicates, or refuse a non-tcp protocol on the identity path outright until a udp
probe exists.

**92. A no-op write on a uniqueness conflict, with the readback guard in one branch and not its
sibling — a silent, permanently keyless asset.** `AssetIdentityKeys.Record`
(internal/store/identity.go:365) is `ON CONFLICT (tenant_id, key_type, key_value) WHERE valid_to IS
NULL DO NOTHING`, so recording a key another asset holds live writes nothing and no sighting. The
rotation branch (correlate.go:596-610) checks for exactly this — `LiveByValue` readback, `holder !=
assetID` is a fault that rolls the attach back — and the new-asset/attach recording loop
(correlate.go:712-737) does not. Measured: an ssh-only occupant whose address was given away by an
ADR-096 lapse returns after the contest goes stale → `Resolve` says `new_asset` (one moderate key
never merges) → `Record` no-ops → a THIRD asset with zero identity keys now holds the address, the
original asset keeps the key and no address, and every later scan attaches to the keyless asset by
address. No audit event anywhere (`Assets.Create` writes none), the two can never re-merge (a
keyless candidate has nothing to agree with), and the trust root at the address is empty for ever,
so credentialed jobs there refuse permanently. The same shape is the *designed* degradation for a
single-moderate-key host changing address (ADR-007), which is why it reads as normal.
**Why:** the ADR says "accumulates a new asset", not "accumulates an asset that can never hold its
own key", and the branch that did think about the no-op was the new one.
**How to apply:** every `DO NOTHING` is a refusal — ask who reads the fact that nothing was written.
If a caller treats "Record returned nil" as "the key is on this asset", it needs the same readback
the rotation branch has, or the verdict needs a third outcome (queue it) rather than a silent split.

**93. An operator "word" verb that names no object, so it blesses every eligible row — including
ones written after the operator looked.** `POST /v1/assets/{id}/identity/confirm` (ADR-097) carries
a `reason` and nothing else, and `AssetIdentityKeys.Confirm` (internal/store/identity_queue.go)
re-stamps EVERY live key on the asset whose provenance is `rotation` or `lapsed`, of any type, from
any service. Measured: one POST reading "I rotated the key on 22 on Tuesday" confirmed three keys —
the ssh_hostkey on 22/tcp the operator meant, an ssh_hostkey on 2222/tcp, and a `service_cert_fp`
on 443/tcp — all three `provenance='confirmed'`. ADR-096's own threat model hands an attacker who
answers a port for two scans a `rotation` key on the victim's asset, so any legitimate confirm on
that asset blesses it: two sightings later `SSHHostKeyFingerprintsAt` returns the attacker's key for
the engine's dial. The cert case also restores corroboration via `EstablishedAt`, which excludes the
same two provenances. And it is a TOCTOU even for a careful operator: a rotation recorded between
the page render and the POST is confirmed unseen.
**Why:** the verb was specified as "confirm the asset's rotated keys", and an asset is the resource
the route is keyed on, so the object of the sentence never got written down.
**How to apply:** for any verb whose whole content is a human's assertion, ask what the human SAW.
The request must carry the identifiers the page rendered (fingerprints, resolution ids) and the
store predicate must include them, refusing when the eligible set has grown since — otherwise the
audit row names an operator who never saw half of what they authorised.

**94. A guard that turns a crash into a clean refusal without adding the remedy — the dead end
survives the fix.** The identity queue's two verbs used to abort on a group carrying two different
values of one key type from one service (measured: `asset_identity_keys_interval_ordered` on
same_host, because the loop retires the row the previous iteration inserted at the same instant;
`asset_identity_keys_one_live_per_port_uidx` on different_host). The repair was a pre-flight
`twoValuesOnOneService` check returning `ErrAmbiguousGroup` → 422 "not supported yet". Correct as a
refusal — it writes nothing — but that shape is exactly the one an ATTACKER picks (answer tcp/22
with a different host key on each scan), `ExpireUnplaceable` will not close it while a candidate
still holds the address, and correlate's stale-contest close-out needs a full window with no
contradiction, which the attacker denies. So the park is permanent and the operator verb that exists
to drain it refuses by design.
**Why:** the crash is the visible defect; the missing verb is invisible because the refusal looks
like a decision.
**How to apply:** after any "we refuse this input" fix, ask what the operator does NEXT. If the
answer is nothing, the refusal moved the dead end rather than closing it — the data to decide was
usually already in the response (here every item's `resolution_id` and `key_value`).

**95. A list read whose cap is applied after the whole set is in memory.** `ResolutionQueue.
ListPending(ctx, c, 200)` has no SQL LIMIT: it selects every pending row of the tenant WITH its
copied `observed_payload`, groups in Go, then keeps 200 ADDRESSES with uncapped items each.
Measured: 24,000 items over 300 addresses → a 5,013,705-byte response in 305 ms, on a queue whose
growth is one item per parked key per scan and which drains only by human action.
**How to apply:** a `limit` parameter that never reaches the query is decoration. Check that the
bound is in the SQL and that the per-group fan-out is bounded too.

**96. An "exactly what you looked at" check that removes the granularity it was added to
protect.** The fix for #93 made `AssetIdentityKeys.Confirm` refuse unless the NAMED set equals the
asset's live rotated/lapsed set exactly (`len(want) != len(have)` → `ErrKeysChanged`). Measured:
three keys on one asset (a genuine rotation on 22, a planted rotation on 2222, a lapsed cert on
443) — naming only the genuine one returns 409 with nothing re-stamped, and the console's one
button (it sends exactly what it rendered) re-stamps ALL THREE `confirmed` in one call. So the
operator's only two moves are "bless the attacker's key too" or "leave the host without
credentialed coverage", which is the dead end the verb exists to close. Exact-set equality adds no
safety over SUBSET semantics ("re-stamp only the named keys, refuse a name that is not live"):
both refuse a key that appeared between the render and the click, only one lets the operator
refuse a member. `go test -overlay` with the cardinality check disabled left the shipped suite
GREEN (its fixture has one rotated key), so the behaviour is untested and the subset fix would not
break it.
**Why:** the review before had measured a confirm blessing keys the operator never saw, so the
repair reached for "the set must match" — the strongest-sounding check — rather than "only what
was named is written".
**How to apply:** for any bulk operator verb, ask what the operator does when they believe ONE
member of the set and not another. If the answer is "all or nothing", the attacker picks which
members are in the set.

**97. An escape hatch sized for one instance of the shape it escapes.** #94's remedy was a single
`key_value`: the operator names which of two keys on one port is the host, the other closes
`discarded`. `chooseKey` drops only items matching the chosen key's (type, source) and then
re-checks `twoValuesOnOneService(keep)` — so a group with TWO ambiguous services (two host keys on
22 AND two certs on 443, one LB address answering as two hosts) is refused by EVERY request shape.
Measured at a held address: 10 requests (both decisions × no choice × each of the four keys) all
422 with 4 items still pending; `ExpireUnplaceable` does not reach it (a candidate holds the
address live) and `CloseExpired` needs a full window with no contradiction, which the attacker
denies. Same permanent park as #94, one shape narrower, and the runbook tells the operator to use
the radio button that cannot produce an accepted request.
**How to apply:** when a scalar field is added to resolve an ambiguity, ask whether the ambiguity
can occur twice in one decision unit. The fix is a LIST (one choice per ambiguous service),
refusing only when an ambiguous unit is unnamed.

**98. A choice grammar that names the VALUE and not the SERVICE the choice is about, resolved by
first match — so the operator's correct answer is refused and the only accepted answer is the
attacker's.** #97's fix made the choice a LIST (`key_values`, one per ambiguous service) and the
listing computes `Ambiguous []AmbiguousService{KeyType, Source, Values}` over every parked item, so
the console can always render a radio per contested service. But `chooseKeys` resolves a chosen
value to an item by scanning the group in enqueued order and taking the FIRST item carrying that
value, then drops the other values of THAT item's service. A host that answers the same key on two
ports (one sshd on 22 and 2222 — or an attacker replaying the victim's public fingerprint on a
second port, which costs nothing since a host key is public) binds the choice to the uncontested
service, the contested one stays ambiguous, and the request 422s. Measured end to end: group =
genuine key on 2222, genuine key on 22, attacker key on 22; the listing offers ONE choice
(`ssh_hostkey 22/tcp [genuine, planted]`); ticking the genuine key → 422 with nothing written, no
other request the console can compose succeeds; ticking the ATTACKER's key → 200, the attacker's
fingerprint recorded `confirmed@22` on the asset that holds the address, the genuine item
`discarded`; two sightings later `SSHHostKeyFingerprintsAt` (what `dispatch.trustMaterial` reads)
returns the attacker's fingerprint at that address:22. The 422's own text ("name which one is the
host for every such service") tells the operator to retry, and the only retry that clears the park
is the wrong one. Same root cause one shape over: two ambiguous services whose value sets overlap
(the console sends the same value twice) can never be resolved as "V on both".
**The detail that makes it non-deterministic:** correlate enqueues every item of a group with ONE
`now`, so `ORDER BY enqueued_at, resolution_id` tie-breaks on a random uuid. Measured 12 identical
groups with one identical operator answer: 5 accepted, 7 refused.
**Fix measured with `go test -overlay`:** bind a choice to a service that is still CONTESTED
(prefer an item whose (type, source) carries another value) — 12/12 accepted, the shipped ADR-097
suite still green. The durable fix is to carry the service with the choice
(`{key_type, source, key_value}`), which the console already has in hand and discards when it
composes `choices`.
**How to apply:** when a decision is rendered per (service, value) and sent as a bare value, ask
how the receiver re-attaches it to the service. First-match over an attacker-influenced list is an
attacker-chosen binding. And check what the refusal message tells the operator to do next.

**99. Two canonicalisations of one value, one in SQL and one in Go, added in the same change.**
ADR-097's listing groups ambiguity in SQL by
`(payload->>'port') || '/' || lower(coalesce(nullif(payload->>'protocol',''),'tcp'))`; the verb
refuses on `sourceOf`'s Go form, `strings.ToLower(strings.TrimSpace(...))` over a decoded int port.
`lower()` without `btrim()` splits `" tcp"` from `"tcp"`: measured, two ssh keys on 22 with those
two spellings list as `ambiguous: []` (no radio rendered anywhere) while both verbs 422 demanding
a choice — a park with no console exit. `keysFrom` normalises the protocol for the key's Source but
stores the RAW payload, so the spelling survives into the queue; `correlate.normProtocol` accepts
any whitespace/case variant of "tcp".
**How to apply:** when one fact is computed twice (once in SQL for the whole set, once in Go for
the decision), diff the two expressions character by character, including `trim`, `lower`, the
default for an empty value, and the type cast.

**99 (re-measured 2026-09-12, S42 B39 rerun).** The fix was `lower(btrim(...))` plus
`jsonb_typeof(port)='number'`, which closes `" tcp"` (measured: listing now offers one
`22/tcp` entry with both values and the choice resolves it) but NOT `"\ttcp"` or `"tcp\n"`:
`btrim` strips ASCII space only, `strings.TrimSpace` strips all Unicode whitespace. Measured:
two keys on 22 spelled `"\ttcp"` and `"tcp"` list as `ambiguous: []` while `same_host` with no
choice 422s "name which one is the host" — a park with no console exit, permanent. Not reachable
from a stock scan point (both engines hardcode `"tcp"`), reachable from an altered one, which
ADR-095 put in the threat model. The durable fix is to canonicalise ONCE: store a normalised
`source` column at `Enqueue` time and have both the listing and `chooseKeys` read it.

**100. A guard evaluated AFTER a narrowing filter, when the question the operator was asked was
computed BEFORE it.** ADR-097's listing computes `Ambiguous` over every pending item at an address;
`ResolveSameHost` then calls `pendingAt(address, &assetID)`, which keeps only items naming that
asset among `candidate_asset_ids`, and runs `chooseKeys`/`twoValuesOnOneService` over the SUBSET.
Two items at one address on one port with different candidate sets — ordinary, because
`CloseStale` releases the occupant's address hold once a park is older than the window, so later
items name no candidate while earlier ones still name the occupant, and `ExpireUnplaceable` only
clears them a window later — produce: the console shows `22/tcp` ambiguous with two values and
offers the occupant as a candidate; choosing the GENUINE key → 422 `ErrKeyNotParked` (its item does
not name the asset); choosing the ATTACKER's → 200; sending NO choice → 200 and the guard never
fires at all. Measured end to end: held key retired, attacker's key recorded `confirmed`, and after
two sightings `SSHHostKeyFingerprintsAt` at that address:22 returns the attacker's fingerprint.
Same family as 98 (the only accepted answer is the attacker's) but the filter, not the grammar, is
what splits the populations.
**How to apply:** whenever a screen asks a question computed over set A and a verb enforces the
answer over set B ⊂ A, the difference is an attacker's opportunity. Check that the guard's
population is the same as the question's, and that narrowing happens only when deciding what to
WRITE, never when deciding whether to REFUSE.

**100 (re-measured 2026-09-12, S42 B39 rerun — CLOSED).** `ResolveSameHost` now reads
`pendingAt(address, nil)` for `chooseKeys`/ambiguity and narrows only the write to items naming
the asset. Measured on the exact P7 shape (genuine key naming the asset, attacker's key naming
nobody, both on 22/tcp): no choice → 422 with `SELECT key_value FROM asset_identity_keys` empty;
choosing the genuine key → 200, only it `confirmed`, the attacker's item `discarded` when it names
the asset and left `pending` when it names nobody; choosing the attacker's key → 200 (the explicit
word) with the choice in the audit detail. 99 is closed too: `"\ttcp"` and `"tcp"` on 22 now park
with ONE stored `source = '22/tcp'` (migration 0046 writes it from `keysFrom`'s `normProtocol`),
the listing offers one ambiguous entry with two values, and the choice from the listing resolves
it. Operator-typed `22/TCP`, ` ssh_hostkey`, `SSH_HostKey ` and a padded fingerprint all normalise
and are accepted; `22 / tcp` (spaces inside) is a 422 `ErrKeyNotParked`, which is fine because the
console fills the source from the listing.

**101. An address-scoped guard beside a page-scoped question: the verb blesses items the screen
never rendered, and hides the candidate that offers the safe verb.** ADR-097's `ListPending` caps
the rendering at `MaxItemsPerGroup = 50` items per address, ordered `enqueued_at DESC`, and
computes `Ambiguous` in SQL over ALL pending items (right) — but builds `QueueGroup.Candidates`
only from the rendered rows (wrong), while `ResolveSameHost`/`ResolveNewAsset` read
`pendingAt(address, …)` with NO limit and record a `confirmed` key for every keyed item there.
Measured: 61 items at one address, the attacker's key on 2222 parked first; the listing renders 50
and says "11 older items not shown"; `same_host` returns `items_closed 61`, `keys_recorded 61`, and
the unseen key is a live `confirmed` identity key of the victim's asset. Second measurement: when
the only item naming the address's real holder is the oldest, `candidates: []` — the console offers
no "Same host: merge into …" button at all, leaving only "Different host: new asset", which takes
the address (`AssetAddresses.Open` closes the holder's interval). One scan in which the attacker
answers SSH on sixty ports mints sixty items, all newer than the contest that started it. The ADR
text asserts the opposite of the code: "the refusal is decided over the whole address — every
pending item there is what the operator was shown".
**How to apply:** when a screen paginates and a verb does not, every per-address fact the decision
turns on must be a SQL aggregate over the whole address (as `Ambiguous` already is), or the verb
must refuse when `items_total` exceeds what was rendered. Ask: what does this verb write that the
operator could not have seen?

**102. A guard that reads a column nothing guarantees is populated.** The ambiguity check exists in
two places and both skip a NULL/empty service: the SQL listing filters `source IS NOT NULL` and Go's
`twoValuesOnOneService` skips `it.Source == ""`. Nothing enforces that a moderate-strength queue item
has a source: `Enqueue` writes NULL when `k.Source == ""` without complaint, migration 0046's
backfill skips any row whose `observed_payload->'port'` is not a JSON number, and there is no
NOT NULL or CHECK. The dev DB holds 13 `ssh_hostkey` rows with `source IS NULL` right now. Measured
with a production-shaped item (observation id present, so `Record` copies the payload and
`asset_identity_keys_one_live_per_port_uidx` applies): the listing shows `ambiguous: []`, no choice
is offered or required, and `same_host` 409s "That resource already exists." for ever — the address
becomes unresolvable by any verb, because the only choice grammar that could drop the NULL-source
item needs a second item on the same (empty) service. With the two keys on DIFFERENT ports the
same item is simply recorded unseen.
**How to apply:** if a guard's correctness depends on a column being populated, the column needs a
CHECK in the migration that adds it, and the writer needs to refuse rather than write NULL. A
partial-index or `IS NOT NULL` filter in the guard is a silent opt-out an attacker only has to
reach once.

**103. One verb is taught to name what the operator saw; its sibling is not, and the gap is the
render→click window.** ADR-097's `confirm` was redesigned around exactly this: the request carries
`keys` and only those are re-stamped, "a key that appears between the render and the click is simply
not named and stays where it was". `POST /v1/identity/queue/resolve` names only the ADDRESS, so both
verbs record every keyed item pending at the moment of the click. The previous round's fix (aggregate
`Keys`/`Candidates`/`Held` over every item rather than the rendered fifty) closed the pagination half
and left the time half open — and the store comment "a decision closes exactly the items it READ" is
about the verb's own transaction, not about what the screen showed. Measured: listing at an address
with `keys: []` (three keyless items); one `ssh_hostkey` item on `22/tcp` inserted; `different_host`
returns `keys_recorded: ["ssh_hostkey@22/tcp SHA256:plant10…"]`, the key is live with provenance
`confirmed` (the provenance excluded from nothing), the new asset takes the address, and two
sightings later `SSHHostKeyFingerprintsAt(addr, 22)` returns the attacker's fingerprint — the
credentialed dial's trust root, from a screen that showed no keys at all. `same_host` does the same
for a key parked on a SECOND service (a same-service late park is caught by the ambiguity guard).
The response names what was recorded; the console (`Identity.tsx` `onSuccess`) shows only
"New asset … · N items closed" and drops `keys_recorded`.
**How to apply:** when two verbs implement the same decision, diff their REQUEST shapes, not their
implementations — if one names its objects and the other names a container, the container one is
unbounded in time. Fix by carrying what was rendered (`keys_seen`, or the group's `last_seen` as
`seen_through`) and leaving anything newer pending so the address stays listed.

**104. The cap lands on the rows the screen renders and not on the aggregate the decision turns
on.** Fixing #101 moved `Keys`, `Held`, `Ambiguous` and `Candidates` into SQL aggregates over EVERY
pending item at the listed addresses — correctly — but only `Items` kept a `LIMIT`
(`MaxItemsPerGroup = 50`). The aggregates have none, and the ADR calls them "bounded by services
rather than scans" — a bound the attacker chooses. Measured: 20 000 items at one address with a
distinct (service, value) each → `keys` = 20 000, 3.2 MB for one group; all on one service instead →
one `ambiguous` entry with 20 000 values (the console renders a radio button per value); 200
addresses × 1 000 keys → **33 MB, 2.06 s, 238 MiB allocated for one GET**, versus 4.85 MB / 0.83 s at
the documented worst case (200 × 50 items, 8 KiB banners). The screen an operator needs to clear a
credentialed dead end is the screen the attacker's parks make unusable. Same shape on the asset page:
`AssetIdentityKeys.SightingsFor` has no LIMIT. And `key_value` is unbounded `text` in migrations 0007
and 0013, shipped untruncated in both `items` and `keys` (only the evidence line gets `left(…, 32)`),
so the cap belongs at `Enqueue`, not in the listing — truncating there would break the `key_choices`
round trip.
**How to apply:** after any "compute it over the whole set instead of the page" fix, ask what bounds
each newly-whole set, and whose input decides that bound. A per-group `LIMIT` plus a `*_total` count
is the same pattern the items array already uses.

**105. The decision's cap is a prefix of the set the guard claims to cover, and the attacker
chooses the order.** ADR-097 fixed #103 with `seen_through` and #104 with `MaxKeysPerGroup = 200`,
and added `MaxItemsPerDecision = 1000` so one click could not hold a 15 s write. `pendingAt` applies
that cap as `ORDER BY enqueued_at, resolution_id LIMIT 1000` — the **oldest** thousand. But the
ambiguity guard runs over that fetched slice (`chooseKeys(all, chosen)` where
`all = pendingAt(address, nil, seenThrough)`) while the listing's `ambiguous` runs over EVERY pending
item at the address in SQL. Above the cap the two disagree, in the attacker's favour, because the
attacker parks first. Measured on the dev DB: attacker key on `22/tcp` parked oldest, 1 000 filler
items on their own services, the host's own key on `22/tcp` parked newest → the screen shows
`ambiguous: [{22/tcp, [attacker, victim]}]`; the operator naming the **host's** key gets
`422 ErrKeyNotParked`; naming the **attacker's** key gets `200` and the key live with provenance
`confirmed`; sending no choice at all also gets `200` and the same result. That is verbatim the
failure ADR-097 §3 says it fixed ("a choice by value alone was measured … refusing the operator's
correct answer and accepting only the attacker's key"), reintroduced by a cap added for latency.
The same cap has a second head: `ResolveSameHost` reads **two** windows — `all` (whole address) and
`mine` (items naming the chosen asset) — each capped at 1 000 independently, so above the cap an
item can be in `mine` and not in `all`. The code reads "not in `keepAll`" as "rejected by the
operator's choice" and closes it `discarded`. Measured: 1 100 items naming nobody parked first, three
genuine items naming the asset parked later → `200`, `items_closed=3`, `keys_recorded=[]`,
`keys_discarded=` all three, zero keys on the asset, and `discarded` is in `ListUnresolved`'s
exclusion list so those observations never correlate again. The console's outcome line prints only
`keys_recorded`/`keys_retired`, so it reads "Merged into abcd1234 · 3 items closed".
**How to apply:** when a decision is capped, ask whether the cap is on the same UNIT the guard and
the screen use. A guard over a fetched page is a guard over a page. Either compute the guard in SQL
over the whole set (it is the aggregate the listing already computes), or make the decision's unit
the rendered unit — act on the items of the keys the operator saw, and refuse when
`keys_total > len(keys)` rather than silently acting on the tail. Two independently-capped reads of
the same set are never comparable; derive one from the other.
**Re-measured after the fix (same review, next round):** `MaxItemsPerDecision` was removed, both verbs
now do ONE unbounded light read of every pending item at the address and refuse with 422 when the
distinct parked keys exceed the 200 the listing renders. Measured on the dev DB: attacker key oldest
on 22/tcp + 1 000 fillers + the host's key newest → both verbs 422 with `SELECT count(*) FROM
asset_identity_keys WHERE valid_to IS NULL` = 0; the same shape with 52 distinct keys → the operator
naming the HOST's key gets 200, the host key live with provenance `confirmed`, the attacker's item
`discarded`, and every entry of `keys_recorded` is in the rendered `keys`. The 1 100-naming-nobody
shape: above the cap 422; at 153 distinct keys `same_host` records the three genuine keys, discards
nothing, and the 150 items naming nobody stay pending. The fix is the right shape — the guard, the
write and the screen now use the same unit.

**106. Each entry is capped and the number of entries is not.** Same review, same file:
`MaxKeysPerGroup` bounds `ambiguous[].values` (`array_agg(...)[1:200]`) and the keys per address, but
nothing bounds how many `ambiguous` ROWS an address has — the `GROUP BY address, key_type, source
HAVING count(DISTINCT key_value) > 1` query has no LIMIT, and `source` is a port the attacker picks.
Measured: 20 000 services × 2 values at one address → 20 000 ambiguous entries, 3.51 MiB for one
group; 200 addresses × 2 000 each → **78.57 MiB in 7.70 s for one GET** (the 200-address page still
has no paging — ADR-097 defers it to B39's second slice). And it is also an operator lockout: every
ambiguous service needs a `key_choices` entry or the verb refuses 422, and a full answer to a
20 000-entry group is 2 251 177 bytes against `MaxBodyBytes = 1 MiB` — 2.1×, so the group can never
be resolved through the API at all, which is the permanent park ADR-097 says `key_choices` exists to
prevent.
**How to apply:** a cap inside a repeated element is not a cap on the response. Count the dimensions:
rows per page, elements per row, bytes per element — and check the ANSWER a refusal demands fits the
request cap that refusal's remedy has to travel in.
**Re-measured after the fix:** the *lockout* half is closed and the *size* half is not, and the two
needed different fixes. The new `discard` verb needs no `key_choices`, and since every ambiguous
service contributes at least two distinct keys, any group needing more than ~100 choices is refused
`ErrTooManyKeys` first — so the answer a refusal demands can no longer exceed the body cap. The
listing is unchanged in kind: 20 000 ambiguous services at one address = 20 000 entries, 2.13 MiB,
346 ms (down from 3.51 MiB only because `keys` is now capped); 200 addresses × 1 000 ambiguous
services = **200 000 entries, 28.59 MiB and 228 MiB allocated for one GET in 2.8 s**, on a route any
`asset.read` caller can hit. When a fix closes one dimension, re-measure the others rather than
assuming the class is gone.

**107. The defensive skip marks the work done before the refusal.** `correlate.resolveHost` sets
`carried[k.ObservationID] = true` and THEN calls `Enqueue`; the new
`if errors.Is(err, store.ErrKeyWithoutService) { WARN; continue }` therefore leaves the observation
marked carried, so the `for _, o := range h.obs { if carried[o.ID] { continue } }` fallback — whose
comment says every observation must get an item or it "re-groups alone next sweep, finds only the
address, and attaches … through the back door" — skips it too. Measured with a `-overlay` blanking
`keysFrom`'s `source` for port 2222: the sweep completes, the WARN fires, the rest of the group parks,
and the skipped key's observation ends with **zero** queue rows and `asset_id IS NULL`, which
`ListUnresolved` re-serves next sweep. Unreachable today (`keysFrom` refuses a payload with no exact
`port`), so it is latent, not live.
**How to apply:** when a new error branch is added inside a loop that also maintains bookkeeping,
check what the bookkeeping already committed to before the branch. Set "handled" flags on the
success path only.


**108. The "no bound" sentinel is a value the request can legally carry.** ADR-097 made
`seen_through` mandatory — "a key parked between the render and the click must not be confirmed
unseen" — and the handler enforces both halves it thought it needed: `time.Parse` fails on an empty
string (400) and a value later than `now+5s` is refused (400, measured: now+6s and now+1h both
refused, now+4s accepted). What it does not check is the ZERO time. `store.pendingAt` and
`Discard` both read `if !through.IsZero() { thr = through }`, so `"0001-01-01T00:00:00Z"` — which
parses, is not in the future, and is exactly what `time.Time{}.Format(time.RFC3339Nano)` produces
from an unset field — means *no bound at all*. Measured: a key parked at T-1h and a second key
parked at T (after any render), `same_host` with `seen_through: "0001-01-01T00:00:00Z"` → 200,
**both** keys recorded live with provenance `confirmed`, both items `merged`. The console never
sends it; a CLI or an integration that forgets the field does, and gets the pre-ADR behaviour with
no signal. Fix: reject the zero value in the handler beside the future check — the field is
required, and "required" has to mean the value too, not just the key.
**How to apply:** when a store helper uses a sentinel to mean "unbounded", check whether the sentinel
is reachable from the wire. A guard that a caller disables by omission is a default, not a guard.

**109. The only remedy is one unpaged page, ordered by a key the attacker refreshes, with no
total.** `ListPending` takes the newest 200 ADDRESSES by `max(enqueued_at) DESC` and the response
carries no address count. ADR-097 defers paging to B39's second slice and says so — but the queue is
now the ONLY way to restore a host's credentialed coverage after a rotation or a contest, and the
ordering key is one the attacker refreshes every scan. Measured: 200 flood addresses parked `now` +
the victim's contest parked two hours earlier → `groups=200`, `PendingAddresses()=201`, the victim's
address **absent from the listing**, and nothing in the response says a group is missing (the only
hint is comparing Health's `contested_addresses` chip against the number of cards). A queue whose
entries can be pushed out of sight by the party the queue exists to adjudicate is a remedy the
attacker chooses. Minimum fix: an `addresses_total` beside the groups and an address filter, before
paging.
**How to apply:** for any screen that is the sole remedy for a security state, ask who decides which
rows appear on it. A LIMIT with no total and no filter is a hiding place; ordering by recency hands
the choice to whoever writes most recently.

**110. Two caps nobody multiplied.** ADR-097 fixed #106 by capping the ambiguous-service ENTRIES
per address at `MaxKeysPerGroup` (200) with `ambiguous_total` beside them — and left the VALUES per
entry capped at the same 200. Nobody multiplied the three bounds. Measured on the dev DB: one
address with 200 ambiguous services x 200 distinct values ships **40,000 values, 2.04 MiB** while
the `keys` list for the same address — the same underlying parked keys — is capped at 200; 25 such
addresses ship **50.14 MiB in 9.0 s**; the 200-address page is **~401 MiB, ~70 s**, for one GET that
needs only `asset.read`. Worse than the 28 MiB the fix was written for. The tell: the `keys` block
and the `ambiguous` block enumerate the SAME set under two different bounds (200 vs 200x200), and
every such group has `keys_total > 200`, so the server refuses every verb but `discard` — the
400 MiB of radio buttons is for a decision that cannot be taken.
**How to apply:** when a fix adds a second cap, write the product out. Cap the block, not each axis:
one budget per address for "values the operator could act on", and ship none of them for a group the
server will refuse anyway.

**111. A page-wide LIMIT shared across groups, spent in attacker-chosen order.** `ListPending`'s
held-key query is `ORDER BY host(address), ... LIMIT MaxKeysPerGroup*len(addresses)+1` — one budget
for the whole page, spent by address in TEXT order, with nothing checking the overflow the `+1`
implies. Measured: a flood address `10.95.0.1` with 500 held rows consumed **401 of 401**, and the
victim's real contest at `10.96.0.1` came back with `held: []` — the console's "Currently held on
those services ... — what *same host* retires" line simply absent, so the destructive verb is offered
with no statement of what it destroys. `?address=10.96.0.1` alone returns `held: 1`, proving the row
exists and the page lost it. This is ADR-097's own already-fixed group-level defect ("a real holder
with no same-host button") recurring at page level through a shared budget.
**How to apply:** a per-group disclosure must have a per-group budget. If one LIMIT covers several
groups, the group whose sort key an attacker chooses decides which other groups get disclosed.

**112. The create-and-take verb that records nothing.** `ResolveNewAsset` creates the asset, records
whatever it can, and opens the address on it — with no check that anything was recorded. Measured,
two shapes, both returning **200**: (a) the attacker echoes the occupant's OWN public SSH fingerprint
from a second port, so the only parked key is `keys_held_elsewhere` and nothing is recorded; (b) the
group is `ip_window`-only (keyless), which the console offers the button for. In both the new asset
ends `keys=0` holding the address live and the real occupant's interval is closed. Under this same
slice's new conjuncts (`TrustMaterial` and `EstablishedAt` both require the asset to hold the address
live) that instantly strips the occupant of credentialed trust, and the keyless newcomer can never
merge (IP alone never merges). The console prints `New asset 2280e223 - 1 item closed`;
`keys_recorded: []` is dropped because the formatter only renders non-empty parts.
**How to apply:** a verb that displaces an existing holder must refuse when its own work came to
nothing, and must refuse BEFORE the create and the address open. "Recorded zero" is not a success.

**113. The pre-check that is a prediction, not an enforcement (check-then-act under READ
COMMITTED).** #112's fix computes `recordable` — "at least one parked key of strength >= 2 has no
live holder" — BEFORE `Assets.Create`, then the record loop re-reads `LiveByValue` for each key and
may decline every one of them. `db.Write` is `pgx.TxOptions{}` = READ COMMITTED, so each statement
takes a fresh snapshot: a key free when it was counted can belong to another asset when the loop
reads it, and the loop has no post-check. Measured (overlay widening the window, then the identical
probe with the candidate fix): the verb returns **200** with `keys_recorded: []`, a keyless asset
takes the contested address, and the previous holder ends with zero live keys and no address —
exactly the state the pre-check exists to prevent. The concurrent writer is ordinary: a correlate
sweep recording the same fingerprint at another address. The fix is three lines, `if
len(res.KeysRecorded) == 0 { return res, ErrNothingToRecord }` immediately before
`AssetAddresses.Open`; rolling back the create is correct there because nothing but the create has
happened (it is not the refusal-record shape).
**How to apply:** a guard computed from a read and consumed by a later read of the same rows is a
prediction. Re-decide on the OUTCOME, at the last moment before the irreversible step. Grep for the
pattern "count N first, then loop and act" inside one `db.Write`; the two loops must share a
snapshot or the second must re-assert the conclusion.

**114. A cap and its "not everything is shown" total in different units.** `SightingsFor` is
`LIMIT 200` over the join `asset_identity_keys x asset_identity_key_sightings` — one row per (key,
sighting address) — while the `total` beside it counts live KEYS. The console guards its warning
with `total > keys.length`. Measured: 120 live keys each sighted at 3 addresses returns **200 rows
covering 67 distinct keys, `identity_keys_total: 120`, and the warning does not fire** — 53 keys,
including any `rotation`/`lapsed` key awaiting confirmation, are silently absent from the only
screen that can confirm them, under a paragraph that reads "A key past this page cannot be confirmed
here". Same root as #106/#110: the bound and the count are computed over different sets.
**How to apply:** whenever a response carries `items` + `items_total`, state the unit of each and
check the console's truncation test is `len(items) == cap`, not `total > len(items)`. A cap on a
JOIN needs a total over the JOIN.


**115. A per-key refusal applied to the first item carrying the key, while its siblings ride out on
the decision.** `ResolveSameHost`/`ResolveNewAsset` deduplicate to one item per distinct key
(`firstOfEachKey`) before the record loop, so when the loop finds a key live on ANOTHER asset it
appends only THAT item to `discarded`; the other items carrying the same key are already in
`closing` and close as `merged`/`new_asset`. Measured: three items of one held-elsewhere key →
`discarded:1, merged:2`, and the two merged rows release their observations back into the sweep —
the exact thing the discard exists to prevent ("the observation stays out of the sweep rather than
re-parking"). No trust moves; the queue just refills.
**How to apply:** when a loop runs over a DEDUPLICATED set but its refusal closes rows, the refusal
must name the whole equivalence class, not the representative. Check every `firstOf*`/`distinct`
helper feeding a branch that writes row state.

**116. A gate whose COST depends on database state runs differently where it runs — and blames
the code.** `.claude/hooks/mutate.py` runs every suite with a fixed `-timeout 120s` and reads a
non-zero exit as "BASELINE RED — the suite fails against its own subject". ADR-097's selector named
a test that drives two `correlate.SweepOnce` calls, and a sweep iterates every ACTIVE TENANT:
82.6 s against a dev database holding 14 374 of them (a number that only grows — every suite run
leaves its fixture tenant behind), versus milliseconds on CI's empty one. Green in CI, red on every
developer machine, with the message pointing at the subject. Fixed by seeding the fixture instead
of sweeping it: the same four cases now run in **1.9 s** (was 57.4 s even after the worst test was
dropped) and all four mutations are still killed. A survey of all 30 declared selectors found no
other suite above 26 s, so this was the only one exposed — measure that on a POPULATED database,
never the empty one the gate uses in CI.

**How to apply:** a `mutate:test` selector must exclude anything that sweeps, and the cost has to be
measured on a POPULATED database, not the empty one CI uses.


**117. A library contract that says the opposite of the comment resting on it.** `eraseGrantMaterial`
clears a released credential out of a `CoreMessage` on the statement after `stream.Send` returns,
and the comment justified it with "the bytes are in the transport's buffer". grpc-go's ServerStream
doc says, in as many words, "It is not safe to modify the message after calling SendMsg. Tracing
libraries and stats handlers may use the message lazily" (`google.golang.org/grpc@v1.83.1`
stream.go:1632), and SendMsg blocks only until there is flow control to SCHEDULE the message. The
erase is still right — a released secret in a decoded message for an unbounded time is what the
zeroisation rule exists to prevent — but it is a trade against a documented contract, safe only
because this server installs no StatsHandler and no interceptor.
**How to apply:** when a security control depends on "the library has finished with this object",
open the library's doc comment in the module cache and quote it. Inferred-and-true reads the same
as inferred-and-false until you look. Then check what makes it safe TODAY and write that down as
the precondition, because that is the thing a future change deletes without noticing.
