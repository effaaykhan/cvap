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

**Constraint on fixes:** `proto/` is frozen additive-only within a major version (ADR-022),
enforced by `buf breaking` with the FILE category and a baseline established at bd0e4f9.
So a proto finding almost never gets fixed by removing or retyping a field. Acceptable fixes
are: a normative comment stating what the receiver MUST do, a new field at a new number, or
a wrapper type in Go. Recommend fixes in that form or they cannot be applied.
