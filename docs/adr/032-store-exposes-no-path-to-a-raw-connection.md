# ADR-032: The store package exposes no path to a raw connection

**Status:** Accepted
**Date:** 2026-09-01

## Context

ADR-002 makes tenant isolation a schema property: every tenant-scoped table has an RLS policy
of the form `tenant_id = current_setting('app.tenant_id')::uuid`, so a forgotten predicate
produces an empty result rather than a leak. Forty policies enforce that.

None of them helps against a connection carrying the wrong tenant. The policy then evaluates
perfectly, against the wrong value, and returns another customer's rows — correct-looking in
the query plan, correct-looking in the logs, and undetectable after the fact. RLS defends
against a forgotten predicate. It has nothing to say about a correct predicate with the wrong
value. `internal/store` was built so that state cannot be constructed: the tenant is set with
`SET LOCAL` inside a transaction, and `Read`/`Write` are the only ways to obtain a queryable
connection.

That design held only as long as no `*pgx.Conn` escapes the package. **Three ways it escaped
were found, all after the design was written down and believed, and none was visible at the
call site.** They are recorded here because a rule stated without them reads as paranoia, and
paranoia gets relaxed by the next person in a hurry.

- **`pgx.Rows` carries `Conn() *pgx.Conn`.** `Conn.Query` returned `pgx.Rows`, so
  `rows.Conn()` yielded the pooled connection. The signature said "result set". Found while
  fixing an unrelated error-mapping inconsistency.

- **`pgx.Batch` carries a caller-supplied callback.** `Batch.Queue` returns a
  `*pgx.QueuedQuery` with `Query(fn func(pgx.Rows) error)`; pgx stores `fn` and invokes it
  later with a live `pgx.Rows`. A caller-supplied *batch* is therefore a caller-supplied
  *callback*, and pgx hands that callback the connection. `Conn.SendBatch` accepted
  `*pgx.Batch`, so the leak arrived through a **parameter** while every return type was
  correctly narrowed. Found by `security-reviewer`, with a working exploit that read another
  tenant's rows.

- **The AST guard could not see three shapes it existed to stop:** an interface method
  returning a connection, a type alias to `pgxpool.Pool`, and a package-level `var`. It walked
  `*ast.FuncDecl` and `*ast.StructType` only. The first matters most, since the whole reason
  `store.Rows` exists is that `pgx.Rows` has a `Conn()` method — and the guard would not have
  noticed `store.Rows` growing one.

The pattern in all three: the dangerous thing was **reachable from** a type in a signature,
never named by it.

## Decision

**No exported signature in `internal/store` returns, accepts, or embeds a type from which a
pgx connection is reachable** — where "reachable" includes:

- a method on the type, including a method on an **interface** the signature names;
- a **type alias** to such a type, or a package-level **var** or **const** holding one;
- **embedding**, which promotes the embedded type's methods (this is why `Conn` holds
  `pgx.Tx` as a named field: embedding would promote `Tx.Conn()`);
- a **caller-supplied callback carried by a parameter**, which the library will invoke with
  whatever it chooses to pass.

The last clause is the generalisation the batch leak forced, and it is the one worth
remembering: **a parameter type that carries a caller-supplied function is as dangerous as a
return type that exposes a connection.**

`encapsulation_test.go` enforces this by parsing the package. It is a test rather than a
convention because every one of the three leaks above looked like a convenience in review.
Each guard has been verified to fail on the shape it targets; a guard nobody has seen fail is
not known to work.

## Alternatives considered

**Return the pgx types and document that callers must not unwrap them.** The cheapest option,
and what the package did before the leaks were found. Rejected on evidence: the leaks were not
callers ignoring documentation, they were reachability nobody had noticed, in code written by
someone who had just written the documentation.

**Put the store behind an interface and keep pgx entirely internal.** Stronger, and it would
have prevented all three. Rejected for now on cost: it means hand-rolling a query surface with
its own scanning, batching and error semantics, which is a large amount of code whose bugs
would be ours rather than pgx's. The narrowing wrappers get most of the benefit for three
small files. Worth revisiting if the wrapper set keeps growing.

**Rely on code review.** The historical failure mode ADR-002 already rejects for tenancy, for
the same reason: it works until the hotfix at 2am, and the failure is silent and unbounded.
A reviewer who has read this ADR still has to notice that a new pgx type has a `Conn()`
method, in a diff about something else.

**Vendor or fork pgx to remove the accessors.** Removes the hazard at the source. Rejected:
it makes every upgrade a merge, for a library whose upgrades carry security fixes.

## Consequences

`store.Rows`, `store.BatchResults` and `store.Batch` exist purely as narrowing wrappers. They
are not abstraction for its own sake — each one exists because a specific pgx type led back to
a connection, and each says so in its own file.

The cost lands on every future pgx surface. Adding `CopyFrom`, `LargeObjects`, listen/notify,
or anything else means checking what the new types reach and wrapping if necessary — and
adding the pgx type to the guard's forbidden list, so the next person cannot reintroduce it.
`store.Batch.Queue` discarding pgx's `*QueuedQuery` return value is the shape of that work:
one line, and the whole fix.

The guard is also now three checks rather than one, and its forbidden list must be extended by
hand. A type it does not know about is a type it cannot stop, so the list is a maintenance
obligation, not a solved problem.

## Review trigger

**Any pgx major version bump**, and any minor bump that adds methods. A new method on an
existing type reopens this silently: nothing in this repository would change, no signature
would move, and the guard's list would still contain exactly the entries it contains today.
Re-audit `pgx.Rows`, `pgx.Row`, `pgx.BatchResults`, `pgx.Batch`, `pgx.QueuedQuery`, `pgx.Tx`
and `pgconn.CommandTag` for new accessors at that point.

Also revisit if the wrapper set grows past a handful of types, which would mean the rejected
"full interface" alternative has become the cheaper one.
