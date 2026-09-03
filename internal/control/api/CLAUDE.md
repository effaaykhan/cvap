# internal/control/api

The operator API. Design and invariants are in `internal/control/CLAUDE.md`; this file is about
**how this package is tested**, because three defects here were invisible to tests that looked
correct.

## A test of an authenticated or session-establishing endpoint uses a cookie jar

**A suite of stateless requests cannot see a binding defect.** Not "is unlikely to" — cannot.

The OIDC tests drove `/start` and `/callback` as two independent cookieless requests. That flow
is not one any browser performs, and it made login CSRF structurally invisible: the whole attack
is that a *second* browser presents a code and state it did not originate, and a harness with no
cookie jar has only ever had one browser's worth of state — namely none. A security review found
it by measuring; every test passed against the vulnerable code, and would have kept passing.

So: any test touching login, logout, session validation, CSRF, or single sign-on carries cookies
between requests the way `oidcFixture` does, and a test of a *binding* drives **two distinct
clients** — one that began the flow and one that did not. `fixture.do` takes a `[]*http.Cookie`
for this; `oidcFixture.callback` and `oidcFixture.callbackWithoutBinding` are the pair.

The rule generalises past cookies: **if the harness cannot express the attack, the test cannot
find it.** Ask what state a real client carries between requests before deciding what a test
needs to carry.

## Assert on the database, not the status code

Every response in this package is deliberately identical across failure modes — one refusal for
every way login can fail, one 404 for every cross-tenant read. That is a security property and it
is also a testing hazard: a test that checks `w.Code` is checking the part that is the same
either way.

The three defects a review found here all produced correct-looking responses. What distinguished
them was `SELECT failed_attempts`, `SELECT count(*) FROM audit_events`, and a second request. See
the refusal-durability rule in `internal/store/CLAUDE.md`.

## Security-relevant tests declare a mutation beside them

`make mutate` applies each declared mutation with `go test -overlay` — the working tree is never
modified — and requires the suite to fail. A surviving mutation names a check no case reaches.

The declaration lives in a comment block next to the tests that must kill it:

```go
// mutate:subject internal/control/api/oidc_client.go
// mutate:test    ./internal/control/api/ -run TestA|TestB
//
// mutate:case    the guard permits an address it does not recognise
// mutate:old     <one line, matching exactly once in the subject>
// mutate:new     <its replacement>
```

`mutate:subject` may be repeated and applies to the cases after it. Mutations are single-line by
construction: one that needs a paragraph is usually testing that the code compiles.

**A surviving mutation is not deleted to make the build green.** Add the case — or, if checking
shows the mutation names no load-bearing control, replace it with one that does and record why.
That happened once here: an absent mapped address claim falling back to `email` survived, and it
survived because claim-specific verification already makes such a claim unlinkable. The mutation
became "ignore the configured claim entirely", which restores the whole original bug and is
killed.

## Sabotage anything the reviewers find

Four of these mutations were first run by hand, and one of the hand runs found a test that proved
nothing: removing the translated-form extraction from the SSRF guard left the suite green,
because every case was already caught by the `2000::/3` allowlist. The fix was a case that only
extraction can catch — a translated address under a *global* prefix. That should not have
depended on remembering to try it, which is why these are declared rather than performed by hand.
