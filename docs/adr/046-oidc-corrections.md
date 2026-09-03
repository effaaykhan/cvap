# ADR-046: OIDC, restated with the SSRF guard made true and two claims corrected

**Status:** Accepted
**Date:** 2026-09-03
**Supersedes:** ADR-045

## Context

ADR-045 was committed, and an ADR-compliance pass then compared its text against the code rather
than against the index. Three of its claims were false, and one of them was false in the worst
direction: it described a control the code did not have, and the code was exploitable in six ways
because of it.

Corrected here rather than edited into ADR-045, on ADR-044's precedent: an accepted ADR is
superseded, not edited, and the rule is not suspended by the document being one commit old.

**The decisions in ADR-045 are unchanged and were right.** Identity is the subject, the client is
public, the callback can name no tenant. Only §3 and two consequence claims move, plus one thing
ADR-045 did not say at all.

## Decision

Unchanged from ADR-045 and restated so this document stands alone:

**Identity is `sub`, never email.** `users.oidc_subject` is NULL until first login; email links an
invited account to a subject ONCE, requires `email_verified`, and is a conditional
`UPDATE ... WHERE oidc_subject IS NULL`, so a second subject with the same address is refused.
Auto-provisioning is off by default and takes its role from configuration, never from a claim.

**The client is public, with PKCE, and no client secret exists anywhere.**

**The callback can name no tenant.** Both halves run behind `resolveTenant`; the state is redeemed
inside the tenant the host resolved to; `iss`, `aud` and `nonce` are checked against that tenant's
row and that attempt; state is single-use by a `DELETE ... RETURNING` whose predicate includes the
expiry; `redirect_uri` comes from `tenants.domain`; `return_to` must be a path.

## The corrections

### 1. The SSRF guard was a blocklist wearing an allowlist's comment

ADR-045 §3 said:

> The guard is an **allowlist of what may be reached** — public unicast — rather than a blocklist
> of bad ranges, for the reason this codebase keeps rediscovering: there is always one more range,
> and the one nobody listed is the one that reaches the metadata service.

The code was a `switch` enumerating bad ranges and ending in `return nil`, so an address it did not
recognise was **permitted** — the exact inverse. The compliance pass ran the real function and got
`2002:a00:1::1` (6to4 carrying 10.0.0.1), `64:ff9b::a00:1` (NAT64 carrying the same), `::a9fe:a9fe`
(the metadata address in v4-compatible form), `240.0.0.1`, `0.1.2.3` and `fec0::1` all permitted.
The accompanying test listed six ranges the switch explicitly named, asserted they were refused,
and reported that as evidence of an allowlist. **It tested the blocklist's entries.**

The replacement is two structures, deliberately different in kind, and this ADR says which is which
rather than claiming both are the same:

- **IPv6 is a genuine allowlist.** Only `2000::/3` is globally-routable unicast (RFC 4291), so
  `::/96`, `64:ff9b::/96`, `fc00::/7`, `fe80::/10`, `fec0::/10` and `ff00::/8` are all refused by
  one condition, without anyone having had to think of them. Five special-purpose ranges inside
  `2000::/3` are then refused by name.
- **IPv4 is the IANA Special-Purpose Address Registry**, which is an enumeration. That is
  defensible where "ways to spell an address" was not, and the difference is worth stating: the
  registry is finite, standardised and changes about once a decade, whereas notations are
  open-ended. Claiming it as an allowlist would be the same overclaim a second time.

### 2. The guard implemented one of ADR-039's five translation mechanisms, and cited ADR-039 while doing it

ADR-039 established that a refusal must reach a host however its address is spelled: an exclusion of
`192.0.2.5` also excludes the NAT64, 6to4, Teredo, ISATAP and v4-compatible forms. `internal/scope`
implements all five. The SSRF guard implemented Teredo, in a comment that named ADR-039.

A refusal list is exclusion-shaped, so ADR-039's rule applies to it whole. On any deployment with
DNS64/NAT64 — an ordinary IPv6-only subnet feature using the same well-known `64:ff9b::/96` prefix
`internal/scope` already recognises — `https://[64:ff9b::a00:5]/` reached `10.0.0.5` with the
private-issuer flag OFF.

**`translatedV4s` moved to `internal/target` and is used by both.** That is ADR-044's pattern
applied to the second thing that needed it: one function in the leaf package, two callers, neither
of which may import the other. Two half-implementations of one rule is the divergence that package
exists to prevent.

The 2000::/3 allowlist happens to catch most translated forms as wrappers, so the extraction is
only load-bearing for a translated address inside a *global* prefix — an ISATAP identifier under an
allocated /32, say. The test asserts exactly that case, because the first version of it did not and
stayed green when the extraction was removed.

### 3. "An identity provider being down is a 502, not a 401" was true of discovery only

The token exchange is also a request to the identity provider, and a connection failure, TLS
failure or timeout there was mapped to a 401 logged at `Info` with no issuer attribute. A provider
that went down between the redirect and the callback presented as "that sign-in could not be
completed" with nothing in the error log — the exact confusion the sentence claimed to prevent.

`exchangeCode` now distinguishes transport failure and 5xx (an outage: 502, logged at `Error` with
the issuer) from a 4xx refusal (the caller's problem: 401).

### 4. The identity key omitted the issuer, which ADR-045 stated the qualifier for and did not act on

ADR-045 said `sub` is "stable **within an issuer**" and then stored it without one, keyed
`(tenant_id, oidc_subject)`. Changing `tenant_auth_config.oidc_issuer` therefore re-pointed every
existing binding into a new issuer's subject namespace, and a colliding `sub` from the new provider
took over that account — with the once-only linking control not applying, because the row is found
by subject lookup rather than by the linking path.

Migration 0028 adds `users.oidc_issuer`, makes the unique index and the lookup
`(tenant_id, oidc_issuer, oidc_subject)`, and constrains the pair to be both-or-neither. Existing
bindings are backfilled from the tenant's configured issuer, which is the only one that could have
minted them; a binding whose issuer cannot be determined has its **subject cleared**, so that user
signs in again and re-links rather than keeping a binding into a namespace nobody checked.

Latent today because nothing writes `oidc_issuer` but a migration — which is exactly why it is
fixed now. After the tenant administration endpoints land it is a data migration against live
bindings rather than a column addition against none.

### 5. Seven things a probe found that neither ADR said

A security review measured this surface rather than reading it, which is the framing that has now
found ten defects across three sessions. Each of these is fixed, sabotage-tested, and stated here
because the ADR is where the next reader looks:

- **The login attempt was not bound to the browser that began it.** `state` gives single-use; it
  says nothing about which user agent arrived. An attacker completes their own login, holds the
  code and state, and causes the victim's browser to open the callback — measured: the victim's
  browser was issued a session for the ATTACKER's account. `SameSite=Lax` does not help, because
  the callback is a top-level GET navigation. Migration 0029 adds `browser_hash` and a
  `__Host-`-prefixed cookie set at `/start`; absent and wrong take one path, and both consume the
  attempt. **Every existing test was two cookieless requests, so the suite was structurally
  incapable of seeing it.**
- **Identity-provider response bodies were unbounded.** `exchangeCode` limits its own; discovery
  and the JWKS refresh happen inside go-oidc, which uses `io.ReadAll`, and an `*http.Client` has
  no body cap. A 256 MiB discovery document took Core's heap to 2.2 GiB from one unauthenticated
  GET — one customer's `oidc_issuer` OOM-killing the process that runs dispatch, ingest and lease
  renewal for every other tenant. The cap now lives in the `RoundTripper`, below every caller
  including ones inside a dependency.
- **`jwks_uri` was the one discovery endpoint not required to be https.** The signing keys are the
  root of every signature check; fetched in cleartext, an on-path attacker substitutes the key set
  and forges a token for any subject.
- **`email_verified` vouched for a claim it does not describe.** With the address mapped to another
  claim, the verification was still read from `email_verified` — so a token asserting a verified
  attacker address alongside the operator's in the mapped claim linked the attacker's subject to
  the operator's account. A configured claim now brings its own `_verified`, and its absence is a
  refusal rather than a fallback to the claim the operator overrode.
- **`azp` was unchecked on a multi-valued audience** (OIDC Core 3.1.3.7), so a token minted for
  another client at the same issuer — on a shared-issuer deployment, another tenant's — was
  accepted as long as ours also appeared.
- **The open-redirect guard ran on the input and `http.Redirect` rewrote the output.**
  `path.Clean` promotes a backslash into position 1, so `/./\evil.test` passed both the Go guard
  and the column CHECK and emerged as `Location: /\evil.test`. The value that is sent is now the
  value that is checked.
- **`/v1/auth/oidc/start` wrote a row per unauthenticated GET with no ceiling**, against a purge
  bounded at `BatchLimit` per sweep — and that purge sat inside the transaction carrying ADR-012's
  lease expiry, so a lock wait on a table an anonymous caller can grow stopped lease expiry for
  the tenant. The purge has its own transaction and the table has a per-tenant ceiling.

## Consequences

Everything ADR-045's consequences said still holds, except the corrected 502 claim: SaaS has a login
path, the verifier is stored in the clear for one login attempt, two tenants may share an issuer,
refresh tokens are not requested, and back-channel logout is not implemented.

**One audit event per login, naming the real method.** Not an ADR-045 claim, and found by the same
pass: `issueSession` hardcoded `{"method": "local"}` while the OIDC callback recorded its own event,
so every single-sign-on login left two rows, one claiming a local password login had succeeded — on
a SaaS tenant, where all three conditions for local auth are unsatisfiable. The three-condition gate
in migration 0026 exists to make local-auth use auditable, and it had stopped being auditable.

**A guard whose comment and whose ADR both described the opposite of the code was found by
running it, not by reading it** — and the same review, measuring rather than reading, found seven
more. Ten defects across three sessions have now come from probes rather than from review of the
text. The recurring shape is worth naming: each was a control that was present, named, commented
and wrong in a way no amount of reading the code would show, because what was wrong was a
QUANTITY — how much memory a body may consume, which browser a cookie came from, what a claim
vouches for — and quantities are measured.

**`/v1/auth/oidc/start` leaks whether a tenant uses single sign-on.** A configured tenant answers
200 where an unknown host and a local-auth tenant answer 401, which on SaaS answers "does a
customer exist at this hostname" — the question the 401/404 fix closed on `/v1/auth/login`. It is
close to inherent: an endpoint whose job is to hand back an authorization URL cannot also be
indistinguishable from one that refuses. ADR-045 claimed the property and a test asserted it while
its own comment conceded the 200. Recorded as a known leak rather than asserted away.

## Review trigger

ADR-045's, unchanged: an identity provider requiring a confidential client; several issuers per
tenant; back-channel logout. Added: a sixth address-translation mechanism, which now has two
consumers rather than one, and any future outbound fetch of an operator-supplied URL — the guard is
per-client today and a second such surface should share it rather than grow its own.
