# ADR-045: OIDC identity is the subject, the client is public, and the issuer is a network the deployment chooses to trust

**Status:** Accepted
**Date:** 2026-09-03

## Context

ADR-017 makes SaaS the primary deployment mode and on-prem a deployment with one tenant row.
Until this session the only login path was local passwords, gated on `deployment_mode = 'onprem'`
by three independent conditions — so the primary mode had no way for anyone to sign in at all.

ADR-041 settled how a login request names a tenant: the host does, before authentication, because
email is unique per tenant and there is no email→tenant function to build. Single sign-on inherits
that and adds an endpoint the rest of the API does not have — a **callback that a third party
redirects a browser to**, carrying values an attacker can choose.

Three decisions inside it are the ones that get reversed later by someone who does not know why.

## Decision

### 1. A returning user is identified by `sub`, never by email

`users.oidc_subject` holds the issuer's subject claim, unique per tenant, NULL until first login.
A returning user is found by it and by nothing else.

Email is the obvious key and it is the wrong one. It is mutable at the identity provider; it is
reassignable, because an employee leaves and the address is handed to their replacement; and at
many providers it is self-asserted. A login path keyed on email hands an account to whoever holds
the address this week. OpenID Connect requires `sub` to be stable within an issuer and never
reassigned, which is the property an identity needs and the one email does not have.

Email keeps exactly one job: **linking an existing invited account to a subject, once.** That is
the single moment an address identifies a person here, so it is bounded twice — the IdP must
assert `email_verified`, and the link is a conditional `UPDATE ... WHERE oidc_subject IS NULL`, so
an account already bound to a subject is never rebound. A second subject arriving with the same
verified address is refused rather than winning.

**Auto-provisioning is off by default and requires a configured role.** An IdP that can create
accounts here decides who has access; one that could also choose the role would be granting
permissions in this system. The role comes from `tenant_auth_config.oidc_default_role_id`, never
from a claim.

### 2. The client is public, with PKCE, and no client secret is stored

Authorization code with PKCE (RFC 7636, S256), no `client_secret` anywhere in the schema or the
code. A confidential client means a per-tenant secret in a table that a backup, a read replica or
one injection yields, and PKCE's protection of the code in transit does not depend on one.

The cost is stated rather than hidden: an identity provider that *requires* a confidential client
cannot be used until there is somewhere real to keep the secret. That is the same key-custody
problem ADR-026's encrypted buffer is deferred on, and it should be solved once for both.

### 3. The issuer is a network location the DEPLOYMENT decides to trust, not the tenant

`tenant_auth_config.oidc_issuer` is set by a tenant administrator, and Core then fetches discovery,
JWKS and the token endpoint from it. **That is a server-side request forgery primitive handed to a
customer.** An issuer of `https://169.254.169.254/` makes Core fetch cloud instance metadata —
credentials for the machine this deployment runs on.

So the check is at **dial time, on the resolved address**, not on the URL. Checking the hostname is
the version that does not work: an attacker controls their own DNS, so `idp.attacker.example`
resolving to a metadata address passes any name-based check, and a name that resolves differently
on the second lookup defeats a resolve-then-validate one. `net.Dialer.Control` sees the address the
connection is actually being made to, which is the only value that cannot be rebound underneath it.

The guard is an **allowlist of what may be reached** — public unicast — rather than a blocklist of
bad ranges, for the reason this codebase keeps rediscovering: there is always one more range, and
the one nobody listed is the one that reaches the metadata service.

`CVAP_CORE_OIDC_ALLOW_PRIVATE_ISSUER` permits private and loopback addresses, because an on-prem
deployment with an internal identity provider is the normal shape of on-prem rather than an
exception. **Link-local stays refused with the flag on**, and that separation is the whole point:
an operator legitimately needs `10.0.0.5`, and nobody legitimately needs `169.254.169.254`.

`CVAP_CORE_OIDC_CA_BUNDLE` supplies private roots for the same deployment. There is deliberately no
setting that disables verification.

### 4. The callback can name no tenant

Both halves of the flow run behind the same `resolveTenant` middleware as everything else, so:

- which issuer to send a browser to comes from the tenant the **host** resolved to;
- the `state` is redeemed inside that tenant's RLS scope, so a state minted at tenant A and
  replayed at tenant B is a row B cannot see;
- `iss` and `aud` are checked against **that tenant's** configuration, because the verifier is built
  from the row just read — a shared or cached client id would let a token minted for tenant A's
  client verify at tenant B, which is the cross-tenant hole the host-first chain exists to close
  reappearing at the last step;
- the `nonce` is compared against the value minted for **this** attempt. go-oidc does not check it
  and cannot, so a verifier without that comparison accepts any valid token from the issuer,
  including one obtained for a different login or a different application.

`state` is single-use, won by a `DELETE ... RETURNING` whose predicate includes the expiry — a
`SELECT` followed by a `DELETE` lets two concurrent callbacks both read the row first. Because the
expiry is in the predicate, a failed attempt does not delete rows it was not entitled to.

`redirect_uri` is built from `tenants.domain` — the value `tenant_for_domain` matched — rather than
from the Host header or a parameter. `return_to` must be a path, checked in Go and constrained
again by the column, because an absolute value makes the callback an open redirect that borrows
this deployment's hostname and its certificate.

## Alternatives considered

**Hand-rolled JWT verification.** No new dependency, and the checks needed are few. Rejected on
ADR-025's own boundary: it names cryptography on the consume side, and JWT verification is where
algorithm confusion lives — an attacker signs with HS256 using the provider's public key as the
shared secret, and a verifier that accepts both families validates it. `go-oidc` is used, and the
supported algorithms are restricted to the asymmetric families explicitly rather than relying on a
default.

**`golang.org/x/oauth2` for the token exchange.** The obvious choice, and it is already a
transitive dependency. Rejected for this one call: the exchange must go through the hardened client
because the token endpoint comes from the same operator-supplied discovery document that discovery
does, and threading a custom client through oauth2 is more indirection than a form POST.

**Match users by email and skip the subject column.** Simpler schema, no linking step, and it is
what a first implementation reaches for. Rejected above: it is an account-takeover primitive
wherever the IdP does not verify addresses, and a silent account transfer wherever an address is
reassigned.

**One setting for "reach anything on the internal network", metadata included.** Fewer knobs.
Rejected: it makes the reasonable on-prem case and the credential-theft case the same switch, so
an operator turning on the first gets the second.

**Store the PKCE verifier in an encrypted cookie instead of the database.** No server-side state,
nothing to purge. Rejected as a larger change than it looks: it needs a key to encrypt with, which
is the key-custody problem again, and the row is also where `state`, `nonce` and `return_to` live —
values that must be *comparable* server-side rather than merely returned.

## Consequences

**SaaS has a login path.** That was the gap; ADR-017's primary deployment mode was unusable.

**The verifier is stored in the clear for the life of one login attempt.** It has to be sent to the
token endpoint, so it cannot be hashed the way `state` and `nonce` are. A database read during
those minutes yields a value that, combined with an intercepted authorization code, completes an
exchange — PKCE still does what it exists for, which is protecting the code in transit through the
browser. The row is single-use, capped at ten minutes by a CHECK, and deleted on consumption.

**Two tenants may share an issuer** — a managed service provider and its customer, two subsidiaries
— which is why `users.oidc_subject` is unique per tenant and why the provider cache is keyed by
issuer while the client id never is.

**An identity provider being down is a 502, not a 401**, and the log names the issuer. A
misconfigured tenant and an outage produce different operator responses, and this is the one place
in the pre-auth surface where distinguishing them leaks nothing: the caller already knows the
hostname resolved, because they got a response about single sign-on at all.

**Refresh tokens are not requested and sessions do not follow the IdP's lifetime.** A session here
lives at most twelve hours by a CHECK constraint and ends when it ends. A user disabled at the
identity provider keeps a live CVAP session until it expires — which is a real gap, closed today
only by an administrator disabling the user here as well. Back-channel logout (`backchannel_logout_uri`)
is the mechanism that would close it properly.

## Review trigger

An identity provider that requires a confidential client, which turns the deferred key-custody
decision into a blocking one. Also: a deployment needing several issuers per tenant, which
`tenant_auth_config`'s one-row-per-tenant shape cannot express; and back-channel logout, at which
point a session's lifetime stops being purely ours.
