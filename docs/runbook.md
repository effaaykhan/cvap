# CVAP operator runbook

Operating a running CVAP deployment: signing operators in and cutting access off,
authorising intrusive scanning, scope discipline, enrollment tokens, the kill
switch, and what a green CI run does and does not promise.

**This documents what the system does, not what the ADRs say it should.** Where
the two differ, it is called out as a **Finding** rather than smoothed over — a
runbook that describes the intended design instead of the deployed one gets an
operator hurt during the incident it was written for. The findings are collected
in [§7](#7-findings-where-the-deployed-system-differs-from-its-docs); the plainly
named limitations are in [§8](#8-known-limitations).

For first install, see [deploy/INSTALL.md](../deploy/INSTALL.md). This picks up
from a running control plane.

---

## 1. Signing operators in, and cutting access off

CVAP authenticates operators one of two ways per tenant.

- **Local password** — for on-prem. It requires **all three** of: the Core-wide
  `CVAP_CORE_LOCAL_AUTH=1`, the tenant's `deployment_mode = 'onprem'`, and the
  tenant's `tenant_auth_config.method = 'local'`. The flag is Core-wide, not
  per-tenant, on purpose: a tenant admin must not be able to switch their own
  users to passwords and so opt out of the deployment's SSO policy.
- **Single sign-on (OIDC)** — authorization code with PKCE, no client secret.
  Identity is the `sub` claim, never email. The issuer, client id and claim
  mapping are per tenant.

### Cutting access off — the two-place caveat (ADR-046)

**Back-channel logout is not implemented.** This is the operational consequence,
and it is the thing to know when an operator leaves or a session is suspected
compromised:

> Disabling a user at the identity provider does **not** end their live CVAP
> session. The IdP is not able to tell CVAP "this person is gone," so a CVAP
> session issued before the IdP change stays valid until it expires (≤ 12 hours).

So revoking access is a **two-place** action, and neither place alone is enough:

1. **At the identity provider** — disable the account, so no *new* CVAP session
   can be obtained.
2. **In CVAP** — end the *current* session, so the existing one stops working
   now rather than at expiry.

**Finding — the CVAP half has no operator API.** There is no `/v1/users`
endpoint and no way for one operator to revoke another's session; `/v1/auth/*`
covers only the caller's own login, logout and password. Today the CVAP-side
revocation is a database action: set the user's status away from `active`
(`UPDATE users SET status = 'disabled' WHERE …`), which the very next request
honours — `Sessions.Lookup` joins `users` and requires `status = 'active'`, so a
disabled user's session stops resolving immediately. A self-service password
change *does* revoke all of that user's own sessions (that path exists); an
administrator revoking someone else's does not.

**Finding — SSO cannot be turned on or off through the API.** The `auth.read`
and `auth.write` permissions are defined but no route consumes them. Changing a
tenant's auth method (including disabling OIDC and falling back to local, or the
reverse) is a change to `tenant_auth_config`, made at bootstrap or directly in
the database, not through an endpoint.

---

## 2. Safe mode versus intrusive, and who may authorise it

A scan is **safe** unless someone explicitly escalates it, and safe is the
default at every layer (ADR-021). Intrusive is not a stronger scan of the same
kind — it is a decision somebody is authorised to take.

- **The permission is its own.** `scan.safety_mode` is separate from
  `scan.create` and `scan.cancel`. Being able to start a scan does not carry the
  authority to make it intrusive; that is a distinct grant, given to distinct
  people.
- **The policy is a ceiling.** A scan under a `safe` policy cannot be escalated;
  only a scan under an `intrusive` policy can opt in, and even then it is safe
  until it does. Escalate a running scan with
  `POST /v1/scans/{scan_id}/safety-mode`.
- **What intrusive actually does today.** The fingerprint engine has a probe
  chain that runs only under intrusive; the discovery engine is always safe (it
  has no probe corpus, so "safe mode" is not even a branch there). Intrusive
  therefore reaches real behaviour — but the fingerprint probe chain sends
  something only when a **signed fingerprint pack** is configured
  (`CVAP_SP_FINGERPRINT_PACK` + its key). Without a pack, an intrusive job falls
  back to banner reading, the same as a safe one. So "intrusive" is authorised
  and wired end to end; whether it changes what goes on the wire depends on the
  pack being present.
- **The ceilings still apply.** Rate and concurrency limits are lower-only and
  enforced regardless of safety mode, at Core and again at the scan point.

---

## 3. Scope discipline, and what the attestation enforces

A scan reaches only networks someone has **attested** they are authorised to
scan. This is a legal boundary, not a formality (execution-plan §8, risk 6).

- **The attestation is `authorization_verified`,** set per target and per zone
  range. It defaults false, and **planning refuses to decompose a target that is
  not attested** — an unattested scan produces no jobs. There is no flag that
  turns this off.
- **Two enforcement sites, and no third (ADR-024).** Scope is enforced once at
  planning time in Core (a target outside an authorised range is not planned)
  and once again in the scan-point runtime (a packet outside the job's allocated
  scope is dropped and reported). Core deciding correctly is not enough on its
  own, and the runtime is not trusted to plan; both hold.
- **The ceilings are lower-only.** A policy may lower `max_rate_pps` and
  `max_concurrent_per_target` below the platform default, never above, and Core
  re-checks them when it builds the constraints rather than trusting the stored
  value — the place that must never be wrong is the one deciding what goes on the
  wire.
- **The `lab/scope.txt` guard is for development, not deployment.** In a source
  checkout a hook blocks scanning anything outside `lab/scope.txt`. That guard
  protects developers; it does not gate a deployment, where the attestation and
  the policy ceilings are the enforcement.

---

## 4. Enrollment tokens (ADR-055, ADR-018)

A scan point joins the fleet by redeeming an enrollment token, which is a bearer
credential for a fleet identity — treat it like one.

- **Shape.** `cvapent_` prefix (identifiable on sight and greppable), 256 bits of
  entropy, single-use, TTL-bounded: 24 hours by default, 7 days maximum.
- **Issue it** either with `cvap-cli enroll-token --tenant … --zone …` on the
  Core host, or through `POST /v1/enrollment-tokens` with the `scanpoint.enroll`
  permission. Both print the token **once**; the database stores only a SHA-256
  hash, so it cannot be recovered — a lost token is reissued, not retrieved. The
  zone is chosen by the operator here and travels with the token; a scan point
  never asserts its own zone (ADR-008).
- **Handle it in a file, not an environment variable.** An env var sits in
  `/proc/<pid>/environ` for the life of the process and is inherited by every
  child, including engine subprocesses that must never see it. The scan point
  reads the token file once, redeems it, and zeroises it.
- **Issuing one is audited** (`enrollment_token.issue`, naming the token by id,
  never by value). Redeeming one produces a `scan_point.enroll` audit event on
  success; a replayed or invalid token is refused and logged but writes no audit
  row, because the refusal rolls its transaction back.

**Finding — there is no API to list or revoke tokens.** `enrollment.Issuer` has
a `Revoke` method, but no route exposes it, and there is no endpoint that lists
outstanding tokens. If a token leaks before it is redeemed, the mitigations are
its short TTL and single-use property; revoking it early today is a database
action, not an operator API call. Prefer short TTLs for this reason.

---

## 5. The kill switch, and reading acknowledgement during an incident

The kill switch is the fleet stop ADR-024 requires to be reachable in seconds.

- **Issue it** with `POST /v1/kill` (`kill.issue` permission): `scope` is
  `tenant`, `zone`, or `scan`, and `reason` is required — a fleet stop with no
  stated reason is unreviewable afterwards. Issue the **narrowest scope that
  covers the incident**: a `tenant` kill halts everything that tenant is running.
- **It propagates fast.** A scan point learns of a kill and halts within a
  10-second bound at the receiver, releases its lease, and stops sending.
- **Resolve it** with `POST /v1/kill/{kill_id}/resolve` (`kill.resolve`) once the
  incident is over; until resolved, the kill keeps halting matching work.

### Reading acknowledgement — what you can and cannot see

The system computes exactly what you would want during an incident: the set of
scan points **expected** to acknowledge the kill (derived from which are within
their heartbeat window — `HeartbeatTimeout`, 90 seconds, one shared constant that
feeds this chase set), which have acknowledged (`kill_acks`, one row per scan
point, recording how many tasks it halted), and how long each took
(`AckLatency`). "Delivered" and "acknowledged" are deliberately the same set, so
"who has not answered yet" is meaningful.

**Finding — none of that acknowledgement state is exposed through the operator
API.** `POST /v1/kill` returns the kill's id, scope, reason and timestamps, and
there is no `GET` on `/v1/kill/*`. So during an incident you can issue and
resolve a kill, but you **cannot, through the API, see whether the fleet actually
acknowledged it** — the "expected versus received acks" answer lives in the
`kill_acks` table and the online scan-point set, and reading it today means
querying the database directly. Treat a `POST /v1/kill` that returns 200 as
"issued", not as "the fleet has stopped"; confirm the stop out of band until this
surface exists.

---

## 5a. A host stopped updating, or its credentialed scans refuse: the identity queue (ADR-096, ADR-097)

Correlation parks an address when the evidence there contradicts what the asset holds — a different
SSH host key from the same service (a reimage, `ssh-keygen -A`, a reused DHCP lease, or someone
answering the port) — or when two hosts answered on one port. While an address is contested every
sighting there waits, so the host's inventory stops moving; Health's **Contested identities** chip
counts them and links to the **Identity** screen.

- **Read it** with `GET /v1/identity/queue` (`asset.read`) or the Identity screen: one card per
  address, the candidate asset, the verdict's reason (which continuity fact failed), the parked keys
  and what each service said.
- **Decide it** with `POST /v1/identity/queue/resolve` (`identity.resolve`), `reason` required:
  `same_host` with the candidate's `asset_id` when the parked key is the same machine (it retires the
  held key of that service and records the parked one; the parked observations attach on the next
  sweep); `different_host` when it is another machine (a new asset takes the address). It refuses
  (422) when it would record no key — every parked key is an echo of what another asset already
  holds, or the group is address-only — because a keyless asset holding the address can never
  merge and leaves the real holder without trust; use `same_host` on the holder, or discard. When two
  different keys answered on one port, name which one is the host for every such service
  (`key_choices`, the radio buttons on the screen, one group per port); the others close as
  discarded. `discard` closes the whole group as noise — nothing recorded, nothing trusted — and is
  the only verb offered when an address carries more parked keys than the page can show. Discarding
  a genuine host's contest loses its parked inventory for those scans and lifts the park at that
  address until the next contradiction re-parks it, like an expiry. The decision carries the
  listing's `last_seen` (`seen_through`): anything parked after you looked stays pending and the
  address comes back — reload rather than assume. The page shows the two hundred newest contests
  with the full count beside them; type an address to find one that newer parks have pushed off. Items parked
  before migration 0046 whose evidence names no port list under the service `unknown` and are all
  treated as one service: you can keep exactly one of them.
- **A rotated host refuses credentialed scans until you confirm.** The key a rotation or a lapse
  recorded is excluded from the credentialed trust root: on the asset page its chip reads *needs
  confirmation*. `POST /v1/assets/{id}/identity/confirm` (`identity.resolve`; `keys` — the rotated
  or lapsed keys you tick — and `reason` required) re-stamps those and only those; anything you do
  not tick stays excluded, and the response lists it. Trusted after two sightings at the address,
  like any key.
- **What a decision means.** Nothing here verifies that the host holds the private key — the
  fingerprint probe checks no possession (B44). A decision records that *you* said so, with your
  user id and reason in `audit_events` (`identity.resolved`, `identity.confirmed`). Confirming a
  key an attacker rotated in hands that attacker the credentialed dial; when in doubt, leave the
  host parked. (Pinning the key on the credential profile — ADR-091 §4, an `operator` line wins
  outright — is the stronger answer, but the profile has no pin writer in the API or CLI yet; B39's
  second slice.) A contest that nobody re-presents for a window expires on its own; a persistent
  one is visible until you act.

---

## 6. Reading CI: the coarse-versus-precise gate split (ADR-058)

Anyone reading a green CI run should know exactly what it promises about
performance, because it is less than it looks.

- **CI enforces the coarse ceiling only** — 2× each published latency SLO, and
  half the throughput floor. That is an order-of-magnitude bound: it catches a
  dropped index or an N+1, and it does **not** fire on the runner noise that a
  gate at the exact threshold produces. A green run means "no order-of-magnitude
  regression," not "we meet the published SLO."
- **The precise SLO runs where the machine is quiet** — the nightly job, and any
  developer running `CVAP_RUN_LOADTEST=1 make loadtest`. That is the gate that
  holds the actual §5 numbers.
- **Every measured number is printed on every run.** The gate is the alarm; the
  printed number is the gauge. Read the numbers for the trend — a value climbing
  toward the SLO is visible in CI long before it trips the coarse ceiling.
- This is the same two-halves shape as the corpus gate (labels always; the
  accuracy metrics when the lab is reachable): a split so that the half that can
  be trusted everywhere runs everywhere, and the half that needs a quiet machine
  or a live lab runs where it is meaningful.

---

## 7. Findings: where the deployed system differs from its docs

Collected from the sections above, so an operator sees them in one place:

1. **Revoking another operator's access has no API** (§1). It is a database
   action; back-channel logout from the IdP does not end a live CVAP session.
2. **SSO cannot be enabled or disabled through the API** (§1). `auth.read` /
   `auth.write` are defined but no route uses them; it is a `tenant_auth_config`
   change.
3. **Kill acknowledgement is not readable through the API** (§5). The expected-
   versus-received ack state is computed and stored but not exposed; a `POST
   /v1/kill` 200 means issued, not stopped.
4. **Enrollment tokens cannot be listed or revoked through the API** (§4). The
   code can revoke; no route does. Rely on short TTLs and single-use.
5. **Scan-point rule-pack load status is not persisted.** Scan-point health
   (`GET /v1/scan-points`) therefore cannot tell you a scan point failed to load
   its rule pack — health covers heartbeat, protocol version and capability set,
   not pack status (execution-plan §6.5).
6. **`internet_reachable` is read and displayed but never written** — see §8.

None of these is a scanning-safety gap; they are operability gaps, and each has a
database-level workaround today. They are listed so a runbook reader plans around
them rather than discovering them mid-incident.

---

## 8. Known limitations

Named plainly, because a limitation an operator does not know about is one they
will mistake for a bug or, worse, for coverage they do not have:

- **No CVE matching.** CVAP reports evidence-based findings against its own rule
  set; it does not match discovered software against a CVE database.
- **No credentialed assessment.** Every check is unauthenticated. There is no
  logging in to a target to inspect it from the inside.
- **Exposure counts are zone-derived, and `internet_reachable` is unwritten.**
  Exposure is computed per zone/vantage point, which is correct — but the
  `internet_reachable` flag on each exposure row is never set true by the
  pipeline (it defaults false and is only read). So any view that orders or
  filters by internet-reachability is, in effect, reading "false everywhere"
  today. Do not read the absence of internet-reachable exposure as "nothing is
  internet-reachable."
- **OS detection is banner-inferred, at low confidence.** Operating system is
  guessed from service banners, not confirmed; findings carry that low confidence
  rather than asserting the OS. Treat it as a hint.
- **SIGKILL loses buffered observations.** A scan point terminated with SIGKILL
  (rather than SIGTERM) loses observations it had buffered but not yet submitted.
  A clean shutdown drains them; a hard kill does not. Local durability across a
  hard kill is scheduled, not yet built (ADR-026, execution-plan §6.5). Prefer
  SIGTERM and let the scan point drain.
