---
name: credscan-hostname-dial-gap
description: cvap-credscan (ADR-075/076) hostname-target scope gap — FIXED same session by refusing KindHostname targets; kept as the pattern record
metadata:
  type: project
---

**RESOLVED (same session, before commit).** `cmd/cvap-credscan/main.go` now refuses any
target whose `canon.Kind != target.KindAddress` immediately after `Canonicalise`, before
`loadScope`/`Permits`/credential/dial — so a hostname never reaches the dial and the
resolved-IP gap below cannot be hit. The read-phase timeout minor is also fixed: `run()`
now takes ctx, size-caps output, and closes the session on `ctx.Done()`. The rest of this
note is kept as the pattern record for future scanning tools that dial.

`cmd/cvap-credscan/main.go` scope-gates with `target.Canonicalise` + `scope.Permits`
BEFORE loading the credential or dialing (main.go:78-88, dial at :126-132) — ordering
is correct and out-of-scope addresses are refused. But it then dials
`net.JoinHostPort(canon.Value, port)`.

**Latent scope gap (the documented internal/scope limitation, now made live by a dial):**
for a `KindHostname` target, `canon.Value` is the hostname and the SSH dialer resolves it
via DNS at connect. `scope.Permits` only matched the hostname by exact string equality
against an allow rule (`internal/scope/scope.go:190-192`: "a hostname rule does not cover
the address that name resolves to"). The resolved IP is never tested against the exclusion
list. If a scope file both allows a hostname and excludes an IP the name resolves to, the
credential is presented to the excluded host, and knownhosts keys on the hostname string
(not the resolved IP) so host-key verification does not save it.

**Why:** the dial capability landed; the scope package's hostname-vs-resolved-IP limitation
was harmless while nothing dialed a name. See [[latent-limitations]] pattern.

**How to apply / reachability:** NOT reachable with the committed `lab/scope.txt` — that
file is addresses/CIDRs only and its own convention is "one CIDR or address per line", and
a hostname target with no hostname allow rule fails closed (hostname never matches a CIDR
allow, `isAddr` is false). Becomes live the moment any hostname allow rule is added to a
scope file. Fix direction: refuse KindHostname targets in this tool, or resolve-then-recheck
each resolved address (both against exclusions and allows) before dialing.

Minor: `internal/credscan/ssh.go` `run()` command execution is not bound by the context/
timeout (only `dialContext` is), so a host that stalls after connect holds the one
connection open past the deadline. One host, one connection — blast radius still bounded.
