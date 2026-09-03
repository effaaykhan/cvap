---
name: scope-translated-form-bypasses
description: ADR-039 translated-address handling in internal/scope — the /128 rule-side gap, the cross-form gap, untrimmed rules, and what was verified correct. Reproduced 2026-09-03.
metadata:
  type: project
---

ADR-039 (`docs/adr/039-translated-addresses-expand-exclusions-only.md`) made NAT64/6to4/
Teredo/v4-compatible forms EXPAND exclusions and NOT expand allows. `internal/scope/scope.go`
gained `translatedV4` and `matchesExclusion`.

**Why:** the previous audit recorded "NAT64 and 6to4 notation of an excluded v4 walks past the
exclusion" as open. This change closes the direction that matters most and opens three narrower
ones in its place.

**How to apply:** on any `internal/scope` diff, re-run these four probes before anything else.
A throwaway `zz*_test.go` in `internal/scope` that calls `scope.Permits` and `t.Logf`s the
verdict proves each in seconds; delete it after.

## FIXED after the audit, in the same session — do NOT re-report

All four were closed before the change was handed back, each with a case in
`internal/scope/scopetest/cases.go` that fails against the old code. The detail below is kept
because it records what the failures looked like, not because they are live.

- **Prefix-form translated exclusion expanded nothing.** `parseRuleAddr` now accepts the
  host-prefix spelling on the rule side, mirroring `parseTargetAddr` on the target side. This
  was the sharp one: `cidr`-typed rules are validated with `ParsePrefix`, which rejects the
  bare address, so `/128` was the only spelling that reached the wire and it expanded nothing.
- **One translated form missed the same host in another.** `matchesExclusion` compares the
  rule's embedded address against the target's embedded addresses as well as against the
  target itself, so NAT64/6to4/Teredo/ISATAP/v4-compatible all cover each other.
- **Untrimmed rules.** `matches` trims once at the top rather than in the hostname branch
  alone, so an exclusion stored with surrounding whitespace still excludes.
- **Zone stripped on one side only.** Stripped on the rule side too, so `fe80::1%eth0` as a
  rule covers `fe80::1` as a target.
- **ISATAP added.** RFC 5214's fixed `0000:5efe` / `0200:5efe` interface-identifier marker,
  recognised under any prefix. ADR-039 now states why this is a different judgement from
  RFC 6052 §2.2 and RFC 8215: those need a guessed offset and ISATAP does not.
- **`translatedV4s` returns every candidate** rather than the first match, so an ISATAP
  identifier inside a prefix-based range cannot have one interpretation silently discarded.
- **Bare prefixes yield nothing.** 0.0.0.0 and 255.255.255.255 are filtered for every
  mechanism, not just `::/96`, so the earlier inconsistency is gone.

## Original findings, for the record (reported 2026-09-03)

1. **A prefix-form translated exclusion expands nothing.** `matchesExclusion` reaches the
   rule-side expansion only through `netip.ParseAddr(rule)`, which fails on any string with a
   `/`. So `64:ff9b::192.0.2.5/128` as a deny does NOT cover `192.0.2.5`, while the bare
   `64:ff9b::192.0.2.5` does. Worse in combination: `scopePlan` (`internal/dispatch/scope.go`)
   validates `cidr`-typed rules with `ParsePrefix`, which REJECTS the bare-address spelling and
   fails the whole job — so through the `cidr` match type, the only expressible spelling of a
   single translated host is the one that does not expand. The target side already normalises
   `x/128` to an address in `parseTargetAddr`; the rule side does not.

2. **Cross-form gap.** The rule-side branch compares the rule's embedded v4 against the target
   ADDRESS (`v4 == addr`), never against the target's embedded v4. A deny of
   `64:ff9b::192.0.2.5` therefore misses targets `2002:c000:0205::1`, `::192.0.2.5` and the
   Teredo form of the same host. ADR-039 claims the exclusion covers the host "by either name";
   the code covers exactly two of the five names.

3. **Rules are not trimmed before parsing.** `matches` calls `TrimSpace` only in its hostname
   branch, and the new rule-side branch not at all. `scopePlan` puts `MatchValue` on the wire
   verbatim and only trims `hostname`/`url` values when checking for emptiness, so
   `" 64:ff9b::192.0.2.5 "` survives planning and expands nothing.

4. **ISATAP (RFC 5214) is a fifth mechanism the ADR does not mention.** `fe80::5efe:v4` and
   `2001:db8::200:5efe:v4` reach a v4 host and are not recognised. Unlike the network-specific
   NAT64 prefixes the ADR declines to guess at, ISATAP needs no guessing: fixed marker
   `0000:5efe`/`0200:5efe` at bytes 8-11, v4 always in the low 32 bits. RFC 8215's
   `64:ff9b:1::/48` is likewise unmentioned.

## Verified correct — do NOT re-report

- All four extractions are right: NAT64 low 32 bits, 6to4 bytes 2-5 (whole `2002:V4::/48`, not
  just `::1`), Teredo bytes 12-15 one's-complemented (`2001:0:4136:e378:8000:63bf:3fff:fdfa`
  → 192.0.2.5), v4-compatible low 32 bits.
- A translated PREFIX rule does not expand: `64:ff9b::/96`, `2002::/16`, `2001::/32` and
  `::/96` as denies do NOT deny v4 hosts. This is the half that would have denied the internet.
- The allow side cannot be widened by any route found: `Permits` calls `matches` (not
  `matchesExclusion`) for allows; a v4 allow never authorises a translated target and a v6
  allow never authorises the v4 host. `::ffff:0:0/96` as an allow becomes `0.0.0.0/0`, which is
  semantically the same set, not a widening.
- Zones, mixed case, leading-zero hextets, hex-tail spellings and `/128` prefix-form TARGETS
  all normalise before the check (`parseTargetAddr`). The zone bypass and the trailing-dot FQDN
  bypass recorded in [[dispatch-scope-and-kill-gaps]] are both closed.
- `::/96` guards `::` and `::1`. `2002::`/`64:ff9b::` extract 0.0.0.0 and `2001::` extracts
  255.255.255.255 with no equivalent guard, but all three over-match, which is fail-closed.

## Standing class, wider than this diff

An IP-shaped target string that `netip` REJECTS falls to `matches`'s case-insensitive string
equality, where no IP exclusion can reach it. `192.0.2.5:443`, `[192.0.2.5]`, `192.0.2.5.` and
`64:ff9b::192.000.2.5` all get past denies of `192.0.2.5` and `192.0.2.0/24` when a
`hostname`- or `url`-typed allow rule carries the identical string. `MatchURL` is an accepted
match type in `scopePlan`, so this is reachable through supported configuration.

Related: [[dispatch-scope-and-kill-gaps]], [[scanpoint-runtime-bypasses]],
[[lab-scope-guard-bypasses]]
