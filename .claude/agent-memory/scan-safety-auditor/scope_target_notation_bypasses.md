---
name: scope-target-notation-bypasses
description: ADR-040 classifyTarget/normaliseHost/looksLikeAddress in internal/scope — which address notations still reach hostname equality, and the SplitHostPort scheme-as-host defect. Reproduced 2026-09-03.
metadata:
  type: project
---

ADR-040 (`docs/adr/040-address-shaped-targets-must-parse.md`) added `classifyTarget`,
`normaliseHost`, `looksLikeAddress` and `quote` to `internal/scope/scope.go`, to close the
standing class recorded in [[scope-translated-form-bypasses]]: an address-shaped target that
`netip` rejects falls to case-insensitive hostname equality, where no address or CIDR exclusion
can reach it.

**Why:** it closes the notations without letters (`192.0.2.5:443`, `[192.0.2.5]`, `192.0.2.5.`,
`192.000.2.5`, `3221225989`, `0300.0.2.5`) and leaves the notations WITH letters, plus a new
normalisation defect. The class is not closed; it is narrowed.

**How to apply:** on any `internal/scope` diff, run these first. A throwaway `zz*_test.go` in
`internal/scope` that calls `classifyTarget` and `Permits` and `fmt.Printf`s the verdict proves
each in seconds; delete it before finishing (the package has no other uncommitted test files).


## FIXED after the audit, in the same session — do NOT re-report

Both Criticals and the High were closed before the change was handed back, each with cases in
`internal/scope/scopetest/cases.go` that fail against the old code.

- **The shape test was a character set.** `looksLikeAddress` now splits on `. / - ,` and asks
  whether every COMPONENT parses as an integer in some base (`ParseUint` base 0: decimal,
  0-octal, 0x-hex — the set `inet_aton` accepts). Kills `0xC0000205`, `3221225989`,
  `0xC0.0x00.0x02.0x05`, `192.0.0x2.5`, `0300.0.2.5`, `192.0.2.1-50`, `10.0.0.0-10.0.0.255`,
  `192.0.2.5,192.0.2.6`. Unicode decimal digits are folded to ASCII for the shape test only, so
  fullwidth forms refuse rather than reaching hostname equality. Bare hex is not a number to
  ParseUint, so `dead.beef` and `1host.corp.example` stay hostnames — that is what stops the
  component test over-refusing.
- **SplitHostPort accepted any port.** `validPort` requires 1-5 digits within 0-65535, so a
  malformed URL no longer normalises to its scheme. `https://printer.corp.example /x` and
  `https://%70rinter.corp.example/` are both excluded by `printer.corp.example` now.
- **Bracket stripping lost the signal.** Port splitting is tried first so `[v6]:port` survives
  intact, the inner string is trimmed, and "was bracketed" travels separately to the shape test.
- **The allow-side widening the ADR denied.** Resolved by making the rule consistent rather than
  by narrowing the code: a URL is judged on its host in BOTH directions, because scope
  authorises hosts and what is requested from one is safety_mode's question. ADR-040 now says
  so; ADR-039's translated-form asymmetry is untouched.
- Comment and ADR inaccuracies about strip ordering, the surviving-colon claim and the
  redundant `//` check are corrected.

## Still open from this audit

- **The normalised host is discarded.** Five spellings of one host pass the gate as five
  distinct target strings, so any future per-target rate or concurrency budget — and the
  `fragile` cap — divides by the number of spellings in a job. No engine implements a budget
  yet; recorded in ADR-040's Consequences for whichever session first does.
- Two known over-refusals, both loud: a literal un-percent-encoded IPv6 zone in a URL, and a
  non-address target carrying a non-port colon (a JDBC string). Covered by ADR-040's review
  trigger.

## Probes that still bypass — reported 2026-09-03, open at hand-back

The reachability model for all of these: `scopePlan` (`internal/dispatch/scope.go:53`) validates
`hostname`/`url` rule values for non-emptiness ONLY, so an allow rule can carry any of these
strings verbatim; the exclusion is written the natural way, as an address or CIDR, and misses.

1. **Letters defeat `looksLikeAddress`.** The digits/dots/slash test is byte-exact, so any
   notation containing a letter or a separator other than `.` `/` is classified as a hostname:
   `0xC0000205`, `0xC0.0x00.0x02.0x05`, `192.0.0x2.5` (glibc `inet_aton`/`getaddrinfo` resolve
   all three to 192.0.2.5), `192.0.2.1-50` and `10.0.0.0-10.0.0.255` (hyphen ranges — the way
   operators most often write scope), `192.0.2.5,192.0.2.6`, and fullwidth digits `２.０.２.５`
   (UTS-46 maps them to ASCII). Decimal and octal ARE refused, because they have no letters.

2. **`net.SplitHostPort` does not validate the port, so any malformed URL normalises to its
   SCHEME.** `normaliseHost` splits `https://printer.corp.example /x` into host `"https"`,
   port `"//printer.corp.example /x"`. Triggers whenever `url.Parse` errors or returns an empty
   Host: a space, a backslash, a percent escape in the host, `http:/host/` with one slash. The
   host-side exclusion check then tests `"https"`, and `looksLikeAddress("https")` is false so
   the refusal branch never fires. `https://%31%39%32.0.2.5/` → host `"https"`.

3. **The bracket branch defeats the shape test.** It strips `[`/`]` without re-trimming and
   without remembering the brackets were there, so `[ 192.0.2.5 ]`, `[192.0.2.5 ]`,
   `[\t192.0.2.5]` and `[0xC0000205]` reach hostname equality. Only the UNBALANCED form
   `[192.0.2.5` is refused, which is the only case the ADR's "leftover bracket" reasoning covers.

4. **Allow-side widening the ADR denies.** `addr`/`isAddr` come from the normalised host but the
   allow loop passes the ORIGINAL target, so the prefix branch short-circuits: a `cidr` allow of
   `192.0.2.0/24` now permits `https://192.0.2.5/admin` and `http://user@192.0.2.5/admin`, which
   it denied before. ADR-040 §"Exclusions reach a URL's host; allows do not" says the opposite,
   and it holds only for hostname URLs.

5. **Normalisation is decision-only.** `classifyTarget`'s canonical `host` is discarded;
   `enginehost.start` authorises and then passes `t.Value` verbatim
   (`internal/scanpoint/enginehost.go:220`). Four spellings of one host now pass the gate as four
   distinct target strings, which multiplies any per-target rate or fragile ceiling keyed on the
   string.

## Verified correct — do NOT re-report

- Userinfo does not smuggle a host: `http://192.0.2.5@evil.example/` classifies as
  `evil.example`, and the reverse `http://evil.example@192.0.2.5/` as 192.0.2.5. Fragment and
  query (`#@`, `?@`) do not either.
- `//192.0.2.5/` is refused (all digits, dots, slashes). Only the hostname form
  `//printer.corp.example/` gets through, as case 1 above.
- Both call sites already fail the whole job on any false — `refuseJob` at
  `internal/dispatch/dispatch.go:918` and `ErrOutOfScope` at `internal/scanpoint/enginehost.go:220`
  — so ADR-040's "fails the job, not the target" needs no caller change. Refusal is not
  distinguishable from denial in the return type, which so far costs nothing.
- Over-refusal is rare: no legitimate hostname shape was found that trips the test. The known
  over-refusals are `https://[fe80::1%eth0]/` (literal, un-percent-encoded zone) and any
  non-address target carrying a colon, e.g. `jdbc:mysql://...`.
- A range target (`192.0.2.0/24`) can never be permitted: any rule spelling it also parses as a
  prefix, and the prefix branch returns `isAddr && Contains`, which is false. Fail-closed.
- `strings.Contains(target, "//")` in the URL guard is redundant — `url.Parse` only sets `Host`
  when it saw an authority — but harmless.

Related: [[scope-translated-form-bypasses]], [[dispatch-scope-and-kill-gaps]],
[[lab-scope-guard-bypasses]]
