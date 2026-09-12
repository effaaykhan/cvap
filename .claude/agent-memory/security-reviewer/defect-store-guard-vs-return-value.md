---
name: defect-store-guard-vs-return-value
description: Recurring CVAP defect shape — a store statement refuses a write, but the caller returns the refused value and downstream code in the same transaction acts on it
metadata:
  type: project
---

When a store method gains a rank/precedence guard in SQL ("this write only lands if …"),
check every caller's **return value** and everything downstream of it in the same
transaction. The guard makes the database right and leaves the process wrong.

**Why:** measured in the ADR-095 review (2026-09-12). `Assets.SetRelease(exact=false)`
correctly refused to overwrite an exact `/etc/os-release` read, but
`correlate.deriveRelease` still returned the band-voted release and `resolveHost` handed
it to `evaluateAdvisories` — an asset held at `intrepid` at 1.0 while the same sweep
raised a CVE built from `hardy`'s keyspace at 0.8. Fixed in-session by `Assets.ReleaseOf`
(read the held row back and match against that). Same family as the user's
[[control-at-the-wrong-layer]]: a control that is correct but sited where it does not
answer the question asked.

**Second-order check once the readback lands:** a value that is now authoritative changes
what every derived number means. Measured after the fix — a banner-derived advisory
finding (`source: network`) renders at **confidence 1.0** on an ordinary fingerprint
sweep, because the held release is exact and ADR-073's other two inputs are 1.0
pass-throughs. Pre-change that only happened inside the credentialed sweep. So: after
making something sticky, ask what confidence/severity composition now reads it.

**How to apply:** for any conditional `UPDATE`, ask "who consumes the value the caller
*intended* to write?" Then ask "what else reads the value that is now sticky?" Assert on
the downstream artefact (the finding, its confidence), not on the column the ADR names —
the column will be right and the finding will not. See
[[probing-the-store-and-advisory-paths]] for how to make the advisory path actually run.
