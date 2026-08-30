---
name: contract-only-review-posture
description: How CVAP wants contract-only commits (proto, schemas, ADRs) reviewed — "does it force the secure implementation", not "is it exploitable today"
metadata:
  type: project
---

Contract-only commits in CVAP (proto definitions, migrations, ADRs) are reviewed against
"does this force, permit, or forbid the secure implementation", not "is this exploitable
now". A field that admits an insecure implementation is a finding in its own right, ranked
as if the insecure implementation had shipped.

**Why:** CVAP is written mostly by an AI with one human reviewer, and both sides of the scan
point protocol will be built later against whatever the contract says. Under ADR-022 the
contract is frozen additive-only, so a shape that invites a mistake cannot be corrected
later without a major version.

**How to apply:** for each field, name the implementation an ordinary competent engineer
would write against that comment, and check whether it is secure. Normative comments
("Core MUST derive identity from the TLS peer certificate") count as part of the contract
and their absence counts as a defect. Related: [[recurring-findings]].

Distinguish real defects from hardening in the write-up — the human reviewer triages by
that split.
