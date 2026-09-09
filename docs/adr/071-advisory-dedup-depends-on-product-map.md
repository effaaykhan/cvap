# ADR-071: The advisory-finding dedup key depends on content, and a map change re-keys it

**Status:** Accepted
**Date:** 2026-09-09

Refines ADR-070. Records a fragility of the advisory-finding dedup key that ADR-070 chose, so it
is visible before it bites rather than diagnosed after.

## Context

ADR-070's dedup key is `advisory|{asset}|{package}|{cve}`. The `{package}` in it is **not** stored
on the service or the finding — it is derived at match time from the `product_packages` map
(product → source package, ADR-064), which is **content** written by `cvap_knowledge_import`. This
was the right call for S34b: the alternative (storing a resolved package on `services`) is a
schema and pipeline change that this session's scope — "real advisory findings exist" — did not
need, and the map already existed for release resolution.

But it means a **finding's identity depends on a mapping that can change.**

## Decision

Record the consequence explicitly; do not fix it this session.

**A change to a `product_packages` entry re-keys existing advisory findings.** If the map's package
name for a product changes (an ingest correction, a renamed source package, a split), the next
sweep computes a **different `dedup_key`** for the same real vulnerability. The old finding is not
matched, so it is not updated — it stays open and stale — and a new finding opens under the new
key. One vulnerability then reads as two: a stale open one under the old package name and a fresh
one under the new. Nothing is silently dropped, but the finding set temporarily double-counts and
the lifecycle (B31, once built) cannot close the orphan because its key no longer matches anything
observed.

This is the same class as the `instance_locator` churn ADR-010 warns against ("never include
anything that churns for unrelated reasons") — except the churn source here is knowledge content,
not the scan. The mitigation, when it is needed, is to make identity independent of the map: store
the resolved package on the service (or the finding) at match time, so a later map change does not
re-key a finding already raised. That is a schema change with its own migration and is **not** done
here.

### Review trigger

The first `product_packages` correction that changes an existing product's package name for a
product that already has open advisory findings. At that point the re-key becomes observable
(duplicate findings for one vulnerability), and storing the package on the service moves from
"noted fragility" to "the fix." Until then the map is append-mostly and the exposure is latent: a
limitation that is true, harmless, and documented today, and becomes a defect the moment the map
starts churning — recorded now precisely so it is not first noticed as duplicate findings in a
customer's console.

## Consequences

- No code or schema change. The fragility is recorded, with the mitigation named and its trigger
  stated, so it is designed for rather than worked around.
- It compounds with B31 (advisory-finding remediation lifecycle): a lifecycle that closes a finding
  when its package rises above the fix still cannot close one whose key no longer matches any
  observation because the map re-keyed it. B31's design must account for the map as an identity
  input, or adopt this ADR's mitigation first.
- It is a third pointer at credentialed assessment (with B30 and B31): a credentialed read yields
  the installed package name directly from the package manager, so identity would not depend on a
  product→package guess at all. The accumulation is the signal, recorded in B31.
