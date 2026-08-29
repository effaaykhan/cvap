---
name: write-detection-rule
description: Procedure for authoring a CVAP detection rule with correct evidence, confidence, and dedup semantics. Use when adding or changing a rule in the rule pack.
paths:
  - internal/engines/rules/**
  - rules/**
---

# Authoring a detection rule

## Decide where it runs first

`execution_site` is `scan_point` or `core`, and the choice is not stylistic.

- **scan_point** when the verdict is request-coupled — it depends on an interaction that
  cannot be reconstructed from stored evidence. Timing inference, handshake behaviour,
  active probe and response pairs.
- **core** when the verdict is evidence-based — the scan point reports what it saw and
  Core decides what it means. Versions, package inventories, config values, banners,
  certificate contents.

Default to `core`. It means the rule can be corrected later and retroactively fix
historical findings, and it avoids a fleet-wide rule distribution problem.

## Required fields

```
rule_id, name, category, engine, execution_site,
default_severity, base_confidence, cwe,
detection_logic, evidence_requirements, remediation_template, version
```

## Evidence requirements

State what must be captured for a human to verify the finding by hand without re-scanning.
A rule whose evidence does not let an analyst confirm it themselves will be disputed by the
customer's team and you will lose the argument.

## Confidence

- Advisory-matched package version: high.
- Direct observation of the condition (expired certificate, protocol negotiated): high.
- Banner-derived version inference: medium at best.
- CPE fallback match: low, and flagged as such in the UI.

Lower the confidence rather than raising the severity when unsure. A false finding costs
more than a missed one.

## Dedup key

Compute from the source type, per `/cvap-invariants`. For network rules that is
`(asset, port, protocol, rule)`. Never include anything that churns for unrelated reasons.

## Impact boundary

The rule establishes evidence without achieving impact. If the detection requires
extracting data, spawning a process, writing to the target, or enumerating internal
services, redesign it. Boolean and timing differentials, out-of-band callbacks, and
benign nonce echoes are the correct shapes.

## Before finishing

Add the rule to the golden corpus with a labelled expected result, and run
`make corpus-check`. A rule with no corpus entry is not measurable and does not ship.
