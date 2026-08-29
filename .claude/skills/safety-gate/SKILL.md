---
name: safety-gate
description: Run the full scope-enforcement and scanner-safety suite before merge.
disable-model-invocation: true
allowed-tools: Bash(make safety) Bash(make corpus-check) Bash(make lint)
---

# Safety gate

This gates merge. A failure here means the scanner could touch something it was not
authorised to touch, which is a legal problem rather than a bug.

## Run

```!
make safety
```

## Then

1. If anything failed, report the failing case and stop. Do not propose a workaround
   that narrows the test.
2. If it passed, run `make corpus-check` and report false positive and false negative
   rates against the gates: FP ≤ 2%, FN ≤ 5%, host discovery recall ≥ 99%.
3. Delegate to `scan-safety-auditor` for the diff if this run covers a change to any
   packet-sending path.

## What the suite covers

Scans run in a network namespace with capture on egress, asserting that no packet leaves
toward an address outside the configured scope. Cases include exclusion overlapping an
allow, CIDR boundary arithmetic, a hostname resolving out of scope, a redirect to an
out-of-scope host, IPv6 forms of excluded v4 addresses, and scope changed mid-scan.

Never adjust the assertions to make a run pass.
