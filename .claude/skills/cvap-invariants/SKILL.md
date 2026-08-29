---
name: cvap-invariants
description: CVAP architecture and safety invariants that must hold in every change. Use when writing or reviewing code that touches observations, assets, findings, migrations, the scan point protocol, credentials, scan scope, or rate limiting.
---

# CVAP invariants

Violating any of these is a defect regardless of whether tests pass. Sources: `docs/architecture-v2.md`, `docs/adr/`.

## Data flow

- Scan Points emit **Observations** only: immutable, timestamped, tagged with scan point and vantage zone. They never write `assets`, `services`, `software_components`, or `findings`.
- Assets, services, software components and findings are **derived** by Core from observations.
- `observation_id` is generated at the scan point and stable across retries, so duplicate submissions deduplicate.
- Correlation must be re-runnable from stored observations without re-scanning.

## Asset identity

- Merge requires one strong key, or corroborating agreement among weaker keys. Strong: agent UUID, cloud instance ID, DMI UUID, TPM/host cert fingerprint. Moderate: SSH host key, service cert fingerprint, hostname+domain+OS. Weak: MAC, NetBIOS, IP-in-window.
- IP alone never merges. MAC is weak — it is virtualised, randomised, and cloned in VM templates.
- Every merge records the observation that justified it, so merges are reversible.
- Conflicting or insufficient evidence goes to the unresolved queue. Do not guess.
- `asset_addresses` uses `valid_from` / `valid_to`. An IP is a time-bounded relationship, never a column on the asset.

## Zones and exposure

- No `zone` column on `assets`. Zone belongs to the observation.
- Exposure is computed from which vantage points can see the asset and what each sees.
- One finding with many `finding_exposure` rows. Never one finding per vantage point.

## Findings

- `rule_id` is always present. `vuln_def_id` is nullable.
- Dedup keys by source:
  - network: asset, port, protocol, rule
  - credentialed: asset, component identity, rule
  - DAST: target, normalised URL path, parameter, rule
  - API: endpoint, method, parameter, rule
  - SAST: repo, file path, **enclosing symbol**, rule — never line number
  - config: asset, setting path, rule
  - cloud: resource ARN, rule
- Normalise URLs before keying, or one vulnerable template yields thousands of findings.

## Database

- `tenant_id` on every tenant-scoped table, with an RLS policy created in the **same migration**.
- Application roles never bypass RLS. Only migration roles do.
- `observations` and `evidence` are partitioned by month from creation. Do not retrofit.
- `finding_history` is a state-change log. Never a row per finding per scan.
- Evidence over a few KB goes to object store; the row holds a summary plus `object_store_ref`.

## Scan point protocol

- Outbound only. The scan point initiates; Core never dials in.
- The broker is internal to Core. Scan points speak only to the dispatch and ingest services.
- `proto/` is additive-only within a major version. No field removal, no renumbering, no semantic change.
- Capability handshake on connect. Core never dispatches a job type or rule format the scan point cannot run.
- Result submission is idempotent by `submission_id`, chunked, and carries the lease epoch.
- Superseded epochs are rejected at ingest.

## Leases

- Assignment carries an expiry and a monotonic epoch.
- The scan point self-aborts and zeroises credentials when renewal fails. It does not continue optimistically.
- `reassign_safe` gates retry. Passive discovery retries. Active or intrusive work fails loudly and surfaces to an operator.
- Reassignment only after demonstrable expiry, with a new epoch.

## Credentials

- Delivered just-in-time with the job, scoped to that job's targets. Never a bulk sync.
- Memory only. Never written to disk on a scan point. Zeroised on completion, abort, or lease loss.
- Every release logged as a `credential_grant` and an audit event.

## Scanning safety

- Detection establishes evidence without achieving impact: boolean and timing differentials rather than data extraction, out-of-band callbacks rather than internal enumeration, benign echo rather than a shell.
- Exclusions are enforced at Core **and** again at the scan point. This duplication is deliberate.
- Rate ceilings: policies may lower the platform default, never raise it. Per scan point 1000 pps, per target 50 pps, fragile assets 10 pps.
- `fragile` is a first-class asset attribute that caps rate regardless of policy.
- Kill switch propagates within 10 seconds.

## Knowledge matching

- Distro packages match against vendor advisories (USN, RHSA, DSA, MSRC, ALAS, secdb) by distro release and package name, using `dpkg` or `rpm` comparator semantics.
- NVD CPE matching is a **fallback only**, flagged as lower confidence in the model and the UI.
- Never match an installed distro package version against an NVD upstream range. Backports make that wrong.

## Precision

- Confidence is a first-class field on observations, rules and findings, not an afterthought.
- A missed finding is a gap. A false finding loses the customer. When in doubt, lower the confidence rather than raising the severity.
