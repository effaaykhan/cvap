---
name: attacker-durable-attribution
description: ADR-095 made a scanned host's own claim about itself permanent — what is now bounded at Core, and the two lies that still survive
metadata:
  type: project
---

`assets.distro_family` / `distro_release` come from `/etc/os-release` on the scanned host
(`credscan.ParseOsRelease` → credhost `package` observation → `correlate.credentialedAttribution`).
Under ADR-095 an inferred sweep can never overwrite an exact read, so a wrong value is
**permanent**: nothing in the product clears the attribution columns — no API route, no store
method, no re-derive verb. The repair is another credentialed read or direct SQL (B39 owns the
operator path).

**Closed as of 2026-09-12 (re-measured, do not re-report):**
- `domain.ReleaseTokenValid` — `[a-z0-9._-]{1,64}`, applied at BOTH sites: the engine
  (`credscan.ParseOsRelease` refuses the read) and Core (`credentialedAttribution` skips the
  observation). A 64 KiB family or `<script>` release now leaves `distro_family`,
  `distro_release`, `os_confidence` and both provenances NULL, and the asset falls back to band
  voting. Two sites because a months-old or altered scan-point build is in the threat model.
- `IngestService.packageObservationsAreCredentialed` — a `package` observation is quarantined
  unless its job's `engine` is `host` AND its payload `address` equals its own task's
  `task_target` (exact string; whitespace and trailing `\n` are refused). Does not break the real
  route: `Scans.EngineForScanType("host") → EngineHost`, and the dev DB has 1,782 `scan_type
  host` jobs all carrying `engine = host`.

**Still true, and worth re-raising when a capability lands:**
- **A lie INSIDE the grammar is still permanent and still believed.** `family=ubuntu,
  release=hardy` on a jammy host pins at 1.0 and raises credentialed findings at 1.0. The ADR
  names this and defers it to B39.
- ~~`correlate.credentialedInventory` has no grammar check~~ — **closed** (2026-09-15):
  it now applies `ReleaseTokenValid` to `Release` and `Family` and skips the observation.
  But the "harmless today only because an out-of-grammar release matches no keyspace row"
  caveat **landed as a defect** in the same session: ADR-099's close-out loop turns
  "matches no keyspace row" into `status = remediated`, so a WITHIN-grammar rename
  (`VERSION_CODENAME=jammy2`) now retires every credentialed finding on the host as fixed.
  Measured 2026-09-15. Exactly the [[latent-limitations]] shape the user keeps naming: a
  documented-harmless gap that a later capability weaponises.
- **`uname -r` is a second attacker-durable attribution field** (ADR-099). It is bounded at
  both sites (`credscan.ParseUname`, `correlate.credentialedInventory` blanks an invalid token),
  but a within-grammar lie — `generic`, `9.9.9-9-generic` — makes `ClassifyKernelPackage` return
  `KernelUnknown`/`KernelInstalledNotRunning`, which suppresses every kernel finding AND (until
  fixed) closes the existing ones as `remediated`. Core's blanking of an invalid token is silent:
  no warn, no audit row, indistinguishable from a pre-ADR-099 scan point.
- `OSRelease.ReleaseKey()` is `Codename` or `ID + "-" + major(VersionID)`, so the value that
  actually becomes the attribution can be 129 bytes, not the 64 the ADR states. And
  `ParseOsRelease` bounds only three keys; the rest of `raw` is unbounded and
  `cvap-credscan` `fmt.Printf`s `PRETTY_NAME` straight to an operator's terminal.

**Why:** the input trust is pre-existing and deliberate (credentialed inventory means believing
the host); what ADR-095 added is *durability*, which turns a transient wrong value permanent.
Same shape as the user's [[latent-limitations]].

**How to apply:** whenever a value is made sticky or authoritative, ask who controls its source,
what clears it, and whether every consumer of that field applies the same bound — a grammar
enforced at one reader and not its sibling is [[recurring-findings]] class 17 (one relation named
two ways). See [[probing-the-store-and-advisory-paths]] for how to run these measurements.
