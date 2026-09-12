# ADR-095: Provenance ranks regardless of recency — an inferred attribution never overwrites an exact one

**Status:** Accepted
**Date:** 2026-09-12
**Follows:** ADR-090 (frozen), whose precedence — the exact `/etc/os-release` read outranks the
banner-inferred family and the band-vote release — was written for ordering *within one sweep*.
Nothing enforced it across time.

## What was measured

After the ADR-093 credentialed run, all three Phase 4 hosts carried release at 1.0 with
`package_manager` provenance and family at 1.0 from `os-release`. The two fingerprint sweeps ADR-094
required (the second sighting of each host key) put `.138` and `.146` back to release 0.9 from the
band vote and family 0.95 from banners. The strongest fact the system holds was overwritten by the
weakest, silently, on a schedule: every fingerprint pass undid what credentialed had established, so
more scanning made the data worse. Same shape as ADR-089's finding — a rule correct where it was
tested and unreachable where it mattered — arriving from the other direction: correct in the sweep
that read the host, absent in every sweep after it.

## Decision

**Provenance ranks regardless of recency.** `package_manager` beats a band vote whatever the
timestamps; `os-release` beats a banner hint whatever the timestamps.

1. An inferred attribution (band vote, banner) **fills an absence and never overwrites** an exact
   one. The rank is enforced in the store statements themselves — `Assets.SetAttribution` and
   `Assets.SetRelease` take an `exact` flag and, for an inferred write, leave every attribution
   column untouched when the held provenance is an exact read — so no later caller can forget it.
   The correlator passes `false` from both inferred paths and `true` from the credentialed one.
2. An exact attribution is superseded **only by another exact read**. A later credentialed pass
   that reads a different release replaces it; the test proves both directions.
3. A host that stops answering credentialed **keeps its last exact value with its age visible.**
   The exact provenance now carries `read_at` (the observation's time), and the asset page shows
   "read on the host on <date> (<age>)" in place of the vote table, saying that the value stays and
   its age grows rather than reverting to a guess. The page also no longer assumes provenance is an
   array — the exact shape is an object, and the `.148` page would have thrown on it.

Measured, through `make store-test` on the correlate, control and store suites:
`TestAnInferredSweepNeverOverwritesAnExactAttribution` — credentialed read at 1.0; a later
fingerprint sweep with a family hint and a release band leaves family, release, confidence and both
provenances untouched, and `read_at` is present; a later credentialed read with a different release
supersedes it.

4. **The release matched against is what the asset holds, not what the sweep voted.** The
   compliance review measured the first cut stopping at the column: the store refused the band
   vote, and the same transaction matched advisories against it anyway, raising a hardy-only CVE on
   a host held at jammy. `resolveHost` now reads the held release after the ranked writes and keys
   advisory matching on that — which also means an inferred sweep with no family hint, or one whose
   vote did not resolve, matches this sweep's banner versions against the exact release a
   credentialed pass established, where before it skipped matching. Stated as a behaviour change:
   findings can now be raised on a sweep that resolved no release of its own. And a finding raised
   that way is a banner claim against an exactly known release, not an exact claim: the version
   input's confidence is the service's own `version_confidence`, so the composed confidence no
   longer reads 1.0 for a banner-derived version merely because the release is exact (ADR-072/073's
   composition, with the weak input it was waiting for).
5. **The guard is self-referential, so it is race-safe.** The first cut read the rank from a
   subselect, which is evaluated against the statement snapshot and not re-read when the row lock is
   granted; an inferred write waiting behind a concurrent exact write landed on top of it and left a
   row whose release said one thing and whose provenance said "read exactly: another". The CASE now
   reads the row's own pre-update columns. And an exact write must carry the canonical object with
   the source the guard reads back (`checkExactProvenance`), so the rank a caller claims and the
   shape the guard recovers cannot disagree.

## Consequences

- ADR-064's "provenance is written even when unresolved, so the abstentions are visible" is
  narrowed: under a held exact read the band vote's abstentions are discarded, because the vote is
  not the answer and recording its reasons beside an exact one would be recording a rejected
  alternative as the basis. ADR-064's index row carries the note.

- The deploy estate's `.138` and `.146` are wrong until the next credentialed pass re-reads them;
  nothing backfills a value the system overwrote. That pass is the next credentialed run.
- The values that get pinned are target-controlled: a compromised host can report any `ID` and
  `VERSION_CODENAME`, and under this ADR no inferred sweep corrects it. Two bounds close most of
  that: the three attribution fields must be short lowercase tokens (`[a-z0-9._-]`, at most 64
  bytes, `domain.ReleaseTokenValid`), enforced at the engine when the host is read AND at Core
  when the observation is applied — a months-old or altered scan point build is why the second
  site exists, the same posture as scope enforcement; and ingest accepts a
  `package` observation only from a credentialed-engine job and only for the task's own target,
  so an enrolled scan point cannot assert an exact attribution for an arbitrary address — and a
  quarantine raised on any chunk is written to the ledger in that chunk's transaction, because the
  review measured the gate laundered by a reconnect: only chunk 0 wrote the ledger status, a later
  chunk's quarantine lived in the stream's memory, and a resume promoted the submission as
  accepted (the zone and task checks had the same hole). What
  remains — a host lying within the token grammar — needs an operator path to clear a pin and
  re-derive, which belongs with B39's surface; until then the repair is another credentialed read
  or SQL.
- `internal/credscan` now imports `internal/domain` for the token rule, so the credentialed engine
  binary links Core's pure decision package. Deliberate: one rule in one place, and `domain` is
  I/O-free; it is not a capability leak. A refusal raised mid-stream is written to the ledger even
  when the chunk is then refused as malformed (in a fresh transaction, since the malformed path
  rolls back on purpose), and the NUL-escape check reads the JSON text's escapes, not raw bytes — a
  banner containing the six printable characters `\u0000` must not void a submission.
- A version input of exactly 0.0 composes as 0.0; only an absent confidence takes the 1.0
  pass-through. The first cut folded zero into absent and promoted the weakest claim.
- The rank is a property of the *source*, not of confidence numbers: an inferred vote at 0.95 does
  not beat an exact read at 1.0, and would not beat it at 0.99 either.
- ADR-090 stands; this ADR is what it lacked across sweeps.
