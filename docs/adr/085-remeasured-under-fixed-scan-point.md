# ADR-085: The ADR-082 measurements, re-verified under the fixed scan point

**Status:** Accepted
**Date:** 2026-09-10
**Corrects the measurement conditions of:** ADR-082 (and the figures cited in ADR-084)

Every measurement in the Session 39 sequence was taken while ADR-083's banner-capture defect was
live — the scan point could miss a service's greeting non-deterministically. ADR-082's 65%/100%
false-positive pair is the decisive evidence for the Phase 4 decision (ADR-084), so it must be a
figure taken under a scan point that works. Both hosts were re-scanned after the ADR-083 fix
(commits 4b0daff, 515c5a1). This records the corrected numbers.

## `.146` (well-maintained host) — changed in count and confidence, not in conclusion

| | before fix (broken capture) | after fix |
|---|---|---|
| votes / release confidence | 1 vote / **0.60** | 2 votes / **0.80** |
| services identified | OpenSSH only (Exim silently missed) | OpenSSH **and Exim** |
| unauthenticated findings | 16 | **20** (Exim's 4 now appear) |
| exposed-block false positives | 16 / 16 = **100%** | 20 / 20 = **100%** |

The defect had hidden a service and understated the finding count and the release confidence. The
**rate and the conclusion are unchanged**: every unauthenticated finding on this host is still a
false positive. Corrected materially in what it shows (Exim present, 0.80, 20 findings); unchanged in
what it means.

## `.138` (partly-patched host) — unchanged

`.138` reported Exim voting before the fix — it was **lucky, not correct**, because capture could
have missed it. Re-scanned under the fix, Exim votes reliably and the numbers are identical: exposed
block TP 7 / FP 13, **65% false positives**, release resolved at 0.80. The 65% figure was right; it
is now taken under a scan point that could not have missed the service.

## The figures, stated precisely so they are defensible

ADR-082 cited 65% (`.138`) and 100% (`.146`). Both are **exposed-block** rates — OpenSSH and Exim
combined. Broken out:

| host | OpenSSH alone | Exim alone | exposed block |
|---|---|---|---|
| `.138` (openssh one behind, exim GA) | 13/16 = **81%** FP | 0/4 = **0%** (GA sits below every fix — all real) | 13/20 = **65%** |
| `.146` (openssh at fix, exim one behind) | 16/16 = **100%** FP | 4/4 = **100%** FP | 20/20 = **100%** |

The direction ADR-082 records holds and is sharper broken out: OpenSSH false positives rise 81% →
100% as the host goes from one-behind to fully patched. `.138`'s Exim is 0% only because its GA
version sits below every fix, so every advisory is genuinely applicable — the absence-of-a-boundary
case, not accuracy (ADR-078).

## A keyspace-completeness caveat surfaced by `.146`'s Exim

`.146`'s Exim is `1ubuntu1.3`, one revision behind the `1ubuntu1.4` fix (USN-8590-1) — so by patch
level it *is* behind. But USN-8590-1 maps **zero CVEs** in the imported keyspace, so it produces no
credentialed-truth finding, and Exim's four unauthenticated findings are all against the CVE-bearing
USNs it is already patched against (`.1`, `.3`) — all false positives. "One revision behind" did not
mean "carries a CVE-mapped vulnerability" here. Whether USN-8590-1 genuinely has no CVEs or the
import under-mapped them is a knowledge-completeness question for the ingest, independent of the
scan-point fix; it does not change any FP figure above.

## The decision stands

ADR-084's Phase 4 decision does not move. Revision blindness (ADR-078) is independent of banner
capture (ADR-083): the false positives come from the banner lacking the Debian revision, not from
whether a banner was captured. Fixing capture changed *which services are seen* (and so the finding
count and the release confidence), not *whether a seen package is judged correctly*. The corrected
figures — 65% partly-patched, 100% well-maintained, worse the better the host — are the same
figures, now taken under a scan point that works, and remain the decisive evidence for leading Phase
4 with credentialed assessment.
