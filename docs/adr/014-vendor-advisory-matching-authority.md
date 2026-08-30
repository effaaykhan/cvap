# ADR-014: Vendor advisories are authority for packages; CPE is flagged fallback

**Status:** Accepted
**Date:** 2026-08-30

## Context

Scan an Ubuntu 20.04 host and find `openssl 1.1.1f-1ubuntu2.16`. NVD says CVE-2022-0778
affects OpenSSL 1.1.1 through 1.1.1n, so naive comparison reports the host vulnerable. It is
not: Ubuntu backported the fix into the package revision while leaving the upstream version
at 1.1.1f. Every enterprise distribution does this for every package. Match on upstream
versions alone and credentialed Linux scanning produces false positives at a rate that makes
the feature unusable — the customer's Linux team stops trusting the tool permanently after
the first report.

## Decision

For any component installed by a distribution package manager, the **vendor advisory is the
matching authority**: match by distro release and package name against
`ADVISORY_FIXED_PACKAGE`, and compare versions with the correct comparator — `dpkg`
semantics with epochs and tildes, or RPM's `rpmvercmp` — each implemented precisely and unit
tested against the distributions' own public test corpora. Ingest USN/OVAL, RHSA and Red Hat
security data, DSA and the Debian security tracker, SUSE SU, Alpine secdb, Amazon ALAS and
Microsoft MSRC CVRF as authorities. CPE matching against NVD ranges is a **fallback for
non-package software only**, backed by a curated fingerprint-to-CPE mapping layer with
attached confidence, and findings derived from it are flagged as lower confidence in the UI.

## Alternatives considered

**NVD CPE ranges as the primary mechanism.** One feed, one matcher, immediate coverage of
everything. Rejected: it is wrong for every backported package, the CPE dictionary is
incomplete, vendor and product strings are inconsistent across entries for the same software,
and NVD's version range expressions are frequently overly broad.

**Lexicographic or semver comparison of package versions.** Rejected: both dpkg and rpm
version ordering are non-lexicographic and mutually incompatible. Getting this subtly wrong
produces silent false negatives, which are worse than false positives because nobody reports
them.

**Advisories only, with no CPE path at all.** Rejected because it leaves non-package software
— appliances, bundled runtimes, anything fingerprinted from a banner — entirely undetected.
The fallback is unreliable, so it is labelled unreliable rather than omitted.

**Shelling out to the distribution's own comparison tools.** Rejected: it cannot compare an
RHEL version from a Debian-based Core host, so the comparator must be ours in any case, and
it would make matching correctness depend on which packages happen to be installed on the
machine running Core.

## Consequences

Credentialed Linux findings become near-correct, which is what makes Phase 4 the first
high-precision output and gives Phase 6 a ground truth to calibrate unauthenticated rules
against. Detection confidence becomes a real, honestly-populated field feeding the risk
engine. The costs are substantial and ongoing: one ingestion pipeline per vendor, each with
its own format and its own breakage, plus two version comparators that must be exactly right
and are tested against external corpora.

## Review trigger

Revisit per source when a distribution changes its advisory format or publishes a new
authoritative feed, and revisit the CPE fallback's confidence weighting if measured false
positive rate from CPE-derived findings exceeds what the UI's flagging can excuse.
