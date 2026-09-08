# rpmvercmp.at — RPM's own version-comparison test corpus

- **Upstream:** rpm-software-management/rpm
- **File:** tests/rpmvercmp.at
- **Commit:** 5dae33c3d0c51c97d5834fe2ecf768b6f5483b81
- **Fetched:** 2026-09-08
- **Why vendored:** this is rpm's OWN test suite for `rpmvercmp`, derived from
  the implementation we validate against — not a re-transcription of our own
  understanding, which would validate nothing (the reasoning behind ADR-062).

## Refresh
    curl -sS -o rpmvercmp.at \
      https://raw.githubusercontent.com/rpm-software-management/rpm/master/tests/rpmvercmp.at
    # then record the new commit:
    gh api "repos/rpm-software-management/rpm/commits?path=tests/rpmvercmp.at&per_page=1" -q '.[0].sha'

Parsed by corpora_test.go (the `RPMVERCMP(a, b, expected)` macros). A parse that
finds zero cases fails the test — a corpus that silently stopped being read is
worse than none.
