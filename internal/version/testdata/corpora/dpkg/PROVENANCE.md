# Dpkg_Version.t — dpkg's own version-comparison test corpus

- **Upstream:** guillemj/dpkg (the dpkg maintainer's GitHub mirror; the canonical
  home is salsa.debian.org/dpkg-team/dpkg, which is unreachable from this build's
  network — only GitHub egress is available)
- **File:** scripts/t/Dpkg_Version.t
- **Commit:** f4941036b04e787c2803d6359802d6725d2476c6
- **Fetched:** 2026-09-08
- **Why vendored:** dpkg's OWN test suite, whose `__DATA__` block cross-checks
  `Dpkg::Version` against the `dpkg --compare-versions` binary itself. Independent
  of our comparator's understanding (ADR-062).

## Refresh
    curl -sS -o Dpkg_Version.t \
      https://raw.githubusercontent.com/guillemj/dpkg/main/scripts/t/Dpkg_Version.t
    gh api "repos/guillemj/dpkg/commits?path=scripts/t/Dpkg_Version.t&per_page=1" -q '.[0].sha'

Parsed by corpora_test.go (the `a b result` triples after `__DATA__`). A parse
finding zero cases fails.
