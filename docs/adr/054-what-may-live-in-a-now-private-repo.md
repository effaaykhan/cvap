# ADR-054: What may live in the repo, now that it is private

**Status:** Accepted
**Date:** 2026-09-05

## Context

The repository changed visibility from public to private. The reasoning that drove some of
what is (and is not) committed was never written down: it came out of a chat exchange around
session 4 and was acted on rather than recorded. That absence is itself the thing worth noting
— the repo's content was shaped by a disclosure model that lives nowhere in the tree, so a
later contributor cannot tell which choices were about an unknown public reader and which are
independent of who can read a clone. This ADR records the decision now, and re-decides it for
private status rather than restating the public-era rule.

## Decision

There are **two** categories, and they must be kept apart rather than collapsed into one "don't
commit sensitive things" rule, because private status moves one of them and not the other:

- **Public-repo hygiene, which private status relaxes.** Concerns that were purely about
  disclosure to an unknown reader — someone who could clone the repo precisely because they were
  not known or trusted. Once the reader set is "people the project deliberately granted access",
  a concern in this category has lost the threat it was defending against.

- **Good practice regardless.** Things that must not be in version control whether the repo is
  public or private — real credentials, customer data, private keys, anything whose exposure is
  bad because of *what it is* and would remain bad if the only readers were the current team.
  Private status does nothing to this category, because the harm is not "an unknown reader saw
  it" but "it is in a clone at all, forever, for everyone who ever had access".

Two things that prompted the original exchange are sorted into these categories, with the
reasoning, because the answer differs:

- **`lab/scope.txt` naming ranges → discipline (good practice regardless), keep it.** A scan
  scope committed to git is a record of what was authorised to be scanned, and that record is
  worth having independent of who reads the repo — it is the artifact `make safety` and the
  lab-scope-guard hook check against. It was never a disclosure problem: it lists loopback,
  the RFC-1918 lab segments, and the RFC-5737 documentation ranges, none of which is routable
  or names a real external target. Private status changes nothing here; it would stay committed
  in a public repo too.

- **Detection-rule coverage → disclosure (public-repo hygiene), relaxed.** What the rule set
  can and cannot detect told an unknown reader precisely what the scanner is blind to — a map
  of the gaps, useful to someone deciding what to hide from it. That concern was about the
  unknown reader, so private status relaxes it: the coverage can be as explicit in the tree as
  is useful to the team, because the readers are now the team.

## Alternatives considered

**Keep the repo public and constrain content to suit.** The prior state. Coherent, but it taxes
every commit with a disclosure review and pushes reasoning like the detection-coverage gap out
of the tree, which is how it came to live in a chat log instead.

**Go private and relax nothing.** Superficially safe, and it is the position that gets adopted
*by default* precisely because it requires no thought — so it is the one to argue against
properly. It is wrong because it wastes the relaxation private status actually earns (the team
now cannot write down a coverage gap it is free to write down), and, more dangerously, it
invites the inverse error: "private, so it does not matter", which starts relaxing the *second*
category — the credentials and customer data that private status must not relax at all. Refusing
to separate the categories is what lets that slide happen unnoticed. The decision is to separate
them explicitly, relax the first, and hold the second exactly where it was.

## Consequences

A private repo is **not an access control** for anything a clone carries. Everyone with read
access has everything in it, forever — including after they leave the project, in a clone made
before their access was removed. So the relaxation is narrow and bounded to the first category:
disclosure to an *unknown* reader is no longer the threat, but disclosure to *any* reader who
ever had access still is. Nothing in the second category moves on the strength of "it's private
now", and a real credential or a piece of customer data is exactly as unacceptable in a private
repo as in a public one.

## Review trigger

The first design partner, or any third-party access to the repository. That is a different
question again from public-versus-private: a private repo with a third party in it reintroduces
an "unknown-to-the-decision reader" for the first category, and simultaneously widens the "ever
had access" set the second category is measured against. Revisit both category assignments then,
not just the first.
