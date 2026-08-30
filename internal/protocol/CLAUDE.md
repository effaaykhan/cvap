# internal/protocol

Conformance tests for the `proto/` wire contract. No production code.

`buf breaking` enforces the mechanical half of ADR-022 -- no removals, no
renumbering, no type changes. This package enforces the behavioural half: that a
build of Core one version ahead of a scan point, or a scan point one version
behind Core, actually interoperates.

The tests here construct *future* descriptors at runtime from the current ones
and round-trip messages through the current generated types. If you add a
message or an enum to `proto/`, the table-driven tests pick it up automatically
-- that is deliberate, so coverage does not depend on anyone remembering.

Three properties to preserve if you edit these tests:

- **Unknown fields must survive a re-marshal, not merely be tolerated on parse.**
  Under ADR-026 a scan point buffers results locally for up to 24 hours and
  resubmits them. If an old build drops fields it does not understand on that
  round-trip, the loss happens inside a customer network, to data nobody is
  watching, and surfaces months later as findings that were never generated.
  Tolerating unknown fields and preserving them are different properties and
  only the second one is enough.
- **The unknown-field assertion must be checked, not assumed.** Every case
  asserts the future field really was unknown to the current type. Without that,
  a test that silently compared a message to itself would pass forever.
- **Streaming cardinality is pinned.** ADR-026 records that changing an RPC's
  streaming shape is a major-version break, not an additive change. It is
  asserted here because it is the one part of the contract `buf breaking`
  reports as a change to a service rather than to a field, and it is easy to
  wave through.
