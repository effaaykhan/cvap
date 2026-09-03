# ADR-039: Translated address forms expand exclusions and do not expand allows

**Status:** Accepted
**Date:** 2026-09-03

## Context

An IPv4 host can be named by several IPv6 addresses. NAT64 (`64:ff9b::/96`, RFC 6052), 6to4
(`2002::/16`, RFC 3056), Teredo (`2001::/32`, RFC 4380), ISATAP (RFC 5214) and the deprecated
IPv4-compatible form (`::/96`, RFC 4291) each embed a v4 address inside a v6 one, and a packet
sent to the translated form reaches the same machine through translating infrastructure.

`internal/scope` unmapped `::ffff:0:0/96` and nothing else, so a scope decision about
`192.0.2.5` said nothing about `64:ff9b::192.0.2.5`. A scan-safety audit found it while
reviewing the scan point runtime. The obvious repair — treat every translated form as its
embedded v4 address, everywhere — is wrong in one of the two directions, and the wrongness is
not symmetric.

## Decision

**Translated forms expand exclusions. They do not expand allows.** Both halves fail closed.

- **Exclusions expand.** An exclusion of `192.0.2.5` also excludes `64:ff9b::192.0.2.5`,
  `2002:c000:0205::1`, the Teredo form, the ISATAP form and the v4-compatible form, because a
  packet to any of them reaches the host the operator excluded. An operator who excluded a medical device and
  found it scanned through a translator would be right to call that a defect in this system,
  not in their configuration.

- **Allows do not expand.** An allow of `192.0.2.0/24` does **not** authorise
  `64:ff9b::192.0.2.5`. The operator authorised a v4 range. The translated form is a different
  address, reached over infrastructure they may not own and may not have authorisation to
  send through, and `SCAN_TARGET.authorization_verified` was recorded against what they wrote.
  An allowlist that silently widens is precisely the failure ADR-037's permission/constraint
  split exists to prevent.

Six narrower rules follow, and each is the conservative reading of the same principle:

- **A translated ADDRESS on the rule side expands; a translated PREFIX does not.** An
  exclusion of `64:ff9b::192.0.2.5` covers `192.0.2.5`, because it plainly names one host. An
  exclusion of `64:ff9b::/96` does **not** cover every IPv4 address, because that prefix
  contains all of them: expanding it would turn one exclusion into a denial of the entire
  internet, which is not what an operator excluding their NAT64 range meant.

- **A rule is read as an address whether or not it carries a mask.** `64:ff9b::192.0.2.5` and
  `64:ff9b::192.0.2.5/128` are the same rule. This is not a convenience: `policy_scope_rules`
  rows typed `cidr` are validated with `ParsePrefix`, which rejects the bare form outright, so
  the masked spelling is the *only* one a `cidr` rule can use — and a rule side that read only
  bare addresses would be unreachable for the natural match type.

- **Five names, one host.** An exclusion in any translated form covers the same host in every
  other, and in bare v4. An operator who excluded the NAT64 form means that machine, not that
  spelling of it.

- **Only NAT64's WELL-KNOWN prefix is recognised, and that is a different judgement from
  ISATAP's.** RFC 6052 §2.2 network-specific prefixes come in five lengths with the embedded
  address at a different offset in each, and RFC 8215's `64:ff9b:1::/48` needs the same guess;
  choosing wrong produces an exclusion matching a host nobody named, which is as bad as
  missing one. ISATAP has no such ambiguity — its marker is a fixed interface identifier
  (`0000:5efe` or `0200:5efe` at bytes 8–11) with the address always in the low 32 bits,
  independent of the prefix — so it is recognised. The test is whether the extraction can be
  wrong, not whether the mechanism is obscure.

- **Only the destination is extracted.** A Teredo address also carries its *server's* v4
  address at bytes 4–7. That is not extracted, because the rule this ADR states is "the packet
  reaches the same host", and a packet to a Teredo client does not reach the Teredo server as
  a scan target.

- **A prefix that names no host yields nothing.** `2002::` and `64:ff9b::` embed 0.0.0.0 and
  `2001::` embeds 255.255.255.255; `::` and `::1` sit inside `::/96`. None is a host a scan
  reaches, and treating them as addresses would let an exclusion of a bare prefix match a
  target that is not there.

**`::ffff:0:0/96` is not in this category and keeps expanding in both directions.** A
v4-mapped address is a notation for a v4 address inside a socket API. It is not routable as
IPv6, it reaches the host by the same path the bare v4 form does, and `netip` already treats
the two as one address through `Unmap`. The line this ADR draws is between a different
*spelling* of an address and a different *route* to a host.

## Alternatives considered

**Expand in both directions.** One rule, easy to state, and it makes the two lists behave
consistently. Rejected: it widens an allowlist by inference. The operator wrote a v4 range and
would be told, correctly, that the tool decided on its own to scan an IPv6 address they never
authorised — through a translator they may not operate, which for NAT64 is frequently the ISP's.
Under execution-plan §8 risk 6 an unauthorised scan is legal exposure, and "the address
resolves to a host you did authorise" is not the authorisation that risk is about.

**Expand in neither direction.** Symmetric the other way, and it is what the code did before.
Rejected on the failure it produces: an exclusion is the mechanism by which an operator
protects a printer, a SCADA controller or a medical device, and one that a NAT64 prefix
defeats is not an exclusion. ADR-024 makes exclusions take precedence over allows *regardless*
of ordering or precedence value; a precedence that can be deleted by choosing a notation is
not a precedence, which is the same argument that made tag-rule dropping a defect.

**Resolve translated forms at planning and rewrite them to v4.** Normalise once, then compare
plain addresses. Rejected: it discards which form was authorised, so the record of what an
operator approved stops matching what was scanned — and Core and the scan point would have to
normalise identically or produce different verdicts, which is the divergence `internal/scope`
exists to prevent. Comparing both forms at decision time keeps one implementation and one
answer.

**Treat this as a rule-authoring problem and document it.** Tell operators to exclude every
form. Rejected: it requires every operator to know five RFCs to write one exclusion, and the
one who does not gets a silent scan of a device they thought they had protected. A control
that depends on the customer knowing about Teredo is not a control.

## Consequences

The two lists behave differently, and that asymmetry reads as a bug to anyone who finds only
one half of it — which is why it is written down here and asserted in
`internal/scope/scopetest`, where Core and the scan point runtime are both held to it.

An operator who genuinely wants to scan through a translator says so explicitly: an allow of
`64:ff9b::/96`, or of the specific translated address, authorises it. Nothing is unreachable;
what changed is that reaching it requires saying so.

`translatedV4s` returns every candidate rather than the first match, because ISATAP is
identified by an interface identifier rather than a prefix and can therefore coexist with a
prefix-based mechanism in one address. Testing all of them over-matches, which for an exclusion
is the direction that fails closed; picking one by switch order would silently discard the
other.

The list of five mechanisms is fixed and will age. A new one is invisible to it and expands
nothing, which is the fail-OPEN direction for exclusions — the same standing weakness a fixed
allowlist of match types has, and the reason the review trigger below exists rather than a
claim that the list is complete.

A translated exclusion still cannot reach a target that is not parseable as an address at all.
`192.0.2.5:443`, `[192.0.2.5]` and `192.0.2.5.` fall through to hostname comparison, where no
address or CIDR rule matches them. That is a separate defect about what a task target may look
like, recorded in the scan-safety memory rather than fixed here, because refusing every
unparseable target would also refuse the URL targets `policy_scope_rules` already accepts.

## Review trigger

A sixth translation mechanism in real use, or a deployment that needs a network-specific NAT64
prefix (RFC 6052 §2.2, or RFC 8215's `64:ff9b:1::/48`) recognised. The second would mean the
prefix has to be configuration rather than a constant, at which point it belongs with the
policy rather than in this package.
