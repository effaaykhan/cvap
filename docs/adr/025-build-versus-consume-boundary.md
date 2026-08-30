# ADR-025: Build-versus-consume boundary

**Status:** Accepted
**Date:** 2026-08-30

## Context

v1 §55 said to build capabilities rather than wrap existing scanners. That is the right rule
and it remains in force, but stated alone it has no boundary — and without one the team will
spend a quarter writing a lexer, or a TLS parser, and call it product work.

## Decision

The line is **security analysis versus commodity infrastructure**.

**Build ourselves.** Discovery logic and scheduling. Fingerprinting heuristics and the
signature corpus. Asset identity resolution and correlation. The rule engine and rule
language. Crawler logic and application modelling. Taint analysis. The risk model. The finding
pipeline. Every part of the control plane, data model and orchestration.

**Consume, do not rebuild.** TLS stacks. HTTP clients. Packet capture primitives. Parser
generators and language grammars. CVE, CPE and advisory data. CVSS calculators. Compression
and cryptography.

Using tree-sitter grammars as SAST frontends is not wrapping a SAST tool — the analysis on top
of the AST is the product. Reimplementing a TLS parser is not an achievement; it is a
liability you will be asked to justify in every procurement review.

## Alternatives considered

**Wrap existing scanners.** Orchestrate nmap, OpenVAS, ZAP, Semgrep and Trivy behind a
unified control plane and data model. Fastest route to broad coverage and to revenue.
Rejected: the finding quality, confidence calibration and evidence model would be whatever
those tools emit, which makes ADR-006's observation-first flow, ADR-010's dedup keys and
ADR-014's advisory matching impossible to implement honestly — and it leaves no defensible
answer to "why you rather than the free tool you are wrapping."

**Build everything, including the commodity layers.** Own TLS parsing, HTTP, packet
primitives and language grammars for maximum control. Rejected: those are solved, hardened by
years of adversarial attention, and reimplementing them substitutes our bugs for their fixes
in exactly the components most exposed to hostile input. It also consumes the engineering
time the differentiating analysis needs.

**A hybrid: build the control plane and data model, wrap third-party engines initially, then
replace them engine by engine.** The most commercially attractive option and the one this
decision explicitly declines. Rejected because a wrapped engine's output shape leaks into the
schema, the confidence model and the UI, and "replace later" is a migration nobody funds once
revenue depends on the wrapper. The engine process boundary means we can still swap
*implementations* later (ADR-027) — but of engines we wrote.

## Consequences

Detection quality, confidence and evidence are ours to control, which is what ADR-014's
precision goal and the risk engine's confidence weighting require, and there is a defensible
answer in every procurement review about what the product actually is.

Stated plainly: **this substantially increases time to first revenue versus the hybrid
approach — by an amount we have not quantified.** That is the price of the decision, and it is
the reason the roadmap front-loads Phase 2 as an independently saleable attack surface
inventory — putting something in front of customers before vulnerability detection is mature
is the mitigation, not a coincidence. The other cost
is a standing obligation: the fingerprint corpus, the rule packs and the comparators are
content that never stops needing work, and they need a named owner rather than being
someone's spare capacity.

## Review trigger

Before starting any Phase 7+ engine — DAST, API, agents, cloud, container, SAST — each of
which is a fresh build-versus-consume judgement at its own scale. And immediately if the
first sellable release slips past month 12.
