# ADR-001: Go for core, scan points and agents; Python for knowledge pipelines

**Status:** Accepted
**Date:** 2026-08-30

## Context

Scan Points and Agents deploy into customer environments we do not control and cannot
observe. Scanning is overwhelmingly concurrent IO — tens of thousands of in-flight
connections — while the knowledge pipelines are messy-feed data wrangling where iteration
speed dominates and deployment is server-side only. One language does not fit both.

## Decision

Go for the Control Plane, Scan Points and Endpoint Agents: a single static binary with no
runtime dependency, the goroutine model matched directly to concurrent IO, trivial
cross-compilation to Windows, Linux and macOS for Phase 9 agents, mature raw-socket support
via `gopacket`, and an infrastructure-security library ecosystem that is already largely Go.
Python 3.12 for Knowledge Plane ingestion pipelines only. Rust is held in reserve: because
engines are separate processes behind a job contract (ADR-027), a single engine can be
rewritten in Rust later without touching anything else.

## Alternatives considered

**Python everywhere.** Eliminated by the deployment constraint alone. Shipping a Python
runtime and its dependency tree into an unowned, possibly air-gapped customer network is a
support cost we would pay on every install, forever.

**Rust for everything.** Better for the packet hot loop and for SAST data structures, and it
would be the right answer if the product were only those things. It carries a real velocity
cost across the large majority of the codebase that is ordinary control-plane and pipeline
work. The engine process boundary means we do not have to pay that cost up front to keep the
option.

**Go for the knowledge pipelines too, for a single-language codebase.** Rejected: advisory
feeds are inconsistent, frequently malformed, and change shape without notice. Iteration
speed is the dominant cost there, and those pipelines run only on servers we operate, so the
static-binary argument does not apply.

## Consequences

Scan Points and Agents ship with **no runtime dependency to install in an environment we do
not control** — a runtime binary plus its engine binaries (ADR-027), distributed as one
archive rather than one file. That is the support-cost benefit that survives. Hiring draws
on the same pool as the rest of the infrastructure security industry. In exchange we accept
two toolchains, two dependency-audit surfaces and two CI paths, and we accept that the
packet hot loop will be slower than a Rust equivalent until we choose to rewrite that engine.

## Review trigger

Revisit when a profiled engine — most likely discovery packet handling or SAST analysis —
is demonstrably bottlenecked by the runtime rather than by IO or algorithm choice. That is a
per-engine decision, not a platform-wide one.
