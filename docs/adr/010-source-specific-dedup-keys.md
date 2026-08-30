# ADR-010: Finding dedup keys are source-specific; SAST keys on symbol not line

**Status:** Accepted
**Date:** 2026-08-30

## Context

The dedup key decides whether dashboard counts mean anything and whether findings churn for
no reason. There is no single key that works across sources: a network finding is identified
by port, a DAST finding by URL and parameter, a SAST finding by a location in source. Getting
this wrong is not a cosmetic problem — it either inflates counts or closes and reopens
findings on unrelated edits, and both destroy trust in the backlog.

## Decision

Dedup keys are source-specific and computed at the finding pipeline:

| Source | Dedup key |
|---|---|
| Network / service | asset, port, protocol, rule |
| Credentialed host | asset, package or component identity, rule |
| DAST | target, **normalised** URL path, parameter name, rule |
| API | endpoint, method, parameter, rule |
| SAST | repository, file path, **enclosing symbol**, rule |
| Configuration | asset, setting path, rule |
| Cloud | resource ARN or equivalent, rule |

Two rules are non-negotiable. SAST keys on the enclosing function or symbol, **never the line
number**. DAST normalises the URL before keying. And the same issue on the same asset seen
from two vantage points is **one finding with two exposures** (ADR-008), not two findings.

## Alternatives considered

**One universal key — asset plus rule plus a locator string.** Tempting for pipeline
simplicity, and it is roughly what the table above collapses to. Rejected because the
locator's structure is what makes it stable: an opaque string gives no way to normalise a URL
or resolve a symbol, so the traps below reappear with no place to fix them.

**Key SAST on file path and line number.** The obvious choice and the reason this ADR exists.
Line numbers shift on every unrelated edit above them, so a whitespace change closes and
reopens every finding in the file, destroying age, triage state and any measure of remediation
progress.

**Key DAST on the raw URL.** Rejected: one vulnerable template behind `/users/{id}/profile`
produces thousands of findings, one per traversed ID — an unusable backlog from a single
defect.

**One finding per vantage point.** Rejected: it inflates the critical count by the number of
vantage points, which is the first number an executive looks at, and it fragments remediation
across rows describing the same defect.

## Consequences

Counts are meaningful and finding age survives ordinary code and infrastructure churn.
Remediation tracking works because a finding persists across scans. The costs are a
source-specific keying path per engine that must be tested per source, a URL normaliser and a
symbol resolver that are each a real piece of work, and the fact that changing a key
definition later migrates or orphans existing findings — so each is effectively frozen once
findings exist.

## Review trigger

Revisit per source when a new engine class ships (cloud, container, agent), and immediately
if measured finding churn between two consecutive unchanged scans is non-zero for any source.
