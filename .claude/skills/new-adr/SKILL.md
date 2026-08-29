---
name: new-adr
description: Create a new architecture decision record. Use when a consequential architectural choice is made or discovered undocumented.
argument-hint: "[short-decision-title]"
disable-model-invocation: true
---

# New ADR

Create `docs/adr/NNN-<slug>.md` using the next free number, then add it to `docs/adr/000-index.md`.

Title: $ARGUMENTS

## Template

```markdown
# ADR-NNN: <title>

**Status:** Accepted | Superseded by ADR-NNN | Proposed
**Date:** <YYYY-MM-DD>

## Context

What forced a decision. The constraint, not the solution. Two or three sentences.

## Decision

What was decided, stated so a reader can check code against it. One paragraph.

## Alternatives considered

What was rejected and why. This is the part future-you will actually need — without it,
the decision looks arbitrary and gets quietly reversed.

## Consequences

What this makes easy, what it makes hard, and what it forecloses.

## Review trigger

The condition under which this should be revisited. Leave blank only if genuinely permanent.
```

Keep it under one page. An ADR nobody reads is worth nothing.
