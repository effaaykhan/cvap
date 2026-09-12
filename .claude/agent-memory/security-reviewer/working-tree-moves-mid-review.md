---
name: working-tree-moves-mid-review
description: Files under review can be edited by another agent mid-session — re-run git diff immediately before writing findings
metadata:
  type: feedback
---

Re-run `git diff` on every file you are reporting on immediately before writing the
findings, and diff again if the review took a long measurement pass.

**Why:** in the ADR-095 review (2026-09-12) both `internal/store/assets.go` and
`internal/correlate/correlate.go` were rewritten by a parallel session while I was
probing — the subselect guard became an inline CASE and an `Assets.ReleaseOf` readback
appeared, fixing the two defects I had just measured. Two unrelated files
(`web/src/lib/console.ts`, `console.test.ts`) also appeared in `git status` that were not
there at the start. Reporting from the earlier read would have described code that no
longer existed.

**How to apply:** checkpoint with `md5sum` on the files under review before a long test
run and compare after. Report findings against the tree as it stands at the end, and say
plainly which findings were already fixed during the session rather than silently
dropping them — the user needs to know they were real. Never restore a backup copy of a
source file over a tree that may have moved; verify the hash first.
