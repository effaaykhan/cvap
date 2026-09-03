---
name: bypass-engine-import-guard
description: State of the engine import guard (now internal/enginepolicy). The six old bypasses are closed by inverting to an allowlist; the new exception mechanism leaks os/exec by prefix match.
metadata:
  type: project
---

The guard moved from `internal/engines/import_policy_test.go` to
`internal/enginepolicy/policy_test.go` and was **inverted into an allowlist**. Its roots are
`internal/engines` plus every `cmd/cvap-engine*`, which closes the boundary problem the old
note ended on — the binary is now covered, not just the library.

## Closed — do NOT re-report

The six bypasses confirmed 2026-09-02 are all closed by the inversion plus one extra check:
transitive laundering through a helper package, third-party network libraries, cgo,
`unsafe`/`plugin`, and bare `os` all fail now because the import is not on `permitted`.
Build-tag-hidden files are caught explicitly — a non-empty `pkg.IgnoredGoFiles` is an error.
Test imports (`TestImports`, `XTestImports`) are checked too.

## Open — confirmed by experiment 2026-09-03

**`exceptions` matches by PREFIX, so granting `os` also grants `os/exec` and `os/signal`.**
`isException` does `imp == a || strings.HasPrefix(imp, a+"/")`. The entry added for
`cmd/cvap-engine-noop` is `{"os", "…/internal/enginewire"}`, and its own comment says
"Deliberately NOT granted: os/exec, os/signal, syscall, net" — the code grants the first
two. Proved by dropping a file importing both into `cmd/cvap-engine-noop`: the guard passed.
`os/exec` is the case the guard exists for ("shelling out escapes the runtime's rate
allocation entirely"). Fix is exact match for exceptions, or explicit sub-path entries.

**The allowlist is still direct-imports-only, and `internal/enginewire` now sits outside the
guard's roots.** Anything on `permitted` (`internal/domain`, `internal/logging`,
`internal/engines`) or granted by exception is trusted wholesale — its own imports are never
walked. `enginewire` is the engine-facing IPC package and the most likely place someone
later adds a socket ("gRPC instead of pipes"); the exception's justification, that it
"imports nothing that could reach a network", is true today and enforced by nothing.

**Why:** an engine reaching the network outside the runtime's rate allocation defeats
ADR-024's ceilings and ADR-027's allocation model entirely — the runtime cannot rate-limit a
socket or a subprocess it does not mediate. That mattes more now that the runtime exists and
is the second scope enforcement site: the guard is the only thing making "engines receive
pre-authorised targets and construct none" structural rather than a convention.

**How to apply:** on any diff to `internal/enginepolicy`, `internal/engines`,
`internal/enginewire` or a `cmd/cvap-engine-*`, test the prefix leak first (add an import,
run the guard, expect a failure), then check whether a newly-permitted first-party package
is itself walked.

Related: [[scanpoint-runtime-bypasses]], [[dispatch-scope-and-kill-gaps]]
