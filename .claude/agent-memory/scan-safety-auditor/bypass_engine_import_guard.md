---
name: bypass-engine-import-guard
description: Confirmed bypasses of internal/engines/import_policy_test.go — check these first on any engine change
metadata:
  type: project
---

`internal/engines/import_policy_test.go` is a **deny-list on direct imports only**. Six
bypasses confirmed by experiment on 2026-09-02 (probe module replicating the walk; all
PASSED the guard when they should have failed):

1. **Transitive imports.** `build.ImportDir` returns direct imports. An engine importing
   `internal/somehelper` that imports `net` passes clean. The doc comment on
   `internal/engines/noop/noop.go` claims the guard "walks the import graph" — it does not.
2. **Build-tag-hidden files.** `//go:build scanmode` on a file importing `net` is invisible:
   `build.ImportDir(dir, 0)` uses the host build context, so constrained-out files land in
   `IgnoredGoFiles` and their imports are never read. Same trick hides a whole package.
3. **Third-party network libraries.** Only `golang.org/x/sys` is forbidden.
   `golang.org/x/net/icmp`, `github.com/miekg/dns`, `github.com/google/gopacket/pcap` all pass.
4. **cgo.** `import "C"` plus `C.socket(...)` passes; `"C"` is not in `forbidden`.
5. **`unsafe` + `go:linkname`**, and **`plugin`** (dlopen a .so), neither forbidden.
6. **`os`** — not forbidden, and `os.StartProcess` is `os/exec` without the import.

`neutralPrefixes` in that file is the correct fix and is explicitly documented as *not
enforced*. Inverting it (allow-list of import prefixes, deny everything else) closes 1, 3, 4,
5 and 6 at once. `packages.Load` with `NeedDeps|NeedImports` closes 1 properly; iterating
build contexts or reading `pkg.IgnoredGoFiles` closes 2.

**Why:** an engine reaching the network outside the runtime's rate allocation defeats
ADR-024's ceilings and ADR-027's allocation model entirely — the runtime cannot rate-limit a
socket or a subprocess it does not mediate.

**How to apply:** on any diff under `internal/engines`, or any diff to the guard itself,
re-test these six specifically rather than trusting a green test run. Also check whether the
engine's `cmd/` main package is covered — the guard's boundary is a directory, the deliverable
is a process, and the main package that wires an engine to IPC sits outside `internal/engines`.

Related: [[dispatch-scope-and-kill-gaps]]
