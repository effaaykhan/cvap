---
name: shutdown-drain-result-loss
description: Graceful SIGTERM shutdown with a job in flight loses gathered results (ADR-026) — the drain loop declares victory on an empty buffer before the abort goroutine enqueues
metadata:
  type: project
---

Graceful shutdown (SIGTERM) of a scan point with a job in flight silently loses
every observation the engine gathered. Reproduced deterministically 2026-09-05
on HEAD 43ac46d via an e2e probe (single-pid SIGTERM, engine in its own pgid —
faithful to production). Log: `"shutting down with jobs in flight"` then
`"result buffer drained; exiting"` ~0.5ms later; submissions=0, observations=0.

**Why:** three facts compose:
- `runJob` (internal/scanpoint/runtime.go:484) does `defer close(j.done)` and, on
  `EngineStopped`, does nothing else — it closes `j.done` as soon as the engine is
  reaped (`host.wait()` returns), NOT after results are submitted.
- `abort()` runs `terminate()` (which does `submit.Enqueue`) in a SEPARATE
  goroutine (`go r.abort(j)`). `stop()` and `wait()` are both released by the same
  `close(h.reaped)` (enginehost.go:544), so `close(j.done)` (little work) reliably
  beats abort's `zeroise→results→toWire→Enqueue` (more work).
- `shutdown()` (runtime.go:359-367) waits ONLY on `j.done`, so it returns before the
  enqueue. Then `cmd/cvap-scanpoint/main.go:134-151` drain loop checks
  `submitter.Buffered()` IMMEDIATELY, sees 0, logs "result buffer drained;
  exiting" and returns — process exits before the enqueue lands. Memory-only
  buffer, so lost. The success log is false.

**Not the lease-loss path.** Mid-job lease loss is SAFE: the process stays up, the
first `go submitter.Run(ctx)` keeps draining, results land quarantined at the
stale epoch. TestSelfAbortOnLeaseLoss passes and confirms this. The defect is
specific to SIGTERM/shutdown (rolling restarts, deploys, node drains).

**How to apply:** severity High — silent ADR-026 data loss on a routine op, and
for non-reassign_safe/intrusive jobs it destroys the exact ADR-012 "what did this
job touch" record. Fix direction: `shutdown()` must wait for the abort goroutine
to RETURN (terminate/Enqueue complete), e.g. a WaitGroup over the spawned aborts
or a per-job "terminated" signal closed after terminate — not `j.done`. And the
main drain loop must not treat an initially-empty buffer as "drained" before
aborts are known enqueued. Relates to [[scanpoint_runtime_bypasses]].
