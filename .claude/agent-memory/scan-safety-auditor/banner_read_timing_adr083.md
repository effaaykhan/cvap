---
name: banner-read-timing-adr083
description: ADR-083 banner-read budget change (maxBannerWait=5s) — kill switch is a process signal so the 5s read never delays it; the ctx-deadline clamp is dead code; concurrency claim breaks in safe mode
metadata:
  type: project
---

ADR-083 fix in internal/engines/discovery/discovery.go raised the banner read from a
hard 1s cap to a caller budget: `maxBannerWait=5s` (unsolicited when no probe applies,
and every probe response read), `shortBannerWait=1s` (unsolicited pre-read when a probe
will follow). Exim delays its SMTP 220 ~4s for a client reverse-DNS lookup, so 1s flipped
the release vote tier between scans.

**Why:** audited 2026-09-10. Findings future audits should check first:

- **Kill switch is NOT delayed by the 5s read.** The discovery engine
  (cmd/cvap-engine-discovery/main.go:59) runs Run with `context.Background()` — never
  cancelled, no deadline. SIGTERM is deliberately unhandled (main.go:18-21), so the
  runtime's `stop()` (internal/scanpoint/enginehost.go:520) terminates the process via
  default signal disposition, immediately, regardless of an in-flight `conn.Read`. So the
  "conn.Read ignores ctx" concern does not bound kill latency here.
- **The readBanner ctx.Deadline() clamp is dead code in production** (discovery.go:526-530).
  Background has no deadline, and the wire job (internal/enginewire/wire.go) carries none, so
  the budget is never clamped — the comment "Still clamped by the job's context deadline" is
  misleading. LATENT: if anyone ever wires a cancellable/deadline ctx into Run to make
  cancellation cooperative, conn.Read will then block up to 5s per in-flight port (concurrent,
  ~5s wall, within 9s MaxStopGrace / 10s ADR-024) — the read has no ctx.Done() watcher.
- **"Bounded by slowest single port, not the sum" is false when open-silent ports > MaxConcurrentPerTarget.**
  In safe mode there are no probes, so web/TLS/mgmt ports (which never greet unsolicited)
  each burn the full 5s. A host with N open silent ports, concurrency C(≤20): banner wall-time
  ≈ ceil(N/C)×5s. Added wall-time vs old 1s cap: +4s per batch. No ctx-deadline backstop.
- **Rate/scope/impact CLEAN.** Read is not charged; cost model (discovery.go:365-391) is
  SynCost(ConnectTimeout)+established+probe count only — banner budget never enters it.
  SynCost keyed on ConnectTimeout, unchanged. Slow read holds a sem slot but takes no tokens.
  No new send, probe, or target construction; IP-only scope path unchanged.

**How to apply:** duration/concurrency-claim issue is Medium-Low (no blast-radius or rate
change, ADR-058 SLOs are API/ingest latency not scan wall-clock). The kill-switch worry the
parent flagged is not a live defect given Background ctx + unhandled SIGTERM — but re-check it
the moment Run is given a real ctx. See [[discovery-engine-wire-findings]].
