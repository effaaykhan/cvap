# ADR-079: A safe-mode scan reports on services that volunteer a banner, not services that exist

**Status:** Accepted
**Date:** 2026-09-10

Recorded from the same Session 39 measurement as ADR-078. Safe mode (ADR-021 default, ADR-048/049)
is a correct safety decision with a measured coverage cost, and the cost must be visible where an
operator reads the result.

## The measurement

The host exposed three services: SSH (22), SMTP/Exim (25), HTTP/Apache (80), all listening on
`0.0.0.0`. A safe-mode scan identified **two of the three**:

- SSH and SMTP send an unsolicited banner on TCP connect, so safe mode reads them passively.
- Apache on port 80 came back **unidentified** (`method: none, solicited: false`). HTTP sends
  nothing until it receives a request, and safe mode withholds the active probe (ADR-048/049:
  banner rules travel in safe mode, probes do not), so the port was seen open but the service was
  never named.

So **one of the three exposed services — a third of the reachable surface — was invisible**, not
because it was filtered or absent, but because identifying it requires a probe safe mode does not
send. This is not a fingerprint-corpus gap: the engine has HTTP identification capability; an
intrusive scan would have sent the GET and named Apache.

## Effect on the accuracy numbers

Because the exposed-package accuracy subset is built from *identified* services, Apache's 24 real
advisory findings (installed GA `2.4.66-2ubuntu2`, below all three apache2 fixes) fell outside it.
The consequence, stated honestly:

- Against the **identified** exposed surface (OpenSSH + Exim): TP 7, FN 0, **recall 100%**.
- Against the **actual** exposed surface (adding Apache's 24): TP 7, FN 24, **recall 23%**.

The second is the number that describes what an operator gets. The `100%` is 100% of what the scan
happened to identify, which silently excludes a reachable, vulnerable service.

## Consequence

- **A safe-mode result is a lower bound on exposure, not a census.** It reports on the services that
  volunteer a banner, not the services that exist. This must be visible to an operator reading a
  safe-mode scan — a clean or thin result on a host is not evidence the host is clean or thin; it
  may be evidence that its services do not talk first. (The same "absence is not evidence" discipline
  the advisory-coverage work applies to releases, applied here to identification.)
- The safety decision itself is correct and unchanged: ADR-021's safe default exists so a scan
  cannot achieve impact, and withholding an unsolicited HTTP request is part of that. The finding is
  not "safe mode is wrong" — it is "safe mode's coverage is narrower than the reachable surface, by a
  measured amount, and the result must say so."
- It compounds ADR-078 for credentialed assessment's case: the services safe mode *does* identify
  are matched with structural false positives (revision blindness), and the services it *doesn't*
  identify are silent false negatives. Both point the same way.
- No fix this session: the coverage cost is recorded, and whether safe-mode results should carry an
  explicit "identification is banner-only; probe-required services may be unreported" caveat in the
  API/UI is a decision this informs but does not make.
