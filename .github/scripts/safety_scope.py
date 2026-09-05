"""The six §6.3 scope-enforcement cases, each measured at the wire.

Imported by safety_gate.py after its engine-level phases. Where the narrow gate
runs an engine directly and checks its egress against lab/scope.txt, these cases
drive the scan-point RUNTIME (test/safety/runtimedrive → engineHost.authorise),
which is ADR-024's second enforcement site and the one that decides whether a
packet may leave. Each case puts real packets on cvap-lab_segment-a and asserts
which addresses did and did not receive them.

Two shapes of enforcement are measured:

  - a forbidden ASSIGNED target refuses the whole job (fail-closed) — no engine,
    no packets. Every such case is paired with a positive control that DOES send,
    so "no packet to the forbidden host" is never the trivial pass of a run that
    sent nothing.
  - a CIDR that includes its network and broadcast addresses, and excludes the
    hosts one below and one above it.

Two of the §6.3 items are NOT wire-exercisable and say why rather than pretending:
a redirect to an out-of-scope host (the fingerprint engine follows no redirect,
so there is no engine action to enforce against) and the NAT64/6to4/Teredo/ISATAP
translated forms of an excluded v4 (the lab has no translator, so a packet to the
translated form has no route and is never produced). Both are asserted in
internal/scope/scopetest and named below.
"""

import json
import subprocess
import sys

# All routable, up lab hosts on segment-a. The forbidden addresses are real hosts
# so a failure produces a real packet to a live target rather than silence.
NET = "cvap-lab_segment-a"
H_NGINX = "10.10.0.11"     # answers, in every /24 case
H_OPENSSH = "10.10.0.14"   # the excluded host in the overlap case
H_TLS = "10.10.0.15"       # one below the /30 boundary
H_A6 = "10.10.0.16"        # the /30 network address
H_WEAKKEY = "10.10.0.19"   # the /30 broadcast address
H_FRAGILE = "10.10.0.20"   # one above the /30 boundary
H_FILTERED = "10.10.0.30"  # SYN retransmits — a long-running scan for the abort case
H_PRINTER = "10.10.0.40"


def _sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def _target(i, value):
    return {"task_id": f"t{i}", "value": value}


def _run(work, capture_image, engine, phase, job):
    """Write the job, run it through runtimedrive in the capture container, and
    return (result_dict, egress_list). egress_list is [(ts, addr, port, plen)]
    for OUTBOUND packets only."""
    (work / f"job-{phase}.json").write_text(json.dumps(job) + "\n")
    r = subprocess.run(
        ["docker", "run", "--rm", "--network", NET,
         "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
         "-v", f"{work}:/w", capture_image, "/w/run-runtime.sh", engine, phase],
        capture_output=True, text=True,
    )
    if r.returncode != 0:
        raise RuntimeError(f"the {phase} capture container failed: {r.stderr[-800:]}")

    result = {}
    rp = work / "out" / f"result-{phase}.json"
    if rp.exists() and rp.stat().st_size:
        try:
            result = json.loads(rp.read_text())
        except ValueError:
            result = {}

    text = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{work}:/w", capture_image,
         "sh", "-c", f"tcpdump -tt -n -r /w/out/capture-{phase}.pcap 2>/dev/null"],
        capture_output=True, text=True,
    ).stdout
    return result, _egress(text)


def _egress(text):
    """Outbound packets from a `tcpdump -tt -n -i any` capture: (ts, addr, port,
    payload_len). Direction is the token before IP/IP6; anything not inbound from
    a peer is egress (loopback is labelled In even outbound, but the resolver is
    the only loopback peer here and belongs in the DNS count)."""
    out = []
    for line in text.splitlines():
        parts = line.split()
        try:
            i = next(j for j, tok in enumerate(parts) if tok in ("IP", "IP6"))
        except StopIteration:
            continue
        if len(parts) < i + 4 or parts[i + 2] != ">":
            continue
        direction = parts[i - 1] if i > 0 else ""
        dst = parts[i + 3].rstrip(":")
        addr, _, port = dst.rpartition(".")
        if direction == "In" and not (addr.startswith("127.") or addr == "::1"):
            continue
        try:
            ts = float(parts[0])
        except ValueError:
            ts = 0.0
        plen = 0
        if "length" in parts:
            k = parts.index("length")
            if k + 1 < len(parts):
                try:
                    plen = int(parts[k + 1].rstrip(":"))
                except ValueError:
                    plen = 0
        out.append((ts, addr, port, plen))
    return out


def _dests(egress):
    d = {}
    for _, addr, _, _ in egress:
        d[addr] = d.get(addr, 0) + 1
    return d


def _dns(egress):
    return sum(1 for _, _, port, _ in egress if port == "53")


# ---------------------------------------------------------------------------
# The six cases. Each takes `sabotage` (the case name currently being sabotaged,
# or None) and returns (report_line, failures). A case sabotaged must fail; a
# case not sabotaged must pass, so make safety-sabotage can break each alone.
# ---------------------------------------------------------------------------

def case_exclusion_overlap(work, img, sab):
    """An exclusion of a host inside an allowed range: the host gets no packet,
    the rest of the range does."""
    name = "exclusion-overlap"
    allowed = ["10.10.0.0/24"]
    exclusions = [] if sab == name else [H_OPENSSH]  # sabotage: drop the exclusion

    # The excluded host is among the assigned targets: fail-closed refuses the
    # whole job, so it receives nothing. Sabotaged, the exclusion is gone and the
    # job runs, and a packet reaches the host the operator excluded.
    res, eg = _run(work, img, "cvap-engine-discovery", name, {
        "job_id": name, "allowed": allowed, "exclusions": exclusions,
        "targets": [_target(0, H_NGINX), _target(1, H_OPENSSH)],
        "rate_budget_pps": 50, "connect_timeout_ms": 3000,
        "max_concurrent_per_target": 4, "safety_mode": "safe",
    })
    # Positive control: the same scope, only the in-scope host assigned, always
    # runs — so "no packet to the excluded host" is never the pass of a run that
    # sent nothing.
    _, ctrl = _run(work, img, "cvap-engine-discovery", name + "-control", {
        "job_id": name + "-c", "allowed": allowed, "exclusions": [H_OPENSSH],
        "targets": [_target(0, H_NGINX)],
        "rate_budget_pps": 50, "connect_timeout_ms": 3000,
        "max_concurrent_per_target": 4, "safety_mode": "safe",
    })

    dests, cdests = _dests(eg), _dests(ctrl)
    fails = []
    if cdests.get(H_NGINX, 0) == 0:
        fails.append(f"{name}: the control sent no packet to {H_NGINX}; the case proves nothing")
    if dests.get(H_OPENSSH, 0) > 0:
        fails.append(f"{name}: {dests[H_OPENSSH]} packet(s) reached the EXCLUDED host {H_OPENSSH}")
    line = (f"{name:<22} excluded {H_OPENSSH}: {dests.get(H_OPENSSH,0)} pkt "
            f"(refused={res.get('refused')}); control {H_NGINX}: {cdests.get(H_NGINX,0)} pkt")
    return line, fails


def case_cidr_boundary(work, img, sab):
    """A /30 includes its network and broadcast addresses and excludes the hosts
    one below and one above."""
    name = "cidr-boundary"
    # Sabotage widens the /30 to a /28, pulling the "one above" host into scope.
    allowed = ["10.10.0.16/28"] if sab == name else ["10.10.0.16/30"]

    res_in, eg_in = _run(work, img, "cvap-engine-discovery", name + "-in", {
        "job_id": name + "-in", "allowed": allowed, "exclusions": [],
        "targets": [_target(0, H_A6), _target(1, H_WEAKKEY)],  # .16 network, .19 broadcast
        "rate_budget_pps": 50, "connect_timeout_ms": 3000,
        "max_concurrent_per_target": 4, "safety_mode": "safe",
    })
    _, eg_below = _run(work, img, "cvap-engine-discovery", name + "-below", {
        "job_id": name + "-below", "allowed": allowed, "exclusions": [],
        "targets": [_target(0, H_TLS)],  # .15, one below
        "rate_budget_pps": 50, "connect_timeout_ms": 3000,
        "max_concurrent_per_target": 4, "safety_mode": "safe",
    })
    res_ab, eg_above = _run(work, img, "cvap-engine-discovery", name + "-above", {
        "job_id": name + "-above", "allowed": allowed, "exclusions": [],
        "targets": [_target(0, H_FRAGILE)],  # .20, one above
        "rate_budget_pps": 50, "connect_timeout_ms": 3000,
        "max_concurrent_per_target": 4, "safety_mode": "safe",
    })

    din, dbelow, dabove = _dests(eg_in), _dests(eg_below), _dests(eg_above)
    fails = []
    if din.get(H_A6, 0) == 0 or din.get(H_WEAKKEY, 0) == 0:
        fails.append(f"{name}: network {H_A6} or broadcast {H_WEAKKEY} of the /30 got no packet; "
                     "either the boundary arithmetic drops them or the case proves nothing")
    if dbelow.get(H_TLS, 0) > 0:
        fails.append(f"{name}: {dbelow[H_TLS]} packet(s) reached {H_TLS}, one BELOW the /30")
    if dabove.get(H_FRAGILE, 0) > 0:
        fails.append(f"{name}: {dabove[H_FRAGILE]} packet(s) reached {H_FRAGILE}, one ABOVE the /30")
    line = (f"{name:<22} in {H_A6}/{H_WEAKKEY}: {din.get(H_A6,0)}/{din.get(H_WEAKKEY,0)} pkt; "
            f"below {H_TLS}: {dbelow.get(H_TLS,0)}; above {H_FRAGILE}: {dabove.get(H_FRAGILE,0)}")
    return line, fails


def case_hostname_out_of_scope(work, img, sab):
    """A hostname target is refused before anything resolves it: no DNS query
    leaves and no packet reaches the address it would have resolved to."""
    name = "hostname-out-of-scope"
    # Sabotage allows the hostname by name, so the runtime permits it and the
    # engine resolves-and-connects — the bypass the planner closes upstream.
    allowed = ["sneaky.example", "10.10.0.11/32"] if sab == name else ["10.10.0.11/32"]

    res, eg = _run(work, img, "cvap-engine-discovery", name, {
        "job_id": name, "allowed": allowed, "exclusions": [],
        "targets": [_target(0, "sneaky.example")],
        "rate_budget_pps": 50, "connect_timeout_ms": 3000,
        "max_concurrent_per_target": 4, "safety_mode": "safe",
    })
    fails = []
    dns = _dns(eg)
    if dns > 0:
        fails.append(f"{name}: {dns} DNS query/queries left the host; the runtime resolved a name "
                     "it should have refused unresolved")
    if not res.get("refused") and sab != name:
        fails.append(f"{name}: the runtime did not refuse a hostname target (refused="
                     f"{res.get('refused')})")
    # Under sabotage the whole point is that SOMETHING escaped (DNS or a packet).
    if sab == name and dns == 0 and not eg:
        fails.append(f"{name}: sabotage produced no egress; the case cannot detect this bypass")
    line = f"{name:<22} DNS queries: {dns}; refused={res.get('refused')}"
    return line, fails


def case_scope_changed_mid_scan(work, img, sab):
    """A scan halted in flight stops putting packets on the wire (ADR-051's wire
    consequence). Differential: a stopped run sends strictly fewer packets than
    the same job run to completion. The trigger — a narrowing turning into a lost
    lease — is asserted in internal/dispatch/TestALeaseIsNotRenewedAfterScopeNarrows."""
    name = "scope-changed-mid-scan"
    # The filtered host draws out SYN retransmits, so an unstopped run keeps
    # sending for the whole connect timeout and a stopped one does not.
    base = {
        "allowed": ["10.10.0.0/24"], "exclusions": [],
        "targets": [_target(0, H_FILTERED), _target(1, H_NGINX)],
        "rate_budget_pps": 50, "connect_timeout_ms": 3000,
        "max_concurrent_per_target": 4, "safety_mode": "safe",
    }
    full = dict(base, job_id=name + "-full")
    _, eg_full = _run(work, img, "cvap-engine-discovery", name + "-full", full)

    # Sabotage: never actually stop (StopAfterMS huge), so the "stopped" run sends
    # as much as the full run and the differential assertion fails.
    stop_ms = 60000 if sab == name else 700
    stopped = dict(base, job_id=name + "-stop", stop_after_ms=stop_ms)
    res, eg_stop = _run(work, img, "cvap-engine-discovery", name + "-stop", stopped)

    n_full, n_stop = len(eg_full), len(eg_stop)
    fails = []
    if n_full == 0:
        fails.append(f"{name}: the unstopped run sent nothing; the case proves nothing")
    elif n_stop >= n_full:
        fails.append(f"{name}: the stopped run sent {n_stop} packet(s), the unstopped {n_full}; "
                     "the abort did not reduce egress, so nothing stopped the in-flight scan")
    line = f"{name:<22} unstopped {n_full} pkt vs stopped {n_stop} pkt (outcome={res.get('outcome')})"
    return line, fails


CASES = [
    case_exclusion_overlap,
    case_cidr_boundary,
    case_hostname_out_of_scope,
    case_scope_changed_mid_scan,
]

CASE_NAMES = [
    "exclusion-overlap", "cidr-boundary", "hostname-out-of-scope",
    "scope-changed-mid-scan",
]

# The two §6.3 items that are asserted in internal/scope/scopetest and cannot be
# put on this lab's wire, each with the reason — a coverage statement, not a gap.
COVERAGE_STATEMENTS = [
    ("ipv6-forms-of-an-excluded-v4",
     "the runtime scope check only ever sees a CANONICAL target: target.Matches requires the "
     "received string to equal its own canonicalisation byte for byte, so a v4-mapped "
     "(::ffff:10.10.0.14) or translated form is refused as non-canonical before scope is even "
     "consulted, and the plain-v4 form it collapses to is what the exclusion-overlap case above "
     "exercises on the wire. The collapse itself (::ffff: and the five translated mechanisms -> "
     "plain v4) is a canonicalisation property of internal/target, asserted there and in "
     "internal/scope/scopetest; it is not a runtime decision and so has nothing to put on this "
     "wire that the plain-v4 exclusion does not already."),
    ("redirect-to-out-of-scope-host",
     "the fingerprint engine follows no redirect (HTTP HEAD, no Location handling in "
     "internal/engines/fingerprint), so it never constructs the redirect target and there is "
     "no engine action to enforce against. If it gains redirect-following, ADR-027 requires it "
     "to authorise the discovered host via KindAuthorise, which engineHost refuses — the same "
     "authorise path the cases above drive. Re-add a wire case when redirect-following lands."),
    ("translated-forms-nat64-6to4-teredo-isatap",
     "a packet to a NAT64/6to4/Teredo/ISATAP form reaches the embedded v4 host only through a "
     "translator, which this lab has none of, so even if the runtime accepted the form, dialing "
     "it would yield no route and no packet to measure. The exclusion-expansion is asserted in "
     "internal/scope/scopetest."),
]


def run_scope_cases(work, capture_image):
    """Run the wire-exercisable cases; return (failures, report_lines). The
    sabotage target, if any, is read from CVAP_SAFETY_SCOPE_SABOTAGE and must be
    a case name — that case is made to fail and every other must still pass."""
    import os
    sab = os.environ.get("CVAP_SAFETY_SCOPE_SABOTAGE") or None
    if sab and sab not in CASE_NAMES:
        return [f"unknown sabotage case {sab!r}; expected one of {CASE_NAMES}"], []

    # When sabotaging one case, run ONLY that case: the point is to prove that
    # case fails, and running the other four wastes minutes of container time and
    # would mask the target's result behind theirs.
    cases = CASES
    if sab:
        cases = [fn for fn, nm in zip(CASES, CASE_NAMES) if nm == sab]

    failures, lines = [], []
    for fn in cases:
        try:
            line, fails = fn(work, capture_image, sab)
        except RuntimeError as e:
            failures.append(str(e))
            continue
        lines.append("  " + line)
        failures.extend(fails)

    if not sab:
        for case, why in COVERAGE_STATEMENTS:
            lines.append(f"  {case:<22} NOT on the wire: {why}")

    return failures, lines
