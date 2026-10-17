"""The R2-D gate: the Scan Point kernel packet ceiling (ADR-110), measured at the wire.

Imported by safety_gate.py. The invariant under test:

    for every interval of length D, packets leaving the Scan Point's network
    namespace, other than TCP to the Core endpoints E,  <=  B + R * D
    with R = 1000 packets/s and B = 100 packets

It is the kernel's: a tc `police` action the network-policy holder
(deploy/netpolicy) installs on every egress interface. Nothing here enforces
anything; the gate builds the real holder, puts a Scan Point stand-in with no
capabilities into its namespace (`--network container:<holder>`), drives
hostile traffic through it, and judges what left from OUTSIDE.

The verdict is the WIRE. Captured on the host side of the namespace's veth,
`-Q in`, every packet the namespace emits whatever its destination - ARP, ICMP,
RSTs for sockets that are gone, traffic to Core - and the non-Core remainder is
held to B + R*D in every window from 1 ms to 3 s. The policer's counters are
reported beside it but never decide anything: tc charges once per BUFFER and
the wire carries PACKETS, and R2-D's validation found the two can differ - one
UDP_SEGMENT buffer left as up to 64 packets. The ADR-110 preconditions are what
make a buffer one packet, so the gate checks them itself (never by asking the
holder) and attacks each:

  P1 segmentation: gso_max_segs 1, gso_max_size <= MTU, every TX segmentation,
     scatter-gather and GRO feature off, on every egress interface;
  P2 the shared police action (R, B, drop) on every egress interface, the
     fail-closed nftables guard, and exactly the policy's filter set: Core
     exclusions, TCP/ICMP/ICMPv6/ARP into the policer, a final catch-all drop;
  P3 no capabilities at all in the Scan Point: effective, permitted,
     inheritable, bounding and ambient sets empty, no_new_privs set;
  P4 the Core exclusions are exactly E;
  P5 forwarding off, IPv4 and IPv6, everywhere in the namespace;
and, beside them, Core is never a scan target (the runtime refuses it).

Hostile traffic: TCP at 1/5/10/20 connections (bulk writes to a sink, peer-driven
ACK storms, RSTs after close), UDP_SEGMENT, large UDP (IP fragments), raw
AF_PACKET frames with PACKET_QDISC_BYPASS; a lowered ceiling that must bite;
and the fingerprint corpus run from inside the policed namespace, which must
identify and evidence exactly what it does outside one. Each precondition
broken in turn (CVAP_SAFETY_R2D_SABOTAGE) must fail this gate.
"""

import base64
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
NET = "cvap-lab_segment-a"
NET_B = "cvap-lab_segment-b"
PEER = "10.10.0.200"            # the hostile peer: in lab/scope.txt, not a lab target
CORE = "10.10.0.11"             # stands in for Core: E is two of its ports
E = [(CORE, 8443), (CORE, 8444)]
R, B = 1000, 100                # ADR-110
LOW_R, LOW_B = 20, 5            # the deliberately lowered ceiling
HOLDER_IMAGE = "cvap-netpolicy:gate"
HOLDER, SP, PEERC, CAP = "cvap-r2d-holder", "cvap-r2d-sp", "cvap-r2d-peer", "cvap-r2d-cap"
HOSTILE = "9003,9006,9021,9016,9007,9008,9001,9004,9030"
WINDOWS_MS = [1, 10, 100, 1000, 3000]
SABOTAGE = os.environ.get("CVAP_SAFETY_R2D_SABOTAGE") or None
SABOTAGES = ["gso-segs", "seg-feature", "forwarding", "udp-default-deny", "udp-allowed", "netraw",
             "other-cap", "unpoliced-iface", "wide-exclusion", "core-target", "core-target-other-refusal",
             "guard-flushed", "guard-arp-removed", "root-qdisc", "exempt-not-refused", "rate-raised",
             "sp-root", "name-keyed-guard", "holder-self-verify", "holder-no-retry", "holder-lists-down"]
# Sabotages that break the namespace's state after a correct start. The real
# holder re-verifies at most every 5 s and EXITS on what they break - the right
# outcome, measured by holder-self-verify - so under the real holder the gate
# would find a dead container, not a broken precondition. They run against the
# stalled holder (set up correctly, then never re-verifies), so what must catch
# them is the gate's own checker.
STATE_SABOTAGES = {"gso-segs", "seg-feature", "forwarding", "udp-default-deny", "udp-allowed", "unpoliced-iface",
                   "wide-exclusion", "guard-flushed", "guard-arp-removed", "root-qdisc"}
PEER_B = "10.20.0.200"          # the hostile peer's second address, on segment-b
HOLDER_IMAGE_NAMED = "cvap-netpolicy:gate-name-keyed"   # the pre-fix holder, for one sabotage only
HOLDER_IMAGE_STALLED = "cvap-netpolicy:gate-stalled"     # a holder whose loop never re-attaches, for one sabotage only
HOLDER_IMAGE_NORETRY = "cvap-netpolicy:gate-no-retry"    # a holder that exits when an interface vanishes mid-pass, for one sabotage only
HOLDER_IMAGE_LISTSDOWN = "cvap-netpolicy:gate-lists-down"  # a holder that treats a DOWN interface as one to verify, for one sabotage only
MIN_LOWERED_FAILURES = 35       # LOW_B + LOW_R*3 = 65 packets fit the 3 s dial timeout; 100 dials
FORWARDING_OFF = ["net.ipv4.ip_forward=0", "net.ipv4.conf.all.forwarding=0", "net.ipv4.conf.default.forwarding=0",
                  "net.ipv6.conf.all.forwarding=0", "net.ipv6.conf.default.forwarding=0"]
SEG_FEATURES = re.compile(r"^\s*(tcp-segmentation-offload|generic-segmentation-offload|generic-receive-offload|"
                          r"scatter-gather|tx-[a-z0-9_-]*segmentation|tx-gso-list|tx-scatter-gather[a-z-]*|"
                          r"rx-gro-list|rx-udp-gro-forwarding): on", re.M)
# The allowed protocols, each into the shared policer, and the final drop: the
# policy the holder must install, restated here so the gate does not take the
# holder's word for it.
ALLOWED = {(10, "ip", "flower", "tcp"), (11, "ip", "flower", "icmp"), (12, "ipv6", "flower", "tcp"),
           (13, "ipv6", "flower", "icmpv6"), (14, "arp", "matchall", None)}
DENY_PREF = 100
# The non-TCP hostile cases: (name, r2dnontcp arguments). Every one must put
# nothing on the wire.
NONTCP = [("udpseg-1x64", ["-mode=udpseg", "-gso=1", "-segs=64"]),
          ("udpseg-100x64", ["-mode=udpseg", "-gso=100", "-segs=64"]),
          ("udpseg-1400x40", ["-mode=udpseg", "-gso=1400", "-segs=40"]),
          ("udpfrag-8000", ["-mode=udpfrag", "-size=8000"]),
          ("raw-bypass", ["-mode=raw"])]


def _sh(*a, check=False, **k):
    r = subprocess.run(list(a), capture_output=True, text=True, **k)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(a[:6])}...: {r.stderr.strip()[-400:]}")
    return r


def _rm(*names):
    for n in names:
        _sh("docker", "rm", "-f", n)


def _build_holder():
    r = _sh("docker", "build", "-q", "-t", HOLDER_IMAGE, str(ROOT / "deploy" / "netpolicy"))
    if r.returncode != 0:
        raise RuntimeError("could not build the network-policy holder image: " + r.stderr[-400:])


def _start_holder(rate, burst, every=1, image=HOLDER_IMAGE, expect_ready=True, extra_env=()):
    """Start the holder as INSTALL §6a says: NET_ADMIN and nothing else, no new
    privileges, forwarding off by sysctl. Returns True when it reported ready;
    with expect_ready=False a refusal to start is the expected outcome and the
    holder's exit status and last log line are returned instead."""
    _rm(HOLDER)
    eps = ",".join(f"{ip}:{port}" for ip, port in E)
    sysctls = [x for s in FORWARDING_OFF for x in ("--sysctl", s)]
    env = [x for kv in extra_env for x in ("-e", kv)]
    _sh("docker", "run", "-d", "--name", HOLDER, "--network", NET, "--cap-drop", "ALL", "--cap-add", "NET_ADMIN",
        "--security-opt", "no-new-privileges", *sysctls,
        "-e", f"CVAP_NP_CORE_ENDPOINTS={eps}", "-e", f"CVAP_NP_RATE_PPS={rate}",
        "-e", f"CVAP_NP_BURST={burst}", "-e", f"CVAP_NP_VERIFY_SECONDS={every}", *env, image, check=True)
    for _ in range(40):
        if "ready:" in _sh("docker", "logs", HOLDER).stdout:
            return True
        if _sh("docker", "inspect", "-f", "{{.State.Status}}", HOLDER).stdout.strip() == "exited":
            break
        time.sleep(0.25)
    if expect_ready:
        raise RuntimeError("the holder never became ready: " + _sh("docker", "logs", HOLDER).stderr[-400:])
    return False


def _holder_exit():
    st = _sh("docker", "inspect", "-f", "{{.State.Status}} {{.State.ExitCode}}", HOLDER).stdout.split()
    last = (_sh("docker", "logs", HOLDER).stderr.strip().splitlines() or [""])[-1]
    return (st + ["?", "?"])[:2], last


def _holder_self_verify(work, fails, lines):
    """The real holder's fail-closed path, measured: break its filter set and
    it must exit within two of its (<= 5 s) cycles, saying why, and the Scan
    Point sharing its namespace must be left with loopback only. Both outcomes
    are reported as findings so the sabotage loop sees a failure either way;
    the text says which it was."""
    _sh("docker", "exec", HOLDER, "tc", "filter", "del", "dev", "eth0", "egress", "pref", str(DENY_PREF), check=True)
    t0 = time.time()
    while time.time() - t0 < 12:
        if _sh("docker", "inspect", "-f", "{{.State.Status}}", HOLDER).stdout.strip() == "exited":
            break
        time.sleep(0.25)
    (st, code), last = _holder_exit()
    took = time.time() - t0
    sp_ifs = _sh("docker", "exec", SP, "ls", "/sys/class/net").stdout.split()
    lines.append(f"  holder-self-verify  holder {st} exit={code} after {took:.1f}s: {last[:110]}; Scan Point interfaces now {sp_ifs}")
    if st != "exited":
        fails.append(f"  r2d holder-self-verify: the holder did NOT exit within {took:.0f}s of its catch-all drop being removed; "
                     f"fail-closed did not hold (status {st}, last log: {last[:120]})")
        return
    fails.append(f"  r2d holder-self-verify: (expected) the holder exited {took:.1f}s after its filter set was broken: {last[:120]}")
    if sp_ifs != ["lo"]:
        fails.append(f"  r2d holder-self-verify: the holder exited but the Scan Point still has {sp_ifs}; it must be left with "
                     "loopback only (ADR-110)")


def _build_variant_holder(tag, transform):
    """A holder image built from the CURRENT script with one deliberate change
    put in by `transform`, so a sabotage runs against the defect itself rather
    than against a checker. The production image and script are untouched."""
    src = (ROOT / "deploy" / "netpolicy" / "netpolicy.sh").read_text()
    old = transform(src)
    assert old != src, "the variant transform changed nothing; the sabotage would test the fixed holder"
    d = pathlib.Path(tempfile.mkdtemp(prefix="np-variant-"))
    shutil.copy(ROOT / "deploy" / "netpolicy" / "Dockerfile", d / "Dockerfile")
    (d / "netpolicy.sh").write_text(old)
    r = _sh("docker", "build", "-q", "-t", tag, str(d))
    shutil.rmtree(d, ignore_errors=True)
    if r.returncode != 0:
        raise RuntimeError(f"could not build the {tag} holder image: " + r.stderr[-400:])


def _build_stalled_holder():
    """A holder that sets up correctly and then never runs `attach` again: an
    interface connected after start stays unpoliced for as long as the holder
    lives. Models a stalled holder; used by the unpoliced-iface sabotage, where
    the GATE must notice and the guard must hold, deterministically - the real
    holder would police the interface within its 5 s cycle and win the race."""
    def stall(src):
        a = '\t\tsleep "$EVERY"\n\t\tattach\n'
        assert src.count(a) == 1, "the hold loop is not where this transform expects it"
        return src.replace(a, "\t\tsleep 3600\n")
    _build_variant_holder(HOLDER_IMAGE_STALLED, stall)


def _build_no_retry_holder():
    """The holder as it was before the mid-pass fix: a verify pass that fails
    because an interface vanished under it is fatal at once (MAX_PASSES 0), so a
    `docker network disconnect` landing inside a pass took the holder - and the
    Scan Point's network - down. Built from the current script with that one
    number put back."""
    def no_retry(src):
        a = "MAX_PASSES=5\n"
        assert src.count(a) == 1, "MAX_PASSES is not where this transform expects it"
        return src.replace(a, "MAX_PASSES=0\n")
    _build_variant_holder(HOLDER_IMAGE_NORETRY, no_retry)


def _build_lists_down_holder():
    """The holder as it was before the DOWN-interface fix: `ifaces` lists every
    interface but loopback, DOWN ones included, so an interface that arrives
    DOWN and stays DOWN for longer than a cycle (Docker's move-in, rename and
    bring-up are separate steps; measured more than a second apart under
    daemon load) fails verification on a set that did not change, and the
    holder exits. Built from the current script with that one line put back."""
    def lists_down(src):
        a = '\t\t[ $((f & 1)) -eq 1 ] || continue\n'
        assert src.count(a) == 1, "the UP test in listing is not where this transform expects it"
        return src.replace(a, "")
    _build_variant_holder(HOLDER_IMAGE_LISTSDOWN, lists_down)


def _build_name_keyed_holder():
    """The holder as it was before the reconnect fix: guard set keyed by
    interface NAME. Built from the current script with that one change put
    back, so the reconnect regression case proves the fix and not the checker."""
    def name_keyed(src):
        # Every target must be present the known number of times: str.replace is
        # silent on a missing one, and a silently unmatched lookup line once built
        # a holder with a name-keyed set and index-keyed lookups, which exited on
        # its first verify pass instead of exercising the reconnect leak.
        def sub(text, a, b, n):
            assert text.count(a) == n, f"{a!r} occurs {text.count(a)}x, not {n}x; the name-keyed transform drifted from the script"
            return text.replace(a, b)
        old = sub(src, "type iface_index;", "type ifname;", 2)
        old = sub(old, 'oif "lo" accept', 'oifname "lo" accept', 1)
        old = sub(old, "oif @policed accept", "oifname @policed accept", 2)
        # name-keyed: add/get/delete by quoted name, never prune, never check indices
        old = sub(old, 'nft add element inet cvap_netpolicy policed "{ $idx }"', 'nft add element inet cvap_netpolicy policed "{ \\"$dev\\" }"', 1)
        old = sub(old, 'nft add element arp cvap_netpolicy policed "{ $idx }"', 'nft add element arp cvap_netpolicy policed "{ \\"$dev\\" }"', 1)
        old = sub(old, 'in_policed() { nft get element inet cvap_netpolicy policed "{ $1 }" >/dev/null 2>&1; }',
                  'in_policed() { nft get element inet cvap_netpolicy policed "{ \\"$1\\" }" >/dev/null 2>&1; }', 1)
        old = sub(old, 'in_policed "$idx" || police_iface "$dev"', 'in_policed "$dev" || police_iface "$dev"', 1)
        old = sub(old, 'in_policed "$idx" || die "$dev (ifindex $idx) is not in the policed set"',
                  'in_policed "$dev" || die "$dev is not in the policed set"', 1)
        old = sub(old, "\tprune\n", "\n", 1)
        old = sub(old, "for e in $(policed_indices); do", "for e in; do", 2)  # no stale-index check either
        assert "type ifname;" in old and "oifname @policed" in old and 'in_policed "$idx"' not in old
        return old
    _build_variant_holder(HOLDER_IMAGE_NAMED, name_keyed)


def _start_sp(work, image, extra_cap=None, root=False):
    """The Scan Point stand-in: shares the holder's namespace, nonroot, every
    capability dropped, no_new_privs - the shape ADR-110 requires of a real
    Scan Point. extra_cap/root exist only to sabotage that shape."""
    _rm(SP)
    caps = ["--cap-drop", "ALL"] + (["--cap-add", extra_cap] if extra_cap else [])
    user = "0:0" if root else "65532:65532"
    _sh("docker", "run", "-d", "--name", SP, "--network", f"container:{HOLDER}", *caps,
        "--security-opt", "no-new-privileges", "--user", user,
        "-v", f"{work}:/w", "--entrypoint", "sleep", image, "3600", check=True)


def _start_peer(work, image):
    _rm(PEERC)
    _sh("docker", "run", "-d", "--name", PEERC, "--network", NET, "--ip", PEER, "--cap-add", "NET_ADMIN",
        "-v", f"{work}:/w", image, "sh", "-c",
        "ethtool -K eth0 tso off gso off gro off >/dev/null 2>&1; exec /w/hostilepeer", check=True)
    # A second leg on segment-b: hostilepeer listens on every address, so the
    # same peer answers the Scan Point's second interface.
    _sh("docker", "network", "connect", "--ip", PEER_B, NET_B, PEERC, check=True)
    time.sleep(1)


def _host_veth(image, dev="eth0"):
    idx = _sh("docker", "exec", HOLDER, "cat", f"/sys/class/net/{dev}/iflink", check=True).stdout.strip()
    links = _sh("docker", "run", "--rm", "--network", "host", image, "ip", "-o", "link", check=True).stdout
    for line in links.splitlines():
        num, name = line.split(":", 2)[:2]
        if num.strip() == idx:
            return name.strip().split("@")[0]
    raise RuntimeError(f"no host interface with ifindex {idx}")


def _capture_start(work, image, veth, phase, name=CAP):
    """Capture everything the namespace emits through one host-side veth. A
    second capture (name=CAP2) runs beside it for the two-interface cases."""
    _rm(name)
    _sh("docker", "run", "-d", "--name", name, "--network", "host", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
        "-v", f"{work}:/w", image, "sh", "-c",
        f"tcpdump -i {veth} -Q in -nn -e -B 65536 --time-stamp-precision=nano -w /w/out/r2d-{phase}.pcap "
        f"2>/w/out/r2d-{phase}.err", check=True)
    time.sleep(1.5)


CAP2 = "cvap-r2d-cap2"


def _dest_capture_start(work, image, phase, dest=None):
    """Capture inside the PEER's namespace, on the interface that holds PEER_B:
    what the namespace sends to the peer's second address, whichever of the
    Scan Point's interfaces (new, old, policed or not) it came through.

    Not a bystander on the bridge: a Linux bridge forwards unicast only to the
    learned port, and a third container on segment-b saw 0 of 200 datagrams the
    destination received (measured). The destination's own interface is the one
    place that provably sees them, and _capture_sees_traffic proves the point
    each run."""
    dest = dest or PEER_B
    dev = _sh("docker", "exec", PEERC, "sh", "-c", f"ip -o -4 addr show | awk '/{dest}\\//{{print $2}}'",
              check=True).stdout.strip()
    if not dev:
        raise RuntimeError(f"the peer has no interface holding {dest}")
    _rm(CAP2)
    _sh("docker", "run", "-d", "--name", CAP2, "--network", f"container:{PEERC}", "--cap-add", "NET_RAW",
        "--cap-add", "NET_ADMIN", "-v", f"{work}:/w", image, "sh", "-c",
        f"tcpdump -i {dev} -nn -e -B 65536 --time-stamp-precision=nano -w /w/out/r2d-{phase}.pcap "
        f"'dst host {dest}' 2>/w/out/r2d-{phase}.err", check=True)
    time.sleep(1.5)


def _capture_sees_traffic(work, image, fails, lines, tag):
    """The positive control for the destination capture: through a POLICED
    second interface, TCP (allowed) to PEER_B must be seen by the same capture
    point the denied-protocol cases use. A capture point that sees nothing
    here would make those cases pass whatever leaked."""
    _dest_capture_start(work, image, f"capture-control{tag}")
    r = _sh("docker", "exec", SP, "/w/r2dload", f"-host={PEER_B}", "-ports=9030", "-n=1", "-dur=1s")
    time.sleep(1)
    text, _ = _capture_stop(work, image, f"capture-control{tag}", name=CAP2)
    tcp = [p for p in _parse(text) if p[1] == "tcp"]
    lines.append(f"  capture-control{tag} TCP packets to {PEER_B} seen at the destination through the policed eth1: {len(tcp)}")
    if len(tcp) < 3:
        fails.append(f"  r2d capture-control{tag}: the destination capture saw {len(tcp)} TCP packet(s) from a connection "
                     "that should have produced several; the reconnect/unpoliced verdicts rest on this capture point")


def _capture_stop(work, image, phase, name=CAP):
    _sh("docker", "exec", name, "pkill", "-INT", "tcpdump")
    time.sleep(1)
    _rm(name)
    err = (work / "out" / f"r2d-{phase}.err").read_text()
    m = re.search(r"(\d+) packets? dropped by kernel", err)
    dropped = int(m.group(1)) if m else None
    text = _sh("docker", "run", "--rm", "-v", f"{work}:/w", image, "sh", "-c",
               f"tcpdump -nn -e -tt --time-stamp-precision=nano -r /w/out/r2d-{phase}.pcap 2>/dev/null").stdout
    return text, dropped


PKT = re.compile(r"^(\d+)\.(\d+) .*?IPv4.*?: (\S+?)\.(\d+) > (\S+?)\.(\d+): Flags \[([^\]]*)\](.*?)length (\d+)")
ICMP = re.compile(r"^(\d+)\.(\d+) .*?IPv4.*?: (\S+) > (\S+): ICMP")
ANY = re.compile(r"^(\d+)\.(\d+) ")


def _parse(text):
    """Every captured packet as (ts_ns, kind, dst, dport, sport, flags, length, seq).
    kind: tcp | icmp | arp | udp | raw | other. Each line is one packet leaving
    the namespace."""
    out = []
    for line in text.splitlines():
        m = ANY.match(line)
        if not m:
            continue
        ts = int(m.group(1)) * 1_000_000_000 + int(m.group(2).ljust(9, "0")[:9])
        t = PKT.match(line)
        if t:
            _, _, src, sp, dst, dp, fl, mid, ln = t.groups()
            sq = re.search(r"seq (\d+):(\d+)", mid)
            out.append((ts, "tcp", dst, int(dp), int(sp), fl, int(ln), sq.group(0) if sq else None))
        elif ICMP.match(line):
            out.append((ts, "icmp", ICMP.match(line).group(4), 0, 0, "", 0, None))
        elif " ARP" in line or "ethertype ARP" in line:
            out.append((ts, "arp", "", 0, 0, "", 0, None))
        elif ": UDP" in line or "proto UDP" in line or "ip-proto-17" in line:
            out.append((ts, "udp", "", 0, 0, "", 0, None))
        elif "0x88b5" in line:
            out.append((ts, "raw", "", 0, 0, "", 0, None))
        else:
            out.append((ts, "other", "", 0, 0, "", 0, None))
    return out


def _is_core(p):
    return p[1] == "tcp" and (p[2], p[3]) in E


def _max_window(ts, w_ns):
    best, j = 0, 0
    for i in range(len(ts)):
        while ts[i] - ts[j] >= w_ns:
            j += 1
        best = max(best, i - j + 1)
    return best


def _classes(pkts, conns):
    c = {"syn": 0, "handshake_ack": 0, "data": 0, "data_retransmit": 0, "ack": 0, "fin": 0, "rst": 0,
         "icmp": 0, "arp": 0, "udp": 0, "raw": 0, "other": 0, "after_own_close": 0}
    closes = {r["local_port"]: r["close_ns"] for r in conns if r.get("local_port")}
    seen, acked = {}, set()
    for p in pkts:
        ts, kind, dst, dp, sp, fl, ln, sq = p
        if kind != "tcp":
            c[kind] += 1
            continue
        if sp in closes and ts > closes[sp]:
            c["after_own_close"] += 1
        if fl == "S":
            c["syn"] += 1
        elif "R" in fl:
            c["rst"] += 1
        elif ln > 0:
            s = seen.setdefault(sp, set())
            if sq in s:
                c["data_retransmit"] += 1
            else:
                s.add(sq)
                c["data"] += 1
        elif "F" in fl:
            c["fin"] += 1
        elif sp not in acked:
            acked.add(sp)
            c["handshake_ack"] += 1
        else:
            c["ack"] += 1
    return c


def _police():
    """The policer's own counters: supporting evidence only. `packets` counts
    the segments of each buffer, `drops` counts buffers, and the bucket
    charges buffers - none of them is the wire."""
    a = json.loads(_sh("docker", "exec", HOLDER, "tc", "-s", "-j", "actions", "get", "action", "police",
                       "index", "1", check=True).stdout)
    st = next(x for x in a if "actions" in x)["actions"][0]["stats"]
    return st["packets"], st["drops"]


def _filter_key(x):
    """One tc filter, normalised: (pref, protocol, kind, keys, action)."""
    o = x.get("options") or {}
    acts = o.get("actions") or []
    if len(acts) != 1:
        act = f"actions:{len(acts)}"
    elif acts[0].get("kind") == "police":
        act = f"police{acts[0].get('index')}"
    else:
        act = acts[0].get("control_action", {}).get("type")
    keys = {k: v for k, v in (o.get("keys") or {}).items()}
    return x.get("pref"), x.get("protocol"), x.get("kind"), keys, act


def _expected_filters():
    want = []
    for ip, port in E:
        fam = "ipv6" if ":" in ip else "ip"
        want.append((1, fam, "flower", {"eth_type": "ipv6" if fam == "ipv6" else "ipv4", "ip_proto": "tcp",
                                        "dst_ip": ip, "dst_port": port}, "pass"))
    for pref, proto, kind, ipp in sorted(ALLOWED):
        keys = {"eth_type": "ipv4" if proto == "ip" else "ipv6", "ip_proto": ipp} if kind == "flower" else {}
        want.append((pref, proto, kind, keys, "police1"))
    want.append((DENY_PREF, "all", "matchall", {}, "drop"))
    return sorted(want, key=repr)


def preconditions(rate, burst):
    """The gate's OWN check of ADR-110's preconditions - never the holder's
    `verify`, so a holder that lies about itself is still caught."""
    fails = []
    ifs = _sh("docker", "exec", HOLDER, "sh", "-c", "ls /sys/class/net").stdout.split()
    ifs = [i for i in ifs if i != "lo"]
    if not ifs:
        fails.append("P2: the namespace has no egress interface at all")
    act = json.loads(_sh("docker", "exec", HOLDER, "tc", "-j", "actions", "get", "action", "police", "index", "1").stdout or "[]")
    pol = [x for e in act for x in e.get("actions", []) if x.get("kind") == "police"]
    if not (len(pol) == 1 and pol[0].get("pkts_rate") == rate and pol[0].get("pkts_burst") == burst
            and pol[0].get("control_action", {}).get("type") == "drop"):
        fails.append(f"P2: the shared police action is not pkts_rate {rate} pkts_burst {burst} drop: {pol}")
    want = _expected_filters()
    for dev in ifs:
        # P1: one buffer is one packet.
        on = SEG_FEATURES.findall(_sh("docker", "exec", HOLDER, "ethtool", "-k", dev).stdout)
        if on:
            fails.append(f"P1: {dev}: segmentation/scatter-gather/GRO features still on: {on}")
        link = (json.loads(_sh("docker", "exec", HOLDER, "ip", "-d", "-j", "link", "show", "dev", dev).stdout or "[{}]")
                or [{}])[0]
        mtu = link.get("mtu", 0)
        segs, size, size4 = link.get("gso_max_segs"), link.get("gso_max_size"), link.get("gso_ipv4_max_size", 0)
        if segs != 1 or size is None or size > mtu or size4 > mtu:
            fails.append(f"P1: {dev}: gso_max_segs {segs}, gso_max_size {size}, gso_ipv4_max_size {size4}, "
                         f"mtu {mtu}: not 1 and <= mtu")
        # P1: the root qdisc is the default. A classful or netem root could
        # clone or reorder after classification; only clsact may sit beside it.
        q = sorted(x.get("kind") for x in json.loads(_sh("docker", "exec", HOLDER, "tc", "-j", "qdisc", "show", "dev", dev).stdout or "[]"))
        if q != ["clsact", "noqueue"]:
            fails.append(f"P1: {dev}: qdiscs are {q}, not exactly clsact + noqueue")
        # P2/P4: exactly the policy's filters, in this order, nothing else.
        f = json.loads(_sh("docker", "exec", HOLDER, "tc", "-j", "filter", "show", "dev", dev, "egress").stdout or "[]")
        have = sorted((_filter_key(x) for x in f if x.get("options")), key=repr)
        if have != want:
            extra = [h for h in have if h not in want]
            missing = [w for w in want if w not in have]
            for h in extra:
                tag = "P4" if h[4] == "pass" else "P2"
                fails.append(f"{tag}: {dev}: an egress filter outside the policy: {h}")
            for w in missing:
                tag = "P4" if w[4] == "pass" else "P2"
                fails.append(f"{tag}: {dev}: a filter the policy requires is missing: {w}")
    # P2: the fail-closed guard, exactly: both chains, hooked at output -300
    # with policy accept, an accept for the policed set (and loopback on inet)
    # and a final counted drop; the set keyed by interface INDEX, not name.
    for fam, want in (("inet", ["accept", "accept", "drop"]), ("arp", ["accept", "drop"])):
        j = json.loads(_sh("docker", "exec", HOLDER, "nft", "-j", "list", "chain", fam, "cvap_netpolicy", "out").stdout
                       or '{"nftables":[]}')["nftables"]
        chain = next((x["chain"] for x in j if "chain" in x), None)
        if not chain:
            fails.append(f"P2: the {fam} guard chain is missing")
            continue
        if (chain.get("hook"), chain.get("prio"), chain.get("policy")) != ("output", -300, "accept"):
            fails.append(f"P2: the {fam} guard is hooked {chain.get('hook')} prio {chain.get('prio')} "
                         f"policy {chain.get('policy')}, not output -300 accept")
        verdicts = [next(k for k in ("accept", "drop", "jump", "goto", "return", "queue") if k in e)
                    for x in j if "rule" in x for e in x["rule"]["expr"] if any(k in e for k in ("accept", "drop", "jump", "goto", "return", "queue"))]
        if verdicts != want:
            fails.append(f"P2: the {fam} guard's verdicts are {verdicts}, not {want}")
        if fam == "inet" and not any("rule" in x and any(e.get("match", {}).get("left", {}).get("meta", {}).get("key") == "oif"
                                                        and e["match"].get("right") == "@policed" for e in x["rule"]["expr"]) for x in j):
            fails.append("P2: the inet guard does not accept on `oif @policed`")
        if fam == "inet" and not any("rule" in x and any(e.get("match", {}).get("right") == "lo" for e in x["rule"]["expr"]) for x in j):
            fails.append("P2: the inet guard has no loopback accept")
        settype = json.loads(_sh("docker", "exec", HOLDER, "nft", "-j", "list", "set", fam, "cvap_netpolicy", "policed").stdout
                             or '{"nftables":[]}')["nftables"]
        st = next((x["set"].get("type") for x in settype if "set" in x), None)
        if st != "iface_index":
            fails.append(f"P2: the {fam} policed set is keyed by {st}, not iface_index; a reconnected interface "
                         "reuses its NAME and would be admitted unpoliced")
    # Membership is by index: nft renders an iface_index element as the live
    # interface's name, so ask nft directly for each live interface's index.
    for dev in ifs:
        idx = _sh("docker", "exec", HOLDER, "cat", f"/sys/class/net/{dev}/ifindex").stdout.strip()
        if _sh("docker", "exec", HOLDER, "nft", "get", "element", "inet", "cvap_netpolicy", "policed",
               f"{{ {idx} }}").returncode != 0:
            fails.append(f"P2: {dev} (ifindex {idx}) is not in the guard's policed set")
    # P3: no capability anywhere in the Scan Point, read from the kernel.
    status = _sh("docker", "exec", SP, "sh", "-c",
                 "for f in /proc/[0-9]*/status; do grep -HE '^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs|Uid):' $f; done").stdout
    if not status.strip():
        fails.append("P3: could not read the Scan Point's capability state")
    for line in status.splitlines():
        path, field, val = (line.split(":", 2) + ["", ""])[:3]
        if field == "Uid" and "0" in val.split()[:2]:
            fails.append(f"P3: {path}: runs as root (uid {val.split()[0]}, euid {val.split()[1]})")
            break
    for line in status.splitlines():
        path, field, val = (line.split(":", 2) + ["", ""])[:3]
        val = val.strip()
        if field.startswith("Cap") and int(val, 16) != 0:
            fails.append(f"P3: {path}: {field} is {val}" + (" (NET_RAW)" if int(val, 16) & (1 << 13) else ""))
        if field == "NoNewPrivs" and val != "1":
            fails.append(f"P3: {path}: no_new_privs is not set")
    insp = json.loads(_sh("docker", "inspect", SP).stdout or "[{}]")[0].get("HostConfig", {})
    if insp.get("Privileged") or insp.get("CapAdd"):
        fails.append(f"P3: the Scan Point was granted {insp.get('CapAdd')} privileged={insp.get('Privileged')}")
    # The holder holds NET_ADMIN and nothing else: NET_RAW in the namespace,
    # in any process, is the raw-frame bypass.
    hcaps = _sh("docker", "exec", HOLDER, "grep", "CapEff", "/proc/1/status").stdout.split()
    if len(hcaps) == 2 and int(hcaps[1], 16) != (1 << 12):
        fails.append(f"P3: the holder's effective capabilities are {hcaps[1]}, not NET_ADMIN alone (bit 12)")
    # P5: forwarding off everywhere in the namespace.
    fwd = _sh("docker", "exec", HOLDER, "sh", "-c",
              "grep -H . /proc/sys/net/ipv4/ip_forward /proc/sys/net/ipv4/conf/*/forwarding "
              "/proc/sys/net/ipv6/conf/*/forwarding 2>/dev/null").stdout
    if "ip_forward" not in fwd:
        fails.append("P5: could not read net.ipv4.ip_forward")
    for line in fwd.splitlines():
        if not line.endswith(":0"):
            fails.append(f"P5: forwarding is on: {line}")
    return fails


def _load(work, n, dur="3s"):
    out = _sh("docker", "exec", SP, "/w/r2dload", f"-host={PEER}", f"-ports={HOSTILE}", f"-n={n}",
              f"-dur={dur}").stdout
    return [json.loads(l) for l in out.splitlines() if l.strip()]


def _judge(name, pkts, rate, burst, lines, fails, tc=None, conns=None, extra=""):
    """The verdict: the non-Core packets on the wire against B + R*D."""
    noncore = [p for p in pkts if not _is_core(p)]
    ts = [p[0] for p in noncore]
    wins = {w: _max_window(ts, w * 1_000_000) for w in WINDOWS_MS}
    bounds = {w: burst + rate * w / 1000 for w in WINDOWS_MS}
    errs = sum(1 for c in conns or [] if c.get("err"))
    tcs = f"tc-packets {tc[0]:>6} tc-drops {tc[1]:>5}" if tc else ""
    lines.append(f"  {name:<15} wire {len(noncore):>5} {tcs} failed-conns {errs:>3}  max/bound "
                 + " ".join(f"{w}ms:{wins[w]}/{bounds[w]:g}" for w in WINDOWS_MS) + extra)
    for w in WINDOWS_MS:
        if wins[w] > bounds[w]:
            fails.append(f"  r2d {name}: {wins[w]} packets left the namespace in {w} ms, above {bounds[w]:g} "
                         f"(B + R*D, R={rate} B={burst})")
    return noncore, errs


def _phase(work, image, veth, name, n, rate, burst, lines, fails, expect_enforcement=False):
    p0, d0 = _police()
    _capture_start(work, image, veth, name)
    conns = _load(work, n)
    time.sleep(5)  # anything still leaving the namespace after every close
    p1, d1 = _police()
    text, dropped = _capture_stop(work, image, name)
    if dropped != 0:
        fails.append(f"  r2d {name}: the capture lost packets ({dropped}); nothing it says can be trusted")
    noncore, errs = _judge(name, _parse(text), rate, burst, lines, fails, tc=(p1 - p0, d1 - d0), conns=conns)
    cls = _classes(noncore, conns)
    lines.append(f"  {'':<15} classes {cls}")
    drops = d1 - d0
    if expect_enforcement and not (drops > 0 and errs >= MIN_LOWERED_FAILURES):
        fails.append(f"  r2d {name}: the lowered ceiling produced {drops} drops and {errs} failed connections; "
                     f"the bucket admits at most {LOW_B + LOW_R * 3} packets in the 3 s dial timeout, so at least "
                     f"{MIN_LOWERED_FAILURES} of 100 must fail")
    return cls, drops


def _nontcp(work, image, veth, rate, burst, lines, fails, tag="", user=None):
    """Every non-TCP hostile case: nothing it sends may reach the wire, and the
    wire as a whole stays within B + R*D."""
    for name, args in NONTCP:
        phase = f"{name}{tag}"
        p0, d0 = _police()
        _capture_start(work, image, veth, phase)
        u = ["-u", user] if user else []
        out = _sh("docker", "exec", *u, SP, "/w/r2dnontcp", f"-host={PEER}", *args).stdout.strip()
        time.sleep(2)
        p1, d1 = _police()
        text, dropped = _capture_stop(work, image, phase)
        if dropped != 0:
            fails.append(f"  r2d {phase}: the capture lost packets ({dropped}); nothing it says can be trusted")
        pkts = _parse(text)
        try:
            res = json.loads(out or "{}")
        except ValueError:
            res = {"unparsed": out[:120]}
        leaked = [p for p in pkts if p[1] in ("udp", "raw", "other")]
        _judge(phase, pkts, rate, burst, lines, fails, tc=(p1 - p0, d1 - d0),
               extra=f"  non-TCP on wire {len(leaked)}  sender {res}")
        if leaked:
            fails.append(f"  r2d {phase}: {len(leaked)} packet(s) of a protocol the policy denies reached the wire "
                         f"({sorted({p[1] for p in leaked})}); only TCP, ICMP, ICMPv6 and ARP may leave (ADR-110)")
        if name == "raw-bypass" and not user:
            # P3 on the socket: the Scan Point user must be REFUSED the raw
            # socket, not merely fail to get frames out.
            if "not permitted" not in (res.get("setup_err") or "") or res.get("sent", 0):
                fails.append(f"  r2d {phase}: the raw AF_PACKET socket was not refused to the Scan Point user "
                             f"(setup_err={res.get('setup_err')!r}, sent={res.get('sent')}); P3 requires EPERM")


HTTP_DATE = re.compile(r"Date: [A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT")


def _evidence(p):
    """An observation's payload without what differs run to run whoever sends
    it: timing fields, and the server's own clock in an HTTP Date header
    (measured: two UNPOLICED runs differ in exactly that and nothing else)."""
    if isinstance(p, dict):
        return {k: _evidence(v) for k, v in p.items()
                if not re.search(r"(time|_at$|duration|elapsed|rtt|latency|_ms$|_ns$|observed|job_id|task_id)", k)}
    if isinstance(p, list):
        return [_evidence(v) for v in p]
    if isinstance(p, str):
        return HTTP_DATE.sub("Date: <server clock>", p)
    return p


def _fields(a, b, pre=""):
    """The leaf paths at which two payloads differ, for the failure message."""
    if isinstance(a, dict) and isinstance(b, dict):
        return [f for k in sorted(set(a) | set(b)) for f in _fields(a.get(k), b.get(k), f"{pre}.{k}")]
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        return [f for i, (x, y) in enumerate(zip(a, b)) for f in _fields(x, y, f"{pre}[{i}]")]
    return [] if a == b else [f"{pre}: {str(a)[:50]!r} vs {str(b)[:50]!r}"]


def _fragile():
    """Hosts the golden corpus labels fragile: the ADR-024 rate-limiter fixture,
    which refuses above ~10 requests a minute BY DESIGN, so whichever of two
    back-to-back runs comes second sees different answers. corpus-check leaves
    it out for the same reason; here it is still scanned (its traffic still
    meets the policer) and only left out of the comparison."""
    c = json.loads((ROOT / "lab" / "corpus" / "corpus.json").read_text())
    hosts = c.get("hosts") if isinstance(c, dict) else c
    return {h["address"] for h in hosts or [] if h.get("fragile")}


def _ident(p):
    tls = p.get("tls") or {}
    chain = tls.get("chain") or []
    return {"method": p.get("method"), "service": p.get("service"), "product": p.get("product"),
            "version": p.get("version"), "ssh_fp": (p.get("ssh") or {}).get("fingerprint"),
            "tls": bool(p.get("tls")), "tls_fps": sorted(c.get("fingerprint") for c in chain) or None,
            "tls_version": tls.get("version"), "tls_cipher": tls.get("cipher_suite")}


def _corpus(work, image, corpus, targets, ports):
    # The engine runs DIRECTLY here, without the runtime's refusal, so the Core
    # stand-in is removed by hand: Core is never a scan target (ADR-110), and an
    # 8443 probe at it would be traffic the ceiling exempts.
    targets = [t for t in targets if t != CORE]
    job = {"kind": "job", "job_id": "r2d-corpus",
           "targets": [{"task_id": f"t{i}", "value": v} for i, v in enumerate(targets)],
           "rate_budget_pps": 50, "connect_timeout_ms": 3000, "max_concurrent_per_target": 4,
           "safety_mode": "intrusive", "ports": ports, "probes": corpus["probes"],
           "banner_matches": corpus["banner_matches"], "max_probes_per_port": corpus["max_probes_per_port"]}
    (work / "job-r2d-corpus.json").write_text(json.dumps(job) + "\n")

    def run(cmd):
        ident, evid = {}, {}
        for line in _sh(*cmd).stdout.splitlines():
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("kind") == "observation":
                p = json.loads(base64.b64decode(m["observation"]["payload"]))
                k = f"{p.get('address')}:{p.get('port')}"
                ident[k], evid[k] = _ident(p), _evidence(p)
        return ident, evid

    p0, d0 = _police()
    policed, policed_ev = run(["docker", "exec", SP, "sh", "-c", "/w/cvap-engine-fingerprint < /w/job-r2d-corpus.json"])
    p1, d1 = _police()
    plain, plain_ev = run(["docker", "run", "--rm", "--network", NET, "--user", "65532:65532", "-v", f"{work}:/w",
                           "--entrypoint", "sh", image, "-c", "/w/cvap-engine-fingerprint < /w/job-r2d-corpus.json"])
    fragile = _fragile()
    keys = sorted(k for k in set(policed) | set(plain) if k.rsplit(":", 1)[0] not in fragile)
    return {"n": len(plain), "fragile": sorted(fragile),
            "ident": [f"{k} {_fields(policed.get(k), plain.get(k))[:3]}" for k in keys if policed.get(k) != plain.get(k)],
            "evidence": [f"{k} {_fields(policed_ev.get(k), plain_ev.get(k))[:3]}" for k in keys
                         if policed_ev.get(k) != plain_ev.get(k)],
            "ssh": sum(1 for v in plain.values() if v["ssh_fp"]), "tls": sum(1 for v in plain.values() if v["tls"]),
            "tc": (p1 - p0, d1 - d0)}


# The runtime's Core-target refusal, as engineHost.authorise words it (ADR-110).
# Matching the reason, not just `refused`, is what tells this guard apart from
# every other way a job can be refused (scope, canonicalisation, safety mode).
CORE_REFUSAL = "is, or covers, a Core endpoint address, which is never a scan target (ADR-110)"


def _core_target(work, image, veth, fails, lines, sabotaged):
    """Core is never a scan target, on a wire: a job naming the Core address,
    through the runtime's real send path. The job's scope allows the address,
    so only the Core-target guard can refuse it - and the gate requires that
    the refusal came from that guard, and, separately, that no packet reached
    Core. The sabotage withholds the Core endpoints, which disables the guard;
    the other-refusal sabotage also narrows the scope so the SCOPE check refuses
    instead, which must not pass for the Core-target guard."""
    other = SABOTAGE == "core-target-other-refusal"
    job = {"job_id": "r2d-core", "allowed": ["10.10.1.0/24"] if other else ["10.10.0.0/16"],
           "targets": [{"task_id": "t", "value": CORE}],
           "rate_budget_pps": 10, "connect_timeout_ms": 500, "max_concurrent_per_target": 1,
           "safety_mode": "safe"}
    if not sabotaged:
        job["core_endpoints"] = [f"{ip}:{port}" for ip, port in E]
    (work / "job-r2d-core.json").write_text(json.dumps(job) + "\n")
    _capture_start(work, image, veth, "core-target")
    out = _sh("docker", "exec", SP, "sh", "-c",
              "/w/runtimedrive /w/cvap-engine-discovery < /w/job-r2d-core.json").stdout
    text, _ = _capture_stop(work, image, "core-target")
    # EVERY TCP packet to Core counts, the exempt ports included: discovery's
    # default ports include 8443, and nothing in this phase talks to Core
    # legitimately, so a packet on 8443 here is a scan riding the exemption.
    to_core = [p for p in _parse(text) if p[1] == "tcp" and p[2] == CORE]
    try:
        res = json.loads(out or "{}")
    except ValueError:
        res = {}
    refused, why = res.get("refused") is True, res.get("refused_error") or ""
    lines.append(f"  core-target  refused={refused}  refused_error={why!r}  scan packets to Core={len(to_core)}")
    if refused and CORE_REFUSAL not in why:
        fails.append(f"  r2d core-target: refused, but not by the Core-target check: {why}")
    elif not refused:
        fails.append("  r2d core-target: the Core-target refusal did not fire; a job naming the Core address "
                     f"{CORE} was run (ADR-110)")
    if to_core:
        fails.append(f"  r2d core-target: {len(to_core)} scan packet(s) reached Core; Core must never be a scan "
                     "target (ADR-110)")


def _udp_loop_start(work, host, seconds):
    """A UDP_SEGMENT sender looping inside the Scan Point for `seconds`."""
    _sh("docker", "exec", "-d", SP, "sh", "-c",
        f"end=$(( $(date +%s) + {seconds} )); while [ $(date +%s) -lt $end ]; do "
        f"/w/r2dnontcp -mode=udpseg -host={host} -gso=100 -segs=64 -n=20 >/dev/null 2>&1; done")


def _reconnect(work, image, lines, fails, rate, burst):
    """The reconnect regression: with a UDP_SEGMENT sender looping, disconnect
    and reconnect the second network. The reconnected interface comes back
    under the same NAME with a new index, no filters and offload on; a guard
    that trusted names let it through (measured before the fix: 4,594 UDP
    superpackets in 0.59 s). Judged on segment-b's bridge, which sees the new
    interface's traffic however briefly it existed; the holder must also still
    be running afterwards, having re-policed rather than exited.

    The sender and the capture run across EVERY reconnect here, the three quick
    cycles included, not only the last one. The pre-fix holder (the committed
    one, name-keyed) did not survive a reconnect: the interface came back under
    its old name, was skipped as already policed, failed its own verify and the
    holder exited fail-closed at its next pass - the 0.59 s of the measurement
    above is that window. A capture that started after the quick cycles saw
    nothing from such a holder (measured: 0 packets, capture control 0, holder
    gone), so the leak must be watched from the first cycle. For the real
    holder this is the stricter statement: nothing leaves through any
    reconnected interface at any point."""
    _sh("docker", "network", "connect", NET_B, HOLDER, check=True)
    time.sleep(2.5)
    pre = preconditions(rate, burst)
    if pre:
        fails += [f"  r2d reconnect (before): {f}" for f in pre]
    # The positive control first, through the policed eth1 while it is up.
    _capture_sees_traffic(work, image, fails, lines, "")
    _udp_loop_start(work, PEER_B, 20)
    time.sleep(0.5)
    _dest_capture_start(work, image, "reconnect")
    # Three quick cycles first, with gaps shorter than a verify pass, as a
    # restarted network gives: a disconnect landing inside a pass is what took
    # the holder down (measured on the fifth cycle). The holder must outlive them.
    for gap in (0.4, 1.1, 0.7):
        _sh("docker", "network", "disconnect", NET_B, HOLDER, check=True)
        time.sleep(gap)
        _sh("docker", "network", "connect", NET_B, HOLDER, check=True)
        time.sleep(gap)
    time.sleep(2.5)
    _sh("docker", "network", "disconnect", NET_B, HOLDER, check=True)
    _sh("docker", "network", "connect", NET_B, HOLDER, check=True)
    time.sleep(6)
    text, dropped = _capture_stop(work, image, "reconnect", name=CAP2)
    _sh("docker", "exec", SP, "sh", "-c", "pkill -f 'r2dnontcp -mode=udpseg'; true")
    if dropped:
        fails.append(f"  r2d reconnect: the capture lost packets ({dropped}); nothing it says can be trusted")
    pk = _parse(text)
    udp = [p for p in pk if p[1] in ("udp", "other")]
    alive = _sh("docker", "inspect", "-f", "{{.State.Status}}", HOLDER).stdout.strip() == "running"
    post = preconditions(rate, burst) if alive else ["the holder is not running"]
    lines.append(f"  reconnect       UDP/other on segment-b across 4 disconnect+connect cycles: {len(udp)}  holder running: {alive}  "
                 f"re-policed: {'yes' if not post else '; '.join(post)[:120]}")
    if udp:
        first, last = pk[0][0], pk[-1][0]
        span = [p[0] for p in udp]
        lines.append(f"  reconnect       leak window: {len(udp)} packets over {(max(span) - min(span)) / 1e9:.2f} s "
                     f"(capture spans {(last - first) / 1e9:.1f} s)")
        fails.append(f"  r2d reconnect: {len(udp)} denied-protocol packet(s) left through the reconnected interface "
                     "before it was policed; the guard admitted an interface it had never verified (ADR-110 P2)")
    if not alive:
        (st, code), last_line = _holder_exit()
        tail = _sh("docker", "logs", HOLDER).stderr.strip().splitlines()[-6:]
        lines.append("  reconnect       holder log (last lines): " + " | ".join(t[:160] for t in tail))
        fails.append(f"  r2d reconnect: the holder exited (exit {code}) on a reconnect instead of re-policing the new "
                     f"interface: {last_line[:160]}")
    fails += [f"  r2d reconnect (after): {f}" for f in post]
    _sh("docker", "network", "disconnect", NET_B, HOLDER)
    time.sleep(2.5)


# Run inside the holder's namespace: wait until the holder is between passes
# (no tc/ethtool/nft/jq of ITS OWN for 300 ms), then until the next ethtool
# whose ancestry reaches PID 1 - the holder's pass, not the Docker HEALTHCHECK's
# concurrent `verify`, whose processes descend from a PID the namespace does
# not see (measured: armed on the health check's ethtool, the deletion landed
# outside any pass and the holder merely pruned) - and delete the pair then.
MIDPASS_TRIGGER = r'''
own() { for p in $(pgrep -x "$1"); do while [ "$p" -gt 1 ]; do p=$(awk '{print $4}' "/proc/$p/stat" 2>/dev/null) || break; done
  [ "$p" = 1 ] && return 0; done; return 1; }
busy() { own tc || own ethtool || own nft || own jq; }
q=0; i=0; while [ $q -lt 30 ]; do if busy; then q=0; else q=$((q+1)); fi; i=$((i+1)); [ $i -gt 3000 ] && exit 3; sleep 0.01; done
i=0; while ! own ethtool; do i=$((i+1)); [ $i -gt 6000 ] && exit 4; sleep 0.001; done
ip link del gatev0 && echo removed
'''


def _iface_removed_mid_pass(work, lines, fails, rate, burst):
    """An interface that vanishes while the holder is inside a verify pass -
    `docker network disconnect` landing between `ifaces` listing it and
    `ethtool -k` reading it - is a changed interface set, not a failed check.
    Measured before the fix: the holder exited on the fifth disconnect/reconnect
    cycle with `eth1: ethtool -k failed / eth1 fails verification`, and the
    gate's second-interface case then found no holder to inspect. Made
    deterministic here: a veth pair is added inside the namespace and the
    holder polices it; once the holder is between passes (no tc/ethtool/nft/jq
    process for 300 ms) the gate waits, inside the namespace, for the next
    `ethtool` - the first one a pass runs is in eth0's own checks, before the
    pair's - and deletes the pair at that instant. The holder must still be
    running afterwards, have logged a re-verify, and every precondition must
    hold with the set naming only live interfaces."""
    reverified = alive = False
    # Up to three attempts: an attempt whose deletion did not land inside a
    # pass (the holder survives AND logs no re-verify) proved nothing, and is
    # repeated with a fresh pair. A holder that exits is judged at once.
    for attempt in range(1, 4):
        before = _sh("docker", "logs", HOLDER).stdout.count("re-verifying")
        # Created and brought up in one exec: a DOWN interface has no root qdisc
        # and is a different (settling) transient than the vanishing one this
        # case is for. Fresh names per attempt, so the log test is unambiguous.
        a, b = f"gatev{attempt}0", f"gatev{attempt}1"
        def running():
            return _sh("docker", "inspect", "-f", "{{.State.Status}}", HOLDER).stdout.strip() == "running"
        # A holder already gone when this case starts (it exited after the
        # reconnect case had judged it) is this case's finding, not a crash
        # that loses the run's other lines.
        if not running():
            alive = False
            break
        policed = False
        _sh("docker", "exec", HOLDER, "sh", "-c",
            f"ip link add {a} type veth peer name {b} && ip link set {a} up && ip link set {b} up", check=True)
        for _ in range(80):
            policed = f"{b} (ifindex" in _sh("docker", "logs", HOLDER).stdout
            if policed or not running():
                break
            time.sleep(0.25)
        # The pair's own arrival is a changed set under a pass (the new
        # interface is DOWN, with no root qdisc, for a moment). A holder that
        # exits on it - or while the trigger waits for its next pass - has
        # shown the defect this case is for, and is judged below, not reported
        # as a case that did not run.
        if not running():
            alive = False
            break
        if not policed:
            fails.append(f"  r2d iface-removed-mid-pass: the holder never policed the added pair {a}/{b}; the case did not run")
            _sh("docker", "exec", HOLDER, "ip", "link", "del", a)
            return
        r = _sh("docker", "exec", HOLDER, "sh", "-c", MIDPASS_TRIGGER.replace("gatev0", a))
        if "removed" not in r.stdout:
            if not running():
                alive = False
                break
            fails.append(f"  r2d iface-removed-mid-pass: the pair was not removed mid-pass (rc {r.returncode}: "
                         f"{(r.stderr or r.stdout).strip()[-120:]}); the case did not run")
            _sh("docker", "exec", HOLDER, "ip", "link", "del", a)
            return
        time.sleep(4)
        alive = _sh("docker", "inspect", "-f", "{{.State.Status}}", HOLDER).stdout.strip() == "running"
        reverified = _sh("docker", "logs", HOLDER).stdout.count("re-verifying") > before
        if not alive or reverified:
            break
        lines.append(f"  iface-removed-mid-pass  attempt {attempt}: the holder survived without a re-verify; "
                     "the removal landed outside a pass, repeating")
    post = preconditions(rate, burst) if alive else ["the holder is not running"]
    lines.append(f"  iface-removed-mid-pass  holder running: {alive}  re-verified: {reverified}  "
                 f"after: {'all hold' if not post else '; '.join(post)[:120]}")
    if not alive:
        (st, code), last = _holder_exit()
        fails.append(f"  r2d iface-removed-mid-pass: the holder {st} (exit {code}) because the interface set changed "
                     f"under a verify pass; a changed set is not a failed check: {last[:140]}")
    elif not reverified:
        fails.append("  r2d iface-removed-mid-pass: the holder survived but logged no re-verify, so the removal did not "
                     "land inside a pass; the case did not exercise what it is named for")
    fails += [f"  r2d iface-removed-mid-pass (after): {f}" for f in post]


def _iface_down_arrival(work, lines, fails, rate, burst):
    """An interface that arrives DOWN and stays DOWN for longer than a verify
    cycle. Docker moves a new interface in DOWN, under a temporary name, and
    brings it up in a later step - measured under daemon load more than a
    second later, when the holder exited on `vethd5ad60f: qdiscs are [clsact],
    not exactly clsact + noqueue` over a set that had not changed. A DOWN
    interface carries nothing and is not an egress interface: the holder must
    stay up, must NOT have admitted it to the policed set, must police it
    within a cycle of its coming up, and every precondition must hold after."""
    a, b = "gatedn0", "gatedn1"

    def running():
        return _sh("docker", "inspect", "-f", "{{.State.Status}}", HOLDER).stdout.strip() == "running"
    if not running():
        (st, code), last = _holder_exit()
        fails.append(f"  r2d iface-down-arrival: the holder is {st} (exit {code}) before the case began: {last[:140]}")
        return
    _sh("docker", "exec", HOLDER, "ip", "link", "add", a, "type", "veth", "peer", "name", b, check=True)
    time.sleep(3.5)  # longer than CVAP_NP_VERIFY_SECONDS (1) + the settle second + a pass
    alive = running()
    admitted = policed_up = None
    post_up = post_del = []
    if alive:
        idx = _sh("docker", "exec", HOLDER, "cat", f"/sys/class/net/{a}/ifindex").stdout.strip()
        admitted = _sh("docker", "exec", HOLDER, "nft", "get", "element", "inet", "cvap_netpolicy", "policed",
                       f"{{ {idx} }}").returncode == 0
        _sh("docker", "exec", HOLDER, "sh", "-c", f"ip link set {a} up && ip link set {b} up", check=True)
        for _ in range(40):
            logs = _sh("docker", "logs", HOLDER).stdout
            policed_up = f"{a} (ifindex" in logs and f"{b} (ifindex" in logs
            if policed_up:
                break
            time.sleep(0.25)
        post_up = preconditions(rate, burst) if running() else ["the holder is not running"]
        _sh("docker", "exec", HOLDER, "ip", "link", "del", a)
        time.sleep(2.5)
        post_del = preconditions(rate, burst) if running() else ["the holder is not running"]
    def held(p):
        return "not run" if not alive else "all hold" if not p else "; ".join(p)[:100]
    lines.append(f"  iface-down-arrival  holder running after 3.5 s DOWN: {alive}  admitted while down: {admitted}  "
                 f"policed once up: {policed_up}  after up: {held(post_up)}  after removal: {held(post_del)}")
    if not alive:
        (st, code), last = _holder_exit()
        fails.append(f"  r2d iface-down-arrival: the holder {st} (exit {code}) while an interface sat DOWN for 3.5 s; "
                     f"a DOWN interface carries nothing and is not a failed check: {last[:140]}")
        return
    if admitted:
        fails.append(f"  r2d iface-down-arrival: the holder admitted a DOWN, unverifiable interface ({a}) to the policed set")
    if not policed_up:
        fails.append(f"  r2d iface-down-arrival: the holder did not police {a}/{b} within 10 s of their coming up")
    fails += [f"  r2d iface-down-arrival (after up): {f}" for f in post_up]
    fails += [f"  r2d iface-down-arrival (after removal): {f}" for f in post_del]


def _second_iface(work, image, lines, fails, rate, burst):
    """ONE bucket across two interfaces, measured at both wires: TCP load split
    across segment-a and segment-b, both veths captured, the two captures
    merged and judged against a single B + R*D."""
    if _sh("docker", "inspect", "-f", "{{.State.Status}}", HOLDER).stdout.strip() != "running":
        # The earlier cases have judged the exit; this one cannot run without
        # a holder and says so, instead of crashing on its veth lookup.
        (st, code), last = _holder_exit()
        fails.append(f"  r2d second-iface: the holder is {st} (exit {code}); the case did not run: {last[:140]}")
        return
    _sh("docker", "network", "connect", NET_B, HOLDER, check=True)
    time.sleep(2.5)
    pre = preconditions(rate, burst)
    fails += [f"  r2d second-iface: {f}" for f in pre]
    va, vb = _host_veth(image, "eth0"), _host_veth(image, "eth1")
    p0, d0 = _police()
    _capture_start(work, image, va, "second-iface-a")
    _capture_start(work, image, vb, "second-iface-b", name=CAP2)
    _sh("docker", "exec", "-d", SP, "/w/r2dload", f"-host={PEER_B}", f"-ports={HOSTILE}", "-n=10", "-dur=3s")
    conns = _load(work, 10)
    time.sleep(5)
    p1, d1 = _police()
    ta, da = _capture_stop(work, image, "second-iface-a")
    tb, db = _capture_stop(work, image, "second-iface-b", name=CAP2)
    if da or db:
        fails.append(f"  r2d second-iface: a capture lost packets ({da}, {db}); nothing it says can be trusted")
    pa, pb = _parse(ta), _parse(tb)
    merged = sorted(pa + pb, key=lambda p: p[0])
    _judge("second-iface", merged, rate, burst, lines, fails, tc=(p1 - p0, d1 - d0), conns=conns,
           extra=f"  per interface a={len([p for p in pa if not _is_core(p)])} b={len([p for p in pb if not _is_core(p)])}")
    if len([p for p in pb if p[1] == "tcp"]) < 50:
        fails.append("  r2d second-iface: fewer than 50 TCP packets left through the second interface; the "
                     "two-interface case did not exercise what it is named for")
    _sh("docker", "network", "disconnect", NET_B, HOLDER)
    time.sleep(2.5)


def _unpoliced_at_wire(work, image, lines, fails, guard_broken=False):
    """The guard's job, on a wire: traffic aimed at a network the holder has
    NOT yet policed (connected while the holder's re-verify is an hour away)
    must not leave. Run in the unpoliced-iface sabotage, where the holder will
    not police eth1 by itself. With guard_broken (the guard-flushed sabotage,
    same unpoliced interface, inet guard flushed) the SAME capture must show
    the leak: a guard sabotage judged by what reaches the destination, not by
    reading the ruleset."""
    _udp_loop_start(work, PEER_B, 5)
    _dest_capture_start(work, image, "unpoliced-at-wire")
    time.sleep(3.5)
    text, _ = _capture_stop(work, image, "unpoliced-at-wire", name=CAP2)
    leaked = [p for p in _parse(text) if p[1] in ("udp", "other", "tcp", "icmp")]
    if guard_broken:
        lines.append(f"  guard-flushed  packets from the namespace on the unpoliced network with the inet guard flushed: "
                     f"{len(leaked)} (the leak the guard exists to stop)")
        if leaked:
            fails.append(f"  r2d guard-flushed: {len(leaked)} packet(s) left through an interface the holder had not "
                         "policed once the inet guard was flushed; the guard, not the policer, is what holds an "
                         "unverified interface (ADR-110 P2)")
        else:
            # Not an r2d finding on purpose: the ruleset inspection already
            # fails this run, and this line says the wire half proved nothing.
            fails.append("  guard-flushed: VOID - the inet guard was flushed and nothing left through the unpoliced "
                         "interface; the wire did not show the guard holding anything")
        return
    lines.append(f"  unpoliced-iface packets from the namespace on the unpoliced network: {len(leaked)} (the guard must hold them)")
    if leaked:
        fails.append(f"  r2d unpoliced-iface: {len(leaked)} packet(s) left through an interface the holder had not "
                     "policed; the nftables guard did not hold (ADR-110 P2)")


def _exempt_cross_check(work, image, fails, lines, mismatch):
    """The Scan Point refuses to start unless every address the holder exempts
    is one it refuses as a target. runtimedrive carries the same check: given
    the holder's E it must start; given an E naming an address Core did not
    resolve to, it must refuse, and refuse BEFORE any engine exists."""
    holder_e = ",".join(f"{ip}:{port}" for ip, port in E)
    e = holder_e.replace(CORE, "10.10.0.77") if mismatch else holder_e
    job = {"job_id": "r2d-xcheck", "allowed": ["10.10.0.0/16"], "targets": [{"task_id": "t", "value": PEER}],
           "rate_budget_pps": 10, "connect_timeout_ms": 500, "max_concurrent_per_target": 1, "safety_mode": "safe",
           "core_endpoints": [f"{ip}:{port}" for ip, port in E], "policy_core_endpoints": e}
    (work / "job-r2d-xcheck.json").write_text(json.dumps(job) + "\n")
    r = _sh("docker", "exec", SP, "sh", "-c", "/w/runtimedrive /w/cvap-engine-discovery < /w/job-r2d-xcheck.json")
    try:
        res = json.loads(r.stdout or "{}")
    except ValueError:
        res = {}
    err = (r.stderr.strip().splitlines() or [""])[-1]
    lines.append(f"  exempt-vs-refused  holder E={e}  started={r.returncode == 0 and not res.get('refused')}  {err[:120]}")
    if mismatch:
        if r.returncode == 0 or "does not recognise as Core" not in err:
            fails.append(f"  r2d exempt-not-refused: the Scan Point ran with an exempt address (10.10.0.77) it would not "
                         f"refuse as a target (rc={r.returncode}: {err[:120]})")
        else:
            fails.append("  r2d exempt-not-refused: (expected) the Scan Point refused to start")
    elif r.returncode != 0:
        fails.append(f"  r2d exempt-vs-refused: the Scan Point refused the holder's own E: {err[:160]}")


def _sabotage_after_start():
    """Break the precondition the sabotage names, after a correct start. The
    holder runs with an hour's re-verify interval in sabotage runs, so it is
    the GATE that must notice, not the holder."""
    if SABOTAGE == "gso-segs":
        _sh("docker", "exec", HOLDER, "ip", "link", "set", "dev", "eth0", "gso_max_segs", "65535", check=True)
    elif SABOTAGE == "seg-feature":
        _sh("docker", "exec", HOLDER, "ethtool", "-K", "eth0", "sg", "on", "tso", "on", "gso", "on")
    elif SABOTAGE == "forwarding":
        # /proc/sys is read-only in an unprivileged container; a privileged one
        # sharing the namespace can write it.
        _sh("docker", "run", "--rm", "--privileged", "--network", f"container:{HOLDER}", "--entrypoint", "sh",
            HOLDER_IMAGE, "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward", check=True)
    elif SABOTAGE == "udp-default-deny":
        _sh("docker", "exec", HOLDER, "tc", "filter", "del", "dev", "eth0", "egress", "pref", str(DENY_PREF),
            check=True)
    elif SABOTAGE == "udp-allowed":
        _sh("docker", "exec", HOLDER, "tc", "filter", "add", "dev", "eth0", "egress", "pref", "15", "protocol", "ip",
            "flower", "ip_proto", "udp", "action", "police", "index", "1", check=True)
    elif SABOTAGE == "unpoliced-iface":
        _sh("docker", "network", "connect", NET_B, HOLDER, check=True)
        time.sleep(1)
    elif SABOTAGE == "wide-exclusion":
        _sh("docker", "exec", HOLDER, "tc", "filter", "add", "dev", "eth0", "egress", "pref", "1",
            "protocol", "ip", "flower", "ip_proto", "tcp", "dst_ip", PEER, "action", "pass", check=True)
    elif SABOTAGE == "guard-flushed":
        _sh("docker", "exec", HOLDER, "nft", "flush", "chain", "inet", "cvap_netpolicy", "out", check=True)
        # The wire half: an unpoliced interface beside the flushed guard. The
        # stalled holder never polices it. The ARP guard is still intact and
        # would hold the neighbour lookup (an IP packet is dropped at the
        # output hook BEFORE it resolves a neighbour, so the ARP guard is
        # never what stops IP on an unpoliced interface), so the peer's
        # address is seeded: what then leaves is what the inet guard alone
        # was holding.
        _sh("docker", "network", "connect", NET_B, HOLDER, check=True)
        time.sleep(1)
        mac = _sh("docker", "inspect", "-f", f'{{{{(index .NetworkSettings.Networks "{NET_B}").MacAddress}}}}',
                  PEERC, check=True).stdout.strip()
        dev = _sh("docker", "exec", HOLDER, "sh", "-c",
                  f"ip -o -4 addr show | awk '$4 ~ /^10\\.20\\./ {{print $2}}'", check=True).stdout.strip()
        _sh("docker", "exec", HOLDER, "ip", "neigh", "replace", PEER_B, "lladdr", mac, "dev", dev, "nud", "permanent",
            check=True)
    elif SABOTAGE == "guard-arp-removed":
        _sh("docker", "exec", HOLDER, "nft", "delete", "table", "arp", "cvap_netpolicy", check=True)
    elif SABOTAGE == "root-qdisc":
        # A root qdisc that duplicates after classification: one charge, two packets.
        _sh("docker", "exec", HOLDER, "tc", "qdisc", "add", "dev", "eth0", "root", "netem", "duplicate", "100%", check=True)


def run_r2d(work, capture_image, corpus, targets, fingerprint_ports):
    """Returns (failures, lines). Requires the lab to be up."""
    fails, lines = [], []
    # The Scan Point stand-in runs as 65532, as a real one does; mkdtemp made the
    # work directory 0700 for the gate's own user.
    work.chmod(0o755)
    for name, pkg in (("hostilepeer", "./test/safety/hostilepeer"), ("r2dload", "./test/safety/r2dload"),
                      ("r2dnontcp", "./test/safety/r2dnontcp")):
        _sh("go", "build", "-o", str(work / name), pkg, cwd=ROOT, check=True,
            env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"})
    try:
        _build_holder()
        if SABOTAGE == "name-keyed-guard":
            _build_name_keyed_holder()
        if SABOTAGE == "holder-no-retry":
            _build_no_retry_holder()
        if SABOTAGE == "holder-lists-down":
            _build_lists_down_holder()
        if SABOTAGE in STATE_SABOTAGES:
            _build_stalled_holder()
        _start_peer(work, capture_image)

        # ---- holder refusals: a start that must NOT succeed ------------------
        if SABOTAGE == "rate-raised":
            ok = _start_holder(5000, B, expect_ready=False)
            (st, code), last = _holder_exit()
            lines.append(f"  rate-raised: holder {st} exit={code}: {last[:120]}")
            if ok or st != "exited" or "above the platform ceiling" not in last:
                fails.append("  r2d rate-raised: the holder accepted CVAP_NP_RATE_PPS=5000; the ceiling must be lower-only (ADR-024)")
            else:
                fails.append("  r2d rate-raised: (expected) the holder refused to start with a raised ceiling")
            return fails, lines

        # ---- the preconditions; in a sabotage run, one of them broken --------
        # A verify interval of 5 (the holder's maximum) in sabotage runs, so it
        # is the GATE that must notice a broken precondition, not the holder.
        image = HOLDER_IMAGE_NAMED if SABOTAGE == "name-keyed-guard" else \
            HOLDER_IMAGE_NORETRY if SABOTAGE == "holder-no-retry" else \
            HOLDER_IMAGE_LISTSDOWN if SABOTAGE == "holder-lists-down" else \
            HOLDER_IMAGE_STALLED if SABOTAGE in STATE_SABOTAGES else HOLDER_IMAGE
        # The mid-pass case needs the holder passing every second, as deployed.
        _start_holder(R, B, every=1 if SABOTAGE in (None, "holder-no-retry", "holder-lists-down") else 5, image=image)
        _start_sp(work, capture_image, extra_cap={"netraw": "NET_RAW", "other-cap": "CHOWN"}.get(SABOTAGE),
                  root=SABOTAGE in ("netraw", "sp-root"))
        if SABOTAGE == "holder-self-verify":
            _holder_self_verify(work, fails, lines)
            return fails, lines
        _sabotage_after_start()
        # A holder that is not running cannot be inspected; if a sabotage took it
        # down (the real holder, fail-closed), that is the finding, not a crash.
        if _sh("docker", "inspect", "-f", "{{.State.Status}}", HOLDER).stdout.strip() != "running":
            (st, code), last = _holder_exit()
            fails.append(f"  r2d precondition: the holder is {st} (exit {code}) after the sabotage: {last[:140]}")
            return fails, lines
        pre = preconditions(R, B)
        lines.append(f"  preconditions: {'all hold' if not pre else '; '.join(pre)}")
        fails += [f"  r2d precondition {f}" for f in pre]

        veth = _host_veth(capture_image)
        # Docker's embedded DNS answers over loopback, which the policy leaves alone.
        dns = _sh("docker", "exec", SP, "nslookup", PEERC).stdout
        lines.append(f"  embedded DNS over loopback: {'resolves' if PEER in dns else 'FAILED'}")
        if PEER not in dns:
            fails.append("  r2d: the Scan Point cannot resolve through Docker's embedded DNS over loopback")
        _core_target(work, capture_image, veth, fails, lines,
                     sabotaged=SABOTAGE in ("core-target", "core-target-other-refusal"))
        _exempt_cross_check(work, capture_image, fails, lines, mismatch=(SABOTAGE == "exempt-not-refused"))
        if SABOTAGE in ("unpoliced-iface", "guard-flushed"):
            _unpoliced_at_wire(work, capture_image, lines, fails, guard_broken=SABOTAGE == "guard-flushed")
        if SABOTAGE == "name-keyed-guard":
            _reconnect(work, capture_image, lines, fails, R, B)
            return fails, lines
        if SABOTAGE == "holder-no-retry":
            _iface_removed_mid_pass(work, lines, fails, R, B)
            return fails, lines
        if SABOTAGE == "holder-lists-down":
            _iface_down_arrival(work, lines, fails, R, B)
            return fails, lines

        # ---- non-TCP: nothing reaches the wire -------------------------------
        _nontcp(work, capture_image, veth, R, B, lines, fails,
                user="0:0" if SABOTAGE == "netraw" else None)
        if SABOTAGE:
            if SABOTAGE == "udp-allowed":
                # The positive control at the lowered ceiling, where one hidden
                # buffer of 64 packets is far past B + R*D.
                # The stalled holder, not an interval: the real holder refuses
                # CVAP_NP_VERIFY_SECONDS above 5 (it did, and this case then
                # crashed instead of judging), and what must notice here is the gate.
                _start_holder(LOW_R, LOW_B, every=5, image=HOLDER_IMAGE_STALLED)
                _start_sp(work, capture_image)
                _sabotage_after_start()
                _nontcp(work, capture_image, _host_veth(capture_image), LOW_R, LOW_B, lines, fails, tag="-low")
            else:
                _phase(work, capture_image, veth, "sabotaged-n10", 10, R, B, lines, fails)
            return fails, lines

        # ---- the guard on a wire: reconnect, and one bucket over two wires ----
        _reconnect(work, capture_image, lines, fails, R, B)
        _iface_removed_mid_pass(work, lines, fails, R, B)
        _iface_down_arrival(work, lines, fails, R, B)
        _second_iface(work, capture_image, lines, fails, R, B)

        # ---- TCP at 1 / 5 / 10 / 20 concurrent connections -------------------
        totals = {}
        for n in (1, 5, 10, 20):
            cls, _ = _phase(work, capture_image, veth, f"tcp-n{n}", n, R, B, lines, fails)
            for k, v in cls.items():
                totals[k] = totals.get(k, 0) + v
        for k in ("syn", "data", "ack", "rst", "after_own_close"):
            if not totals.get(k):
                fails.append(f"  r2d: the load never produced {k} traffic; the ceiling was not shown to cover it")

        # ---- a deliberately lowered ceiling must bite ------------------------
        _start_holder(LOW_R, LOW_B)
        _start_sp(work, capture_image)
        veth = _host_veth(capture_image)
        if (p := preconditions(LOW_R, LOW_B)):
            fails += [f"  r2d lowered: {f}" for f in p]
        # 100 connections against a 3 s dial timeout: the bucket admits at most
        # LOW_B + LOW_R * 3 = 65 packets in that time, so at least 35 can never
        # get a SYN out. The failures are arithmetic, not luck - with 20, SYN
        # retries at 1 s fit inside the refilled bucket and none need fail.
        _phase(work, capture_image, veth, "lowered-n100", 100, LOW_R, LOW_B, lines, fails, expect_enforcement=True)
        _nontcp(work, capture_image, veth, LOW_R, LOW_B, lines, fails, tag="-low")

        # ---- the corpus, policed vs not --------------------------------------
        _start_holder(R, B)
        _start_sp(work, capture_image)
        ports = sorted(set(fingerprint_ports) | {p for pr in corpus["probes"] for p in pr["ports"]})
        c = _corpus(work, capture_image, corpus, targets, ports)
        lines.append(f"  corpus          {c['n']} observations outside the namespace ({c['ssh']} SSH host keys, "
                     f"{c['tls']} TLS handshakes; fragile, not compared: {c['fragile']}); identified differently inside {len(c['ident'])} {c['ident'][:5]}; "
                     f"evidence different {len(c['evidence'])} {c['evidence'][:5]}; tc-drops {c['tc'][1]}")
        if c["n"] == 0:
            fails.append("  r2d corpus: the unpoliced run identified nothing; the comparison proves nothing")
        if c["ident"]:
            fails.append(f"  r2d corpus: {len(c['ident'])} service(s) identified differently from inside the "
                         f"policed namespace: {c['ident'][:5]}")
        if c["evidence"]:
            fails.append(f"  r2d corpus: {len(c['evidence'])} observation(s) carry different evidence from inside "
                         f"the policed namespace: {c['evidence'][:5]}")
        if c["tc"][1]:
            fails.append(f"  r2d corpus: the policer dropped {c['tc'][1]} buffer(s) of normal fingerprinting")
    finally:
        _rm(SP, HOLDER, PEERC, CAP)
    return fails, lines
