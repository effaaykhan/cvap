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
import subprocess
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
             "other-cap", "unpoliced-iface", "wide-exclusion", "core-target", "core-target-other-refusal"]
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


def _start_holder(rate, burst, every=1):
    _rm(HOLDER)
    eps = ",".join(f"{ip}:{port}" for ip, port in E)
    sysctls = [x for s in FORWARDING_OFF for x in ("--sysctl", s)]
    _sh("docker", "run", "-d", "--name", HOLDER, "--network", NET, "--cap-add", "NET_ADMIN", *sysctls,
        "-e", f"CVAP_NP_CORE_ENDPOINTS={eps}", "-e", f"CVAP_NP_RATE_PPS={rate}",
        "-e", f"CVAP_NP_BURST={burst}", "-e", f"CVAP_NP_VERIFY_SECONDS={every}", HOLDER_IMAGE, check=True)
    for _ in range(40):
        if "ready:" in _sh("docker", "logs", HOLDER).stdout:
            return
        time.sleep(0.25)
    raise RuntimeError("the holder never became ready: " + _sh("docker", "logs", HOLDER).stderr[-400:])


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
    time.sleep(1)


def _host_veth(image):
    idx = _sh("docker", "exec", HOLDER, "cat", "/sys/class/net/eth0/iflink", check=True).stdout.strip()
    links = _sh("docker", "run", "--rm", "--network", "host", image, "ip", "-o", "link", check=True).stdout
    for line in links.splitlines():
        num, name = line.split(":", 2)[:2]
        if num.strip() == idx:
            return name.strip().split("@")[0]
    raise RuntimeError(f"no host interface with ifindex {idx}")


def _capture_start(work, image, veth, phase):
    _rm(CAP)
    _sh("docker", "run", "-d", "--name", CAP, "--network", "host", "--cap-add", "NET_RAW", "--cap-add", "NET_ADMIN",
        "-v", f"{work}:/w", image, "sh", "-c",
        f"tcpdump -i {veth} -Q in -nn -e -B 65536 --time-stamp-precision=nano -w /w/out/r2d-{phase}.pcap "
        f"2>/w/out/r2d-{phase}.err", check=True)
    time.sleep(1.5)


def _capture_stop(work, image, phase):
    _sh("docker", "exec", CAP, "pkill", "-INT", "tcpdump")
    time.sleep(1)
    _rm(CAP)
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
    guard = _sh("docker", "exec", HOLDER, "nft", "list", "chain", "inet", "cvap_netpolicy", "out").stdout
    if "drop" not in guard:
        fails.append("P2: the fail-closed nftables guard is missing")
    policed = _sh("docker", "exec", HOLDER, "nft", "-j", "list", "set", "inet", "cvap_netpolicy", "policed").stdout
    members = {e for x in json.loads(policed or "{}").get("nftables", []) for e in (x.get("set", {}).get("elem") or [])}
    for dev in ifs:
        if dev not in members:
            fails.append(f"P2: {dev} is not in the guard's policed set")
    # P3: no capability anywhere in the Scan Point, read from the kernel.
    status = _sh("docker", "exec", SP, "sh", "-c",
                 "for f in /proc/[0-9]*/status; do grep -HE '^(Cap(Inh|Prm|Eff|Bnd|Amb)|NoNewPrivs):' $f; done").stdout
    if not status.strip():
        fails.append("P3: could not read the Scan Point's capability state")
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
    if expect_enforcement and not (drops > 0 and errs > 0):
        fails.append(f"  r2d {name}: the lowered ceiling produced {drops} drops and {errs} failed connections; "
                     "an enforced ceiling must produce both")
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
    to_core = [p for p in _parse(text) if p[1] == "tcp" and p[2] == CORE and not _is_core(p)]
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
        _start_peer(work, capture_image)

        # ---- the preconditions; in a sabotage run, one of them broken --------
        _start_holder(R, B, every=3600 if SABOTAGE else 1)
        _start_sp(work, capture_image, extra_cap={"netraw": "NET_RAW", "other-cap": "CHOWN"}.get(SABOTAGE),
                  root=(SABOTAGE == "netraw"))
        _sabotage_after_start()
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

        # ---- non-TCP: nothing reaches the wire -------------------------------
        _nontcp(work, capture_image, veth, R, B, lines, fails,
                user="0:0" if SABOTAGE == "netraw" else None)
        if SABOTAGE:
            if SABOTAGE == "udp-allowed":
                # The positive control at the lowered ceiling, where one hidden
                # buffer of 64 packets is far past B + R*D.
                _start_holder(LOW_R, LOW_B, every=3600)
                _start_sp(work, capture_image)
                _sabotage_after_start()
                _nontcp(work, capture_image, _host_veth(capture_image), LOW_R, LOW_B, lines, fails, tag="-low")
            else:
                _phase(work, capture_image, veth, "sabotaged-n10", 10, R, B, lines, fails)
            return fails, lines

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
