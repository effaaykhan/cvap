"""Per-operation wire admission for the fingerprint engine (M0 R2a).

Imported by safety_gate.py. The gate's ratio check compares the WHOLE run's wire
against what the engines REPORTED, across both engines at once: a per-connection
capture showed one class at 1.20 and another at 2.4x while the run-wide ratio
read 0.98, because the filtered host's over-modelled SYN trains paid for the
rest. That number cannot say whether any single operation stayed inside what it
was admitted before it began, which is the R2a invariant:

    captured engine-originated packets <= admitted packets, per operation

One job per case, one capture per job, offload off (test/safety/run-wireops.sh),
so every TCP connection in a capture is one operation, in the order the engine
performs them: a port's own connection first, then its probe. The admitted
number is the engine's own (test/safety/admissiondump), never a copy of its
formula.

What counts as ENGINE-ORIGINATED, read off each outbound packet:
  - every SYN;
  - the ACK that completes the handshake;
  - every segment carrying data, once (a retransmitted range is not counted again);
  - the first FIN, and a RST that closes the connection when no FIN went first.
Everything else this end sends — ACKs of the peer's data, retransmissions, a RST
answering data after our FIN — is KERNEL-RESPONSE traffic. It is printed for
every operation and bounded by R2-B, not here.

Every case also asserts it exercised what it is named for, so none can pass by
sending nothing.
"""

import base64
import json
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
NET = "cvap-lab_segment-a"
H_NGINX = "10.10.0.11"
H_OPENSSH = "10.10.0.14"
H_TLS = "10.10.0.15"
H_FILTERED = "10.10.0.30"
# A responder this module starts for the large-response case and removes after:
# inside lab/scope.txt, on the internal lab network, and not a lab target, so
# nothing else ever scans it.
H_BIG = "10.10.0.200"
# Per gate run: a fixed name let a second run's `docker rm -f` remove the first
# run's responder mid-case. A second run now fails loudly on the address instead.
BIG_NAME = f"cvap-safety-bigtalk-{os.getpid()}"
BIG_BYTES = 65536

PKT = re.compile(
    r"^(\d+\.\d+) IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): "
    r"Flags \[([^\]]*)\](.*?)length (\d+)")
SEQ = re.compile(r"seq (\d+):(\d+)")


def _template_probe():
    # As many placeholders as the engine's 512-byte cap allows at the longest
    # (46-character) expansion — the worst case R2a admits for.
    ph = b"{{target}}"
    n = (512 - 2) // 46
    payload = ph * n + b"\r\n"
    return {"name": "template-max", "ports": [80], "read_bytes": 4096,
            "payload": base64.b64encode(payload).decode(), "rarity": 1}


def _job(jid, targets, ports, mode, probes, corpus, conc=4, timeout_ms=3000):
    return {"kind": "job", "job_id": jid,
            "targets": [{"task_id": f"t{i}", "value": v} for i, v in enumerate(targets)],
            "rate_budget_pps": 50, "connect_timeout_ms": timeout_ms,
            "max_concurrent_per_target": conc, "safety_mode": mode, "ports": ports,
            "probes": probes, "banner_matches": corpus["banner_matches"],
            "max_probes_per_port": corpus["max_probes_per_port"]}


def _flows(text):
    """Outbound packets grouped per connection, in first-SYN order."""
    me, flows, order = None, {}, []
    for line in text.splitlines():
        m = PKT.search(line)
        if not m:
            continue
        ts, s, sp, d, dp, fl, mid, ln = m.groups()
        ln = int(ln)
        if me is None and fl == "S":
            me = s
        if s == me:
            key = (d, int(dp), int(sp))
            out = True
        elif d == me:
            key = (s, int(sp), int(dp))
            out = False
        else:
            continue
        if key not in flows:
            flows[key] = []
            order.append(key)
        sq = SEQ.search(mid)
        flows[key].append({"out": out, "flags": fl, "len": ln,
                           "seq": (int(sq.group(1)), int(sq.group(2))) if sq else None})
    return [(k, flows[k]) for k in order if any(p["out"] for p in flows[k])]


def _classify(pkts):
    """(engine, response, detail) counts for one connection's outbound packets."""
    engine = response = 0
    synack = handshake_acked = fin = closed = False
    seen = []
    detail = {"syn": 0, "data": 0, "data_bytes": 0, "in_bytes": 0, "rtx": 0}
    for p in pkts:
        if not p["out"]:
            if p["flags"] == "S.":
                synack = True
            detail["in_bytes"] += p["len"]
            continue
        f = p["flags"]
        if f == "S":
            engine += 1
            detail["syn"] += 1
        elif p["len"] > 0:
            if p["seq"] and any(a <= p["seq"][0] and p["seq"][1] <= b for a, b in seen):
                response += 1  # a retransmission of data already counted
                detail["rtx"] += 1
                continue
            if p["seq"]:
                seen.append(p["seq"])
            engine += 1
            detail["data"] += 1
            detail["data_bytes"] += p["len"]
            if "F" in f:
                fin = closed = True
        elif "F" in f and not fin:
            engine += 1
            fin = closed = True
        elif "R" in f and not closed:
            engine += 1
            closed = True
        elif f == "." and synack and not handshake_acked:
            engine += 1
            handshake_acked = True
        else:
            response += 1
    return engine, response, detail


def _start_big(work, img):
    # test/safety/bigtalk, static, mounted like the engines: every connection
    # gets the whole body, concurrently.
    subprocess.run(["docker", "rm", "-f", BIG_NAME], capture_output=True)
    built = subprocess.run(["go", "build", "-o", str(work / "bigtalk"), "./test/safety/bigtalk"],
                           cwd=ROOT, capture_output=True, text=True,
                           env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"})
    if built.returncode != 0:
        return False
    r = subprocess.run(
        ["docker", "run", "-d", "--name", BIG_NAME, "--network", NET, "--ip", H_BIG,
         "-v", f"{work}:/w", img, "/w/bigtalk", ":8080", str(BIG_BYTES)],
        capture_output=True, text=True)
    return r.returncode == 0


def _cases(corpus):
    by = {p["name"]: p for p in corpus["probes"]}
    for need in ("https-head", "http-head", "ssh-hostkey"):
        if need not in by:
            raise SystemExit(f"safety: built-in corpus has no {need!r} probe; a wire case would be empty")
    big_probe = dict(by["http-head"], ports=[8080])
    # The largest payload the engine accepts, over TLS: two segments once the
    # record is wrapped round it, which a one-packet-per-payload charge missed.
    tls_max = dict(by["https-head"], name="https-max",
                   payload=base64.b64encode(b"HEAD / HTTP/1.0\r\nX: " + b"a" * 487 + b"\r\n\r\n").decode())
    return [
        # name, job, kill_after, expected ops (op kind, probe name), exercised(flows) -> str|None
        ("connection", _job("w-conn", [H_NGINX], [80], "safe", [], corpus), None,
         [("port", None)],
         lambda fl: None if fl[0][2]["syn"] >= 1 else "no SYN"),
        ("banner", _job("w-banner", [H_OPENSSH], [22], "safe", [], corpus), None,
         [("port", None)],
         lambda fl: None if fl[0][2]["in_bytes"] > 0 else "the peer volunteered nothing"),
        ("tls", _job("w-tls", [H_TLS], [443], "intrusive", [by["https-head"]], corpus), None,
         [("port", None), ("probe", "https-head")],
         lambda fl: None if len(fl) > 1 and fl[1][2]["data_bytes"] >= 1000 else "no ClientHello on the wire"),
        ("ssh", _job("w-ssh", [H_OPENSSH], [22], "intrusive", [by["ssh-hostkey"]], corpus), None,
         [("port", None), ("probe", "ssh-hostkey")],
         lambda fl: None if len(fl) > 1 and fl[1][2]["data"] >= 3 else "fewer than three client messages"),
        ("payload", _job("w-payload", [H_NGINX], [80], "intrusive", [by["http-head"]], corpus), None,
         [("port", None), ("probe", "http-head")],
         lambda fl: None if len(fl) > 1 and fl[1][2]["data_bytes"] > 0 else "no payload on the wire"),
        ("worst-case-template", _job("w-template", [H_NGINX], [80], "intrusive", [_template_probe()], corpus),
         None, [("port", None), ("probe", "template-max")],
         lambda fl: None if len(fl) > 1 and fl[1][2]["data_bytes"] >= 100 else "the expanded payload did not leave"),
        ("large-peer-response", _job("w-big", [H_BIG], [8080], "intrusive", [big_probe], corpus), None,
         [("port", None), ("probe", "http-head")],
         lambda fl: None if max(f[2]["in_bytes"] for f in fl) >= BIG_BYTES // 2 else "the peer sent little"),
        # The three below are where the admission R2a replaced fell short, so a
        # return to it fails here rather than passing at the 3s default.
        ("short-timeout", _job("w-short", [H_NGINX], [80], "safe", [], corpus, timeout_ms=500), None,
         [("port", None)],
         lambda fl: None if fl[0][2]["syn"] >= 1 and fl[0][1] >= 3 else "the connection did not open"),
        ("linear-syn-train", _job("w-linear", [H_FILTERED], [5432], "safe", [], corpus, timeout_ms=2500),
         None, [("port", None)],
         lambda fl: None if fl[0][2]["syn"] >= 3 else f"{fl[0][2]['syn']} SYN(s); the train did not run"),
        ("tls-max-payload", _job("w-tlsmax", [H_TLS], [443], "intrusive", [tls_max], corpus), None,
         [("port", None), ("probe", "https-max")],
         lambda fl: None if len(fl) > 1 and fl[1][2]["data_bytes"] >= 1500 + 512 else "the payload did not leave"),
        ("mid-dial-cancellation", _job("w-cancel", [H_FILTERED], [5432], "safe", [], corpus), "1.5",
         [("port", None)],
         lambda fl: None if fl[0][2]["syn"] >= 2 else "killed before the SYN train started"),
        ("concurrent", _job("w-conc", [H_NGINX], list(range(8000, 8019)) + [80], "safe", [], corpus, conc=20),
         None, [("port", None)] * 20,
         lambda fl: None if len(fl) >= 20 else f"only {len(fl)} connection(s)"),
    ]


# Attempts per case, for the "exercised" condition ONLY. large-peer-response
# races the engine's own close (connect-and-close; read-one-chunk-and-close)
# against the peer's slow start at MSS 536, so whether a run gets BIG_BYTES // 2
# out before the engine's RST varies run to run (measured: 3 in 30 short with a
# peer that no longer aborts itself). Every attempt is still judged against
# admission, and a violation fails the case at once - it is never retried away.
ATTEMPTS = {"large-peer-response": 3}


def run_wire_ops(work, capture_image, corpus):
    failures, lines = [], []
    if not _start_big(work, capture_image):
        return ["  wire-ops: could not start the large-response responder; the case would be empty"], lines
    try:
        for name, job, kill_after, ops, exercised in _cases(corpus):
            adm = subprocess.run(["go", "run", "./test/safety/admissiondump"], input=json.dumps(job),
                                 cwd=ROOT, capture_output=True, text=True)
            if adm.returncode != 0:
                failures.append(f"  wire-ops {name}: admissiondump failed: {adm.stderr[-300:]}")
                continue
            admitted = json.loads(adm.stdout)
            env = ["-e", f"KILL_AFTER={kill_after}"] if kill_after else []
            tries, short = ATTEMPTS.get(name, 1), []
            for attempt in range(1, tries + 1):
                phase = f"wireops-{name}" + (f"-a{attempt}" if attempt > 1 else "")
                tag = f" [attempt {attempt}/{tries}]" if tries > 1 else ""
                (work / f"job-{phase}.json").write_text(json.dumps(job) + "\n")
                run = subprocess.run(
                    ["docker", "run", "--rm", "--network", NET, "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
                     *env, "-v", f"{work}:/w", capture_image, "/w/run-wireops.sh",
                     "cvap-engine-fingerprint", phase],
                    capture_output=True, text=True)
                if run.returncode != 0:
                    failures.append(f"  wire-ops {name}{tag}: capture failed, nothing proven: "
                                    f"{(run.stderr or run.stdout)[-300:]}")
                    break
                text = subprocess.run(
                    ["docker", "run", "--rm", "-v", f"{work}:/w", capture_image, "sh", "-c",
                     f"tcpdump -n -tt -r /w/out/capture-{phase}.pcap 2>/dev/null"],
                    capture_output=True, text=True).stdout
                flows = [(k, *_classify(p)) for k, p in _flows(text)]
                if len(flows) != len(ops):
                    failures.append(f"  wire-ops {name}{tag}: {len(flows)} connection(s) captured, "
                                    f"expected {len(ops)}; operations cannot be attributed")
                    break
                violated = False
                for (key, engine, response, detail), (kind, probe) in zip(flows, ops):
                    limit = admitted["port"] if kind == "port" else admitted["probes"][probe]
                    op = "connection" if kind == "port" else probe
                    lines.append(f"  {name:<22} {op:<14} admitted {limit:>3}  engine {engine:>3}  "
                                 f"diff {limit - engine:>+4}   (kernel-response {response}, "
                                 f"total {engine + response}, in {detail['in_bytes']}B){tag}")
                    if engine > limit:
                        violated = True
                        failures.append(
                            f"  wire-ops {name}{tag}: {op} to {key[0]}:{key[1]} put {engine} engine-originated "
                            f"packet(s) on the wire against {limit} admitted before it began (R2a)")
                why = exercised([(k, e, d) for k, e, r, d in flows])
                if why:
                    short.append(f"attempt {attempt}: " + ", ".join(f"{d['in_bytes']}B" for k, e, r, d in flows))
                if violated or not why or attempt == tries:
                    if why:
                        failures.append(f"  wire-ops {name}: did not exercise what it is named for: {why}"
                                        + (f" in any of {attempt} attempt(s) ({'; '.join(short)})" if tries > 1 else ""))
                    break
    finally:
        subprocess.run(["docker", "rm", "-f", BIG_NAME], capture_output=True)
    return failures, lines
