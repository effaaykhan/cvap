"""The lab-present half of corpus-check: scan, ingest, diff, measure.

Imported by corpus_check.py only when the lab is reachable. Kept separate so the
always-on half needs neither docker nor a database driver to import.
"""

import base64
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
GROUND = ROOT / "lab" / "corpus" / "ground-truth.json"
NETWORK = {"segment-a": "cvap-lab_segment-a", "segment-b": "cvap-lab_segment-b"}
BASE_IMAGE = os.environ.get("CVAP_SAFETY_IMAGE", "alpine:latest")
SCANNED_PORTS = [21, 22, 23, 80, 443, 631, 8080, 8443, 9100]


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def build(work):
    """Static engine binaries and the corpus dump, exactly as the runtime ships."""
    env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"}
    for eng in ("cvap-engine-discovery", "cvap-engine-fingerprint"):
        r = sh(["go", "build", "-o", str(work / eng), f"./cmd/{eng}"], cwd=ROOT, env=env)
        if r.returncode:
            raise RuntimeError(f"build {eng}: {r.stderr}")
    r = sh(["go", "run", "./test/safety/corpusdump"], cwd=ROOT)
    if r.returncode:
        raise RuntimeError(f"corpusdump: {r.stderr}")
    return json.loads(r.stdout)


def ground_truth_has_not_drifted():
    """Re-capture live and assert the committed ground truth still matches. A
    stale committed file would let the always-on half check labels against a lab
    that no longer exists."""
    r = sh(["sh", str(ROOT / "lab" / "corpus" / "ground-truth.sh")])
    if r.returncode:
        return False, f"ground-truth.sh failed: {r.stderr[:200]}"
    live = _norm(r.stdout)
    committed = _norm(GROUND.read_text())
    if live != committed:
        return False, ("live ground truth differs from the committed lab/corpus/ground-truth.json. "
                       "Regenerate it (lab/corpus/ground-truth.sh > lab/corpus/ground-truth.json) "
                       "and re-review the corpus labels.")
    return True, ""


def _norm(jsonl):
    rows = []
    for line in jsonl.splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    rows.sort(key=lambda r: (r.get("target", ""), r.get("kind", "")))
    return json.dumps(rows, sort_keys=True)


def run_engine(work, binary, network, job, phase, ports_env=None):
    """Run an engine binary in a container on a lab segment; return its
    observation objects. Same shape as the safety gate's container run."""
    (work / f"job-{phase}.json").write_text(json.dumps(job) + "\n")
    env_args = []
    if ports_env:
        env_args = ["-e", f"CVAP_ENGINE_DISCOVERY_PORTS={ports_env}"]
    r = subprocess.run(
        ["docker", "run", "--rm", "--network", network, "-v", f"{work}:/w",
         *env_args, BASE_IMAGE, "sh", "-c", f"/w/{binary} < /w/job-{phase}.json"],
        capture_output=True, text=True)
    obs = []
    for line in r.stdout.splitlines():
        try:
            m = json.loads(line)
        except ValueError:
            continue
        if m.get("kind") == "observation":
            obs.append(m["observation"])
    return obs


def decode(o):
    return json.loads(base64.b64decode(o["payload"]))


def run_metrics(corpus, gt, always_msg):
    ok, why = ground_truth_has_not_drifted()
    if not ok:
        print(f"corpus-check: FAILED (ground truth drift)\n  {why}", file=sys.stderr)
        return 1

    work = pathlib.Path(tempfile.mkdtemp(prefix="cvap-corpus-"))
    try:
        dump = build(work)
    except RuntimeError as e:
        print(f"corpus-check: {e}", file=sys.stderr)
        return 1

    # --- scan each segment: discovery then fingerprint ---
    by_zone = {}          # zone type -> list of {type,payload}
    found_hosts = set()   # addresses discovery called alive
    found_ports = set()   # (addr, port) discovery found open
    services = {}         # (addr, port) -> {service, product, version}

    for seg, hosts in _hosts_by_segment(corpus).items():
        network = NETWORK[seg]
        zone_type = corpus["zones"][seg]["type"]
        targets = [{"task_id": f"t{i}", "value": h} for i, h in enumerate(hosts)]

        disc_job = {"kind": "job", "job_id": f"disc-{seg}", "targets": targets,
                    "rate_budget_pps": 200, "connect_timeout_ms": 3000,
                    "max_concurrent_per_target": 10, "safety_mode": "safe"}
        disc = run_engine(work, "cvap-engine-discovery", network, disc_job,
                          f"disc-{seg}", ports_env=",".join(map(str, SCANNED_PORTS)))
        for o in disc:
            p = decode(o)
            if o["type"] == "host" and p.get("alive"):
                found_hosts.add(p["address"])
            if o["type"] == "port" and p.get("state") == "open":
                found_ports.add((p["address"], p["port"]))

        fp_job = {"kind": "job", "job_id": f"fp-{seg}", "targets": targets,
                  "rate_budget_pps": 200, "connect_timeout_ms": 3000,
                  "max_concurrent_per_target": 10, "safety_mode": "intrusive",
                  "ports": SCANNED_PORTS, "probes": dump["probes"],
                  "banner_matches": dump["banner_matches"],
                  "max_probes_per_port": dump["max_probes_per_port"]}
        fp = run_engine(work, "cvap-engine-fingerprint", network, fp_job, f"fp-{seg}")
        for o in fp:
            p = decode(o)
            if o["type"] == "service" and p.get("port"):
                services[(p["address"], p["port"])] = {
                    "service": p.get("service", ""), "product": p.get("product", ""),
                    "version": p.get("version", "")}
            by_zone.setdefault(zone_type, []).append({"type": o["type"], "payload": o["payload"]})

    # --- ingest through the real correlator + rules for findings and merge ---
    plan = {"scan": by_zone, "merge": corpus.get("merge_scenarios", [])}
    ing = sh(["go", "run", "./test/corpus/ingest"], cwd=ROOT,
             input=json.dumps(plan),
             env={**os.environ,
                  "APP_DATABASE_URL": os.environ.get(
                      "APP_DATABASE_URL",
                      "postgres://cvap_app_login:cvap_dev_only_app_password@127.0.0.1:5432/cvap?sslmode=disable")})
    if ing.returncode:
        print(f"corpus-check: ingest failed: {ing.stderr[-800:]}", file=sys.stderr)
        return 1
    result = json.loads(ing.stdout)

    return _score(corpus, always_msg, found_hosts, found_ports, services, result)


def _hosts_by_segment(corpus):
    # scanned:false hosts (the fragile rate fixture, the filtered host) are not
    # scanned here — their purpose is make safety, and a deliberately degrading
    # or invisible host in an accuracy denominator measures the wrong thing. The
    # exclusion is stated in the corpus note and enforced in one place, here.
    out = {}
    for h in corpus["hosts"]:
        if h.get("scanned") is False:
            continue
        out.setdefault(h["segment"], []).append(h["address"])
    return out


def _score(corpus, always_msg, found_hosts, found_ports, services, result):
    # Expected sets from the corpus, over the SCANNED hosts only — the same set
    # the scan targeted, so recall denominators and the scan agree.
    hosts = [h for h in corpus["hosts"] if h.get("scanned") is not False]
    exp_alive = [h["address"] for h in hosts if h.get("alive")]
    exp_ports = [(h["address"], p["port"]) for h in hosts if h.get("alive")
                 for p in h.get("ports", []) if p.get("port") in SCANNED_PORTS]
    exp_services = {(h["address"], p["port"]): p for h in hosts if h.get("alive")
                    for p in h.get("ports", []) if p.get("service")}
    exp_findings = set()
    for h in hosts:
        for p in h.get("ports", []):
            for f in p["findings"]:
                exp_findings.add((h["address"], p["port"], f))

    got_findings = set((f["address"], f["port"], f["rule"]) for f in result.get("findings", []))

    fails = []
    report = []

    # Host recall.
    hr = _ratio(len([a for a in exp_alive if a in found_hosts]), len(exp_alive))
    report.append(("host discovery recall", hr, THRESH("host_recall"), hr >= THRESH("host_recall")))

    # Port recall.
    pr = _ratio(len([e for e in exp_ports if e in found_ports]), len(exp_ports))
    report.append(("port discovery recall", pr, THRESH("port_recall"), pr >= THRESH("port_recall")))

    # Service identification accuracy: service protocol must match; product where labelled.
    sid_ok = 0
    for key, want in exp_services.items():
        got = services.get(key)
        if got and got["service"] == want["service"] and \
           (not want.get("product") or got["product"] == want["product"]):
            sid_ok += 1
    sid = _ratio(sid_ok, len(exp_services))
    report.append(("service identification", sid, THRESH("service_id"), sid >= THRESH("service_id")))

    # Findings: FP (unexpected) and FN (missed).
    fp = got_findings - exp_findings
    fn = exp_findings - got_findings
    total = max(len(exp_findings), 1)
    fp_rate = len(fp) / max(len(got_findings), 1)
    fn_rate = len(fn) / total
    report.append(("finding false-positive rate", fp_rate, THRESH("finding_fp"), fp_rate <= THRESH("finding_fp")))
    report.append(("finding false-negative rate", fn_rate, THRESH("finding_fn"), fn_rate <= THRESH("finding_fn")))

    # Merge correctness.
    merges = result.get("merge", [])
    merge_ok = sum(1 for m in merges if m["assets"] == m["expected"])
    mr = _ratio(merge_ok, len(merges))
    report.append(("asset merge correctness", mr, THRESH("merge"), mr >= THRESH("merge")))

    print(f"corpus-check: {always_msg}; 6 metrics MEASURED against the lab")
    for name, val, thr, passed in report:
        mark = "ok " if passed else "FAIL"
        cmp = "<=" if "false" in name else ">="
        print(f"  [{mark}] {name:<28} {val:6.1%}  ({cmp} {thr:.0%})")
        if not passed:
            fails.append(name)

    # Precision first: any unexpected finding is named and fails, even if the rate
    # is under the cap.
    if fp:
        print("  UNEXPECTED findings (each one is a lost customer):", file=sys.stderr)
        for a, p, r in sorted(fp):
            print(f"    {a}:{p} {r}", file=sys.stderr)
        if "finding false-positive rate" not in fails:
            fails.append("unexpected findings present")
    if fn:
        print("  MISSED findings:", file=sys.stderr)
        for a, p, r in sorted(fn):
            print(f"    {a}:{p} {r}", file=sys.stderr)
    for m in merges:
        if m["assets"] != m["expected"]:
            print(f"    merge {m['name']}: {m['assets']} assets, expected {m['expected']}", file=sys.stderr)

    if fails:
        print(f"\ncorpus-check: FAILED — {', '.join(fails)}", file=sys.stderr)
        print("Thresholds are ADR §6.2 and are not moved. If one cannot be met, the number "
              "above is the report.", file=sys.stderr)
        return 1
    print("corpus-check: every metric meets its ADR §6.2 threshold")
    return 0


def THRESH(k):
    from corpus_check import THRESHOLDS
    return THRESHOLDS[k]


def _ratio(n, d):
    return 1.0 if d == 0 else n / d
