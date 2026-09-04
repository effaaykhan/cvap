#!/usr/bin/env python3
"""The golden-corpus gate: does a real scan of the lab match the hand-labels?

============================================================================
Two halves, and the split is the point (make safety's shape, one level up).
============================================================================

ALWAYS, no lab, no database:
  - the corpus is well-formed and every finding it names is a real rule;
  - every label is consistent with lab/corpus/ground-truth.json — the container's
    own account of itself. A drifted corpus fails here, on a laptop, before CI.

WHEN THE LAB IS REACHABLE (and CVAP_REQUIRE_LAB=1 makes absence fatal, which CI
sets):
  - re-capture ground truth live and assert the committed file still matches;
  - run the real discovery and fingerprint engines against the lab, ingest their
    observations through the real correlator and rules (test/corpus/ingest), and
    diff the result against the corpus;
  - compute the six ADR §6.2 metrics against their thresholds. Precision first:
    any UNEXPECTED finding fails the gate outright and is listed by name.

The pass line always states the enforcement state — "N label checks passed, 6
metrics NOT MEASURED (no lab)" is honest; "corpus-check OK" over half a gate is
the silent-no-op this project keeps finding.
"""

import ipaddress
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORPUS = ROOT / "lab" / "corpus" / "corpus.json"
GROUND = ROOT / "lab" / "corpus" / "ground-truth.json"
MIGRATION = ROOT / "migrations" / "0032_builtin_rule_pack.up.sql"
NETWORK_A = "cvap-lab_segment-a"
NETWORK_B = "cvap-lab_segment-b"
BASE_IMAGE = os.environ.get("CVAP_SAFETY_IMAGE", "alpine:latest")

# ADR §6.2 thresholds. Not moved; if one cannot be met the number is reported.
THRESHOLDS = {
    "host_recall": 0.99,
    "port_recall": 0.98,
    "service_id": 0.90,
    "finding_fp": 0.02,   # max
    "finding_fn": 0.05,   # max
    "merge": 1.00,
}


def die(msg):
    print(f"corpus-check: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# Always-on half.
# ---------------------------------------------------------------------------

def load_json(path):
    if not path.exists():
        die(f"{path} does not exist")
    try:
        return json.loads(path.read_text())
    except ValueError as e:
        die(f"{path} is not valid JSON: {e}")


def load_ground_truth():
    if not GROUND.exists():
        die(f"{GROUND} does not exist — run lab/corpus/ground-truth.sh with the lab up")
    out = {}
    for line in GROUND.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        out.setdefault(row["target"], {}).update(row)
    return out


def rule_names_from_migration():
    """The rule names the built-in pack actually seeds — the set a corpus finding
    may reference. Read from the migration, not from a hand list that could drift."""
    import re
    text = MIGRATION.read_text()
    return set(re.findall(r"'([a-z0-9-]+)', '(?:tls|exposure|web|crypto)'", text))


def check_schema(corpus):
    problems = []
    known_rules = rule_names_from_migration()
    if not known_rules:
        die("could not read rule names from the migration; the schema check is checking nothing")

    seen_addr = set()
    for h in corpus.get("hosts", []):
        a = h.get("address")
        if not a:
            problems.append("a host has no address")
            continue
        try:
            ipaddress.ip_address(a)
        except ValueError:
            problems.append(f"{a} is not an IP address")
        if a in seen_addr:
            problems.append(f"{a} appears twice")
        seen_addr.add(a)
        if "alive" not in h:
            problems.append(f"{a} has no alive label")
        if not h.get("source"):
            problems.append(f"{a} has no source (where the label came from)")
        if h.get("scanned") is False and not h.get("note"):
            problems.append(f"{a} is scanned:false with no note saying why it is excluded")
        for p in h.get("ports", []):
            for f in p.get("findings", []):
                if f not in known_rules:
                    problems.append(f"{a}:{p.get('port')} names finding {f!r}, not a seeded rule")
    for u in corpus.get("uncovered", []):
        if not u.get("reason"):
            problems.append(f"uncovered case {u.get('case')!r} has no reason")
    if not corpus.get("hosts"):
        problems.append("corpus has no hosts")
    return problems


def check_label_consistency(corpus, gt):
    """Every finding label must be DERIVABLE from the container's self-description
    in ground-truth.json. This is the edge that keeps the corpus honest: a label
    the containers do not support cannot survive here.

    Only the checks whose facts ground-truth.json carries are enforced; a finding
    whose truth is a config fact not in ground truth (the HTTP header rules, the
    exposure zone) is schema-checked above but not re-derived here, and that is
    stated rather than silently skipped."""
    problems = []
    # Map corpus host -> ground-truth entry by matching the target's IP.
    ip_to_target = {}
    # ground-truth rows that carry an ip
    for tgt, row in gt.items():
        if "ip" in row:
            ip_to_target[row["ip"]] = tgt
    # TLS targets have no ip in ground truth; map by the corpus source naming them.
    derivable = 0
    for h in corpus.get("hosts", []):
        for p in h.get("ports", []):
            for f in p["findings"]:
                fact = _gt_for_finding(h, p, f, gt)
                if fact is None:
                    continue  # not a ground-truth-derivable finding; schema-checked only
                derivable += 1
                ok, why = fact
                if not ok:
                    problems.append(f"{h['address']}:{p['port']} labels {f} but ground truth says {why}")
    return problems, derivable


def _gt_row_for_host(h, gt):
    """Find the ground-truth TLS/ssh row for a corpus host by the CN/target hint
    in its source string."""
    src = h.get("source", "")
    for tgt, row in gt.items():
        if tgt in src.replace("target-a-", "").replace("target-", ""):
            return row
        # e.g. source "compose target-a-tls-expired" -> target "tls-expired"
        if ("tls-" + tgt.split("-")[-1]) in src:
            return row
    # direct: the source names the target token
    for tgt, row in gt.items():
        if tgt != "" and tgt in src:
            return row
    return None


def _gt_for_finding(h, p, f, gt):
    """Return (ok, why) if this finding is ground-truth-derivable, else None."""
    row = _gt_row_for_host(h, gt)
    if f == "tls-certificate-expired":
        if not row:
            return (False, "no ground-truth cert row found")
        return (row.get("expired") is True, f"expired={row.get('expired')}")
    if f == "tls-self-signed-non-dev":
        if not row:
            return (False, "no ground-truth cert row found")
        return (row.get("self_signed") is True, f"self_signed={row.get('self_signed')}")
    if f == "tls-missing-chain":
        if not row:
            return (False, "no ground-truth cert row found")
        ok = row.get("self_signed") is False and row.get("served_chain_len") == 1
        return (ok, f"self_signed={row.get('self_signed')} served_chain_len={row.get('served_chain_len')}")
    if f == "tls-weak-key":
        if not row:
            return (False, "no ground-truth cert row found")
        try:
            bits = int(row.get("key_bits") or 0)
        except ValueError:
            bits = 0
        return (0 < bits < 2048, f"key_bits={row.get('key_bits')}")
    # The HTTP header rules, the plaintext rules, the exposure and legacy/cipher
    # rules turn on config facts (server headers, zone type, ssl_protocols) that
    # ground-truth.json carries only partially; they are schema-checked and
    # exercised by the scan half, not re-derived here.
    return None


# ---------------------------------------------------------------------------
# Lab detection.
# ---------------------------------------------------------------------------

def lab_reachable():
    if shutil.which("docker") is None:
        return False, "docker is not on PATH"
    # A quick TCP connect to a known always-up target inside the lab, from a
    # throwaway container on the segment (the segments are internal: true, so the
    # host cannot reach them directly).
    r = subprocess.run(
        ["docker", "run", "--rm", "--network", NETWORK_A, BASE_IMAGE,
         "sh", "-c", "nc -w2 -z 10.10.0.11 80 2>/dev/null && echo up || echo down"],
        capture_output=True, text=True, timeout=60,
    )
    if "up" in r.stdout:
        return True, ""
    return False, f"lab network {NETWORK_A} not reachable ({r.stdout.strip() or r.stderr.strip()[:120]})"


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    corpus = load_json(CORPUS)
    gt = load_ground_truth()

    problems = check_schema(corpus)
    lc_problems, derivable = check_label_consistency(corpus, gt)
    problems += lc_problems

    if problems:
        print("corpus-check: FAILED (always-on: schema / label consistency)", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    schema_hosts = len(corpus["hosts"])
    always_msg = (f"{schema_hosts} hosts schema-valid; {derivable} finding labels "
                  f"cross-checked against ground truth")

    require = os.environ.get("CVAP_REQUIRE_LAB") == "1"
    reachable, why = lab_reachable()
    if not reachable:
        metrics = ", ".join(sorted(THRESHOLDS))
        print(f"corpus-check: {always_msg}; 6 metrics NOT MEASURED (no lab: {why})")
        print(f"corpus-check: metrics not run: {metrics}")
        print("corpus-check: set CVAP_REQUIRE_LAB=1 to make an absent lab fatal (CI sets it)")
        if require:
            print("corpus-check: CVAP_REQUIRE_LAB=1 and the lab is absent", file=sys.stderr)
            return 1
        return 0

    # Live ground-truth drift check, then the scan-and-diff metrics.
    from corpus_metrics import run_metrics  # noqa: E402  (only needed with a lab)
    return run_metrics(corpus, gt, always_msg)


if __name__ == "__main__":
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    sys.exit(main())
