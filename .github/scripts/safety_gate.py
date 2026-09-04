#!/usr/bin/env python3
"""The scope-enforcement gate, narrow form.

============================================================================
Runs the engine with egress capture and asserts nothing left scope.
============================================================================

docs/execution-plan.md puts the full gate in week 8. This is the part that
could not wait: the discovery engine is the first code in this repository that
can put a packet on a wire, and shipping it with the gate still a failing stub
is the wrong order.

WHAT THIS COVERS
  - Every packet the engine sent went to an address inside lab/scope.txt.
  - Every packet went to an address the engine was GIVEN. An engine constructs
    no targets (ADR-027), so a destination outside the authorised set is target
    construction however it arose — a DNS lookup to a resolver, a redirect
    followed, a hostname resolved to something unexpected.

WHAT THIS DOES NOT COVER, and week 8 still owes
  - The two-site scope enforcement itself. This exercises the ENGINE with
    targets already authorised; Core's planning check and the runtime's send
    path check are unit-tested and are not driven end to end here.
  - Exclusion overlapping an allow, CIDR boundary arithmetic, a hostname
    resolving out of scope, a redirect to an out-of-scope host, IPv6 forms of an
    excluded v4 address.
  - A raw-socket engine. There is none (ADR-047), and when there is, the capture
    below is the only evidence rather than one of two — the connect path is
    observable through the socket API and a raw sender is not.
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
# CVAP_SAFETY_SCOPE overrides the scope file, and it exists to make the gate
# checkable.
#
# The lab networks are `internal: true`, so nothing outside lab/scope.txt is
# ROUTABLE from them — a target outside scope produces no packet at all rather
# than an out-of-scope one, which means the obvious sabotage ("scan something
# out of scope") cannot exercise the assertion. That is the lab working as
# designed and it leaves the gate's judgement unproven.
#
# Narrowing the scope file instead makes addresses that WERE scanned fall
# outside it, which drives exactly the comparison the gate exists to make.
# `make safety-sabotage` does this and requires a failure.
SCOPE = pathlib.Path(os.environ.get("CVAP_SAFETY_SCOPE", "")) if os.environ.get("CVAP_SAFETY_SCOPE") \
    else ROOT / "lab" / "scope.txt"
NETWORK = os.environ.get("CVAP_SAFETY_NETWORK", "cvap-lab_segment-a")

# The capture container's base. Overridable because the gate must run on a
# machine whose registry access is broken, where whatever alpine is already
# cached is the only one available.
BASE_IMAGE = os.environ.get("CVAP_SAFETY_IMAGE", "alpine:3.20")

# Targets the engine is authorised for. All inside lab/scope.txt and all on the
# lab network, so a packet leaving to anything else is the finding.
TARGETS = ["10.10.0.11", "10.10.0.12", "10.10.0.20"]


PORTS = "22,80,443,8080"


def load_scope():
    nets = []
    for line in SCOPE.read_text().splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            nets.append(ipaddress.ip_network(line, strict=False))
    if not nets:
        sys.exit("safety: lab/scope.txt names no networks")
    return nets


def in_scope(addr, nets):
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in n for n in nets)


CAPTURE_IMAGE = "cvap-safety-capture:local"


def prepare_capture_image():
    """An image with tcpdump, built without a registry or a Dockerfile.

    The lab networks are `internal: true` — no route off the host, which is half
    of why a misaimed scan cannot reach the internet — so a container attached to
    one cannot install anything. tcpdump therefore has to be present BEFORE the
    capture container joins that network.

    `docker run` on the default bridge followed by `docker commit` does that with
    no build and no registry pull beyond the base image, which matters because
    this has to work on a machine whose registry access is broken.
    """
    have = subprocess.run(["docker", "image", "inspect", CAPTURE_IMAGE],
                          capture_output=True, text=True)
    if have.returncode == 0:
        return CAPTURE_IMAGE

    name = "cvap-safety-prep"
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    prep = subprocess.run(
        ["docker", "run", "--name", name, BASE_IMAGE,
         "sh", "-c", "apk add --no-cache tcpdump"],
        capture_output=True, text=True,
    )
    if prep.returncode != 0:
        print("safety: could not prepare a capture image (no tcpdump, no network to fetch it).",
              file=sys.stderr)
        print("        This gate needs one; it has NOT run and nothing is proven.", file=sys.stderr)
        print(prep.stderr[-800:], file=sys.stderr)
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        return None
    subprocess.run(["docker", "commit", name, CAPTURE_IMAGE], capture_output=True, check=True)
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    return CAPTURE_IMAGE


def main():
    if shutil.which("docker") is None:
        print("safety: docker is not available; cannot capture egress", file=sys.stderr)
        return 2

    nets = load_scope()
    work = pathlib.Path(tempfile.mkdtemp(prefix="cvap-safety-"))
    out = work / "out"
    out.mkdir()
    out.chmod(0o777)

    # A STATIC binary, mounted rather than baked into an image.
    #
    # No Dockerfile and no image build: the gate then needs only a base image
    # and nothing from a registry at run time, which is what lets it work on a
    # machine whose registry access is broken. It also means the thing under
    # test is exactly the binary `go build` produced, not a copy inside a layer.
    subprocess.run(
        ["go", "build", "-o", str(work / "cvap-engine-discovery"), "./cmd/cvap-engine-discovery"],
        cwd=ROOT, check=True,
        env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"},
    )
    shutil.copy(ROOT / "test" / "safety" / "run.sh", work / "run.sh")
    (work / "run.sh").chmod(0o755)

    capture_image = prepare_capture_image()
    if capture_image is None:
        return 2

    job = {
        "kind": "job",
        "job_id": "safety-gate",
        "targets": [{"task_id": f"t{i}", "value": v} for i, v in enumerate(TARGETS)],
        "rate_budget_pps": 50,
        "connect_timeout_ms": 500,
        "max_concurrent_per_target": 4,
        "safety_mode": "safe",
    }
    (work / "job.json").write_text(json.dumps(job) + "\n")

    run = subprocess.run(
        ["docker", "run", "--rm", "--network", NETWORK,
         "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
         "-e", f"CVAP_ENGINE_DISCOVERY_PORTS={PORTS}",
         "-v", f"{work}:/w", capture_image, "/w/run.sh"],
        capture_output=True, text=True,
    )
    if run.returncode != 0:
        print("safety: the capture container failed; the gate proved nothing", file=sys.stderr)
        print(run.stdout[-2000:], file=sys.stderr)
        print(run.stderr[-2000:], file=sys.stderr)
        return 1

    cap = out / "capture.pcap"
    if not cap.exists() or cap.stat().st_size == 0:
        print("safety: no capture was produced; the gate proved nothing", file=sys.stderr)
        return 1

    # Read the capture with tcpdump rather than a parser of our own: the format
    # is the evidence and a hand-rolled reader is a place to be wrong about it.
    proc = subprocess.run(
        ["docker", "run", "--rm", "-v", f"{work}:/w", capture_image,
         "sh", "-c", "tcpdump -n -r /w/out/capture.pcap 2>/dev/null"],
        capture_output=True, text=True, check=False,
    )

    authorised = set(TARGETS)
    destinations = {}
    for line in proc.stdout.splitlines():
        # tcpdump's layout varies with the link type: a `-i any` capture is
        # LINUX_SLL2 and inserts an interface name and a direction before the
        # protocol. Locating the IP/IP6 token rather than indexing a fixed
        # column is what makes this read both — the first version assumed
        # Ethernet framing and silently matched nothing, reporting an empty
        # capture as "the gate proved nothing" when the capture was full.
        parts = line.split()
        try:
            i = next(j for j, tok in enumerate(parts) if tok in ("IP", "IP6"))
        except StopIteration:
            continue
        if len(parts) < i + 4 or parts[i + 2] != ">":
            continue

        # EGRESS ONLY, and this is the second thing the gate got wrong about its
        # own evidence.
        #
        # The first run "found" 30 packets to an unauthorised address, which was
        # the capture container's own IP receiving REPLIES from the targets it
        # had just connected to. A gate that reports inbound traffic as egress
        # produces a finding on every correct run — and one that fires on correct
        # code is one people learn to skip, which is the same failure as one that
        # silently passes.
        #
        # `tcpdump -i any` gives LINUX_SLL2 framing with a direction field
        # immediately before the protocol token. Requiring it rather than
        # inferring direction from an address means the gate does not need to
        # know the container's own IP.
        if i == 0 or parts[i - 1] != "Out":
            continue
        dst = parts[i + 3].rstrip(":")
        # Strip the port. IPv4 and IPv6 both put it after the final dot in
        # tcpdump's rendering.
        addr = dst.rsplit(".", 1)[0]
        destinations[addr] = destinations.get(addr, 0) + 1

    if not destinations:
        print("safety: the capture contains no OUTBOUND packets; the gate proved nothing.",
              file=sys.stderr)
        print("        Either the engine sent nothing, or the capture lacks the direction",
              file=sys.stderr)
        print("        field this gate reads (tcpdump -i any / LINUX_SLL2).", file=sys.stderr)
        return 1

    failures = []
    for addr, count in sorted(destinations.items()):
        if not in_scope(addr, nets):
            failures.append(f"  {addr} ({count} packet(s)) is OUTSIDE lab/scope.txt")
        elif addr not in authorised:
            failures.append(
                f"  {addr} ({count} packet(s)) is in scope but was NOT an authorised target. "
                "An engine constructs no targets (ADR-027)."
            )

    print(f"safety: {sum(destinations.values())} outbound packet(s) to {len(destinations)} address(es)")
    for addr, count in sorted(destinations.items()):
        print(f"  {addr:<20} {count}")

    if failures:
        print("\nsafety: FAILED", file=sys.stderr)
        for f in failures:
            print(f, file=sys.stderr)
        return 1

    print("\nsafety: every TCP packet went to an authorised target inside lab/scope.txt")
    print("The capture filter is 'tcp', which is exactly this engine's traffic and MUST")
    print("widen when that stops being true — a raw-socket engine would be invisible to it.")
    print("NOT covered here — see the docstring and docs/execution-plan.md 6.3:")
    print("  the two-site scope check end to end, exclusion/allow overlap, CIDR")
    print("  boundaries, hostname and redirect cases, IPv6 forms, raw sockets.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
