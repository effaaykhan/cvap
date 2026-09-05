#!/usr/bin/env python3
"""The scope-enforcement gate, the full §6.3 form.

============================================================================
Runs the engine AND the runtime send-path with egress capture, and asserts
nothing left scope.
============================================================================

Two layers, because scope is enforced in the runtime and the engine is not:

  - ENGINE phases (main, below): the discovery and fingerprint engines run
    directly, and the capture proves the packet budget, payload inertness on
    non-inert ports, and that a safe job sends no payload. These measure the
    engine, which is the first code here that can put a packet on a wire.

  - SCOPE cases (safety_scope.py): the six §6.3 cases run a job through the
    scan-point RUNTIME's send-path scope check — ADR-024's second enforcement
    site, which an engine-direct run never instantiates — and assert which
    addresses did and did not receive packets. Exclusion overlapping an allow,
    CIDR boundary arithmetic, a hostname refused before resolution, the
    v4-mapped form of an excluded address, and a scan halted in flight. A
    redirect to an out-of-scope host and the NAT64/6to4/Teredo/ISATAP forms are
    named as coverage statements with the reason they are not on this wire.

WHAT THIS COVERS
  - Every packet the engine sent went to an address inside lab/scope.txt.
  - Every packet went to an address the engine was GIVEN. An engine constructs
    no targets (ADR-027), so a destination outside the authorised set is target
    construction however it arose — a redirect followed, a lookup, a name
    resolved to something unexpected.
  - Resolver traffic, since the filter is `tcp or udp port 53`. There should be
    none: the engine refuses a target that is not an IP address, because
    net.Dialer would otherwise resolve a name and connect to an answer no
    enforcement site had checked. A DNS packet appearing here means that
    refusal has stopped working.

    An earlier version of this docstring claimed DNS coverage while the filter
    was `tcp` alone, so the exact traffic it promised was invisible — a
    packet-capture audit measured twelve queries in a run this gate called
    clean.

WHAT THIS STILL DOES NOT COVER
  - Core's planning-time scope check (site one) end to end. The scope cases here
    drive the runtime (site two), which is the last line before packets; site one
    is unit-tested (internal/dispatch) and its refusals produce no wire traffic
    to capture.
  - A redirect to an out-of-scope host, and the NAT64/6to4/Teredo/ISATAP
    translated forms — coverage statements in safety_scope, each with its reason.
  - A raw-socket engine. There is none (ADR-047), and when there is, this capture
    is the only evidence rather than one of two — the connect path is observable
    through the socket API and a raw sender is not.
"""

import base64
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

# How far the engine's packet model may fall short of the wire before this is a
# finding. Slack for scheduling and for a connection the peer closes first;
# nothing like the 2.94 an audit measured when the budget counted attempts.
MaxWireToChargedRatio = 1.15

# Targets the engine is authorised for. All inside lab/scope.txt and all on the
# lab network, so a packet leaving to anything else is the finding.
# The filtered host is in the list deliberately: it is the only target that
# exercises the SYN-retransmit path, which is what the packet-budget assertion
# below is actually about. Without it the ratio check passes even with the
# accounting sabotaged, because every other lab target answers or refuses
# instantly.
# 10.10.0.15 is the TLS target, and it is here because the fingerprint engine's
# handshake is the only packet cost this gate has never measured. A model for it
# (TLSHandshakeCost) exists in the engine; without a target that completes a
# handshake, that number is asserted by nothing.
# 10.10.0.14 is the OpenSSH host, and it was missing. Its absence meant the one
# target in the lab that volunteers a real banner was never reached by this gate,
# so the entire banner-identification path — the whole of what safe mode does —
# was exercised by unit tests alone. Found by reading the gate's own output and
# noticing which addresses were not in it.
TARGETS = ["10.10.0.11", "10.10.0.12", "10.10.0.14", "10.10.0.15", "10.10.0.16",
           "10.10.0.20", "10.10.0.30", "10.10.0.40"]

# Ports where unsolicited bytes are NOT inert, and 10.10.0.40 listens on them.
#
# This is the static probe denylist from internal/scanpoint/corpus.go, restated
# here as a WIRE assertion rather than a unit test: the fingerprint engine is
# pointed at 9100 in intrusive mode with the real corpus, and not one payload
# byte may arrive. On a real 9100 any bytes are a print job, and invariant 9 is
# that detection establishes evidence without achieving impact.
#
# The listener matters. Against a closed port the assertion passes trivially,
# because a refused connection cannot carry a payload whether the denylist works
# or not — which is the shape of a gate that silently proves nothing.
NON_INERT_PORTS = {"9100", "631"}


# Ports chosen so the FILTERED target dominates the packet count.
#
# Most of these are closed on the nginx targets — an instant RST, one packet —
# and filtered on 10.10.0.30, where each costs a SYN and its retransmissions.
# That is what gives the packet-budget assertion below something to measure; a
# short list of mostly-open ports produced a signal too small to separate correct
# accounting from none.
PORTS = "21,22,23,25,80,110,143,443,3306,5432,8080,8443"

# The fingerprint engine gets a shorter list, and that is the point of the second
# phase rather than a shortcut.
#
# This phase runs INTRUSIVE with the real built-in corpus, so every port here
# costs a connect plus a chain of probes — and 443 costs a full TLS handshake at
# a target that completes one. A long port list would multiply that into a
# minutes-long gate without measuring anything the short list does not.
#
# 22 volunteers a banner (no probe follows a hard match), 80 takes the HTTP chain,
# 443 takes the handshake, and 9100 is here as the ASSERTION: it is on the
# non-inert denylist, so a correct run sends a connect and no probe payload to it.
# 631 is here as well as 9100 because both are on the denylist and only one was
# being exercised: half a wire assertion is a gate that reports more than it
# checked. 10.10.0.40 listens on both.
FINGERPRINT_PORTS = [22, 80, 443, 631, 5432, 9100]


def dst_is_local(dst):
    """Whether a destination is on this host — a resolver, typically.

    `tcpdump -i any` labels loopback traffic "In" in both directions, so the
    egress test cannot key on direction alone without dropping DNS to a
    container's own resolver. This keeps those packets in scope for the
    assertion; being IN the capture is not the same as being authorised.
    """
    addr = dst.rstrip(":").rsplit(".", 1)[0]
    return addr.startswith("127.") or addr == "::1"


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

    # STATIC binaries, mounted rather than baked into an image.
    #
    # No Dockerfile and no image build: the gate then needs only a base image
    # and nothing from a registry at run time, which is what lets it work on a
    # machine whose registry access is broken. It also means the thing under
    # test is exactly the binary `go build` produced, not a copy inside a layer.
    for engine in ("cvap-engine-discovery", "cvap-engine-fingerprint"):
        subprocess.run(
            ["go", "build", "-o", str(work / engine), f"./cmd/{engine}"],
            cwd=ROOT, check=True,
            env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"},
        )
    # runtimedrive runs a job through the scan-point RUNTIME's send-path scope
    # check — ADR-024's second site — which the engine-direct phases below never
    # instantiate. The §6.3 scope cases (safety_scope.py) drive it.
    subprocess.run(
        ["go", "build", "-o", str(work / "runtimedrive"), "./test/safety/runtimedrive"],
        cwd=ROOT, check=True,
        env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64"},
    )
    for script in ("run.sh", "run-runtime.sh"):
        shutil.copy(ROOT / "test" / "safety" / script, work / script)
        (work / script).chmod(0o755)

    capture_image = prepare_capture_image()
    if capture_image is None:
        return 2

    # Scope-only fast path: the engine phases below (corpus dump, three container
    # runs, the budget and payload assertions) measure the ENGINE and pass every
    # time a scope case is sabotaged, so running them 5× for the sabotage matrix
    # is minutes of waste that could also mask the scope result. When a scope case
    # is being sabotaged — or CVAP_SAFETY_ONLY_SCOPE is set — skip straight to the
    # scope cases. runtimedrive, the engines and the scripts are already built.
    only_scope = (os.environ.get("CVAP_SAFETY_ONLY_SCOPE") == "1"
                  or bool(os.environ.get("CVAP_SAFETY_SCOPE_SABOTAGE")))
    if only_scope:
        import safety_scope
        failures, lines = safety_scope.run_scope_cases(work, capture_image)
        for ln in lines:
            print(ln, file=(sys.stderr if failures else sys.stdout))
        if failures:
            print("\nsafety: FAILED (scope cases only)", file=sys.stderr)
            for f in failures:
                print(f, file=sys.stderr)
            return 1
        print("\nsafety: scope cases passed; engine phases skipped (scope-only run)")
        return 0

    # The REAL corpus, asked for rather than restated.
    #
    # A probe list written into this gate would drift from internal/scanpoint the
    # moment either changed, and the gate would go on reporting a clean run about
    # a corpus nobody uses. See test/safety/corpusdump.
    dump = subprocess.run(["go", "run", "./test/safety/corpusdump"],
                          cwd=ROOT, capture_output=True, text=True)
    if dump.returncode != 0:
        print("safety: could not read the built-in fingerprint corpus", file=sys.stderr)
        print(dump.stderr[-2000:], file=sys.stderr)
        return 1
    corpus = json.loads(dump.stdout)

    job = {
        "kind": "job",
        "job_id": "safety-gate",
        "targets": [{"task_id": f"t{i}", "value": v} for i, v in enumerate(TARGETS)],
        "rate_budget_pps": 50,
        # The PLATFORM DEFAULT, not a short test value.
        #
        # At 500ms no SYN retransmit fits inside the timeout, so synCost is 1
        # whatever the accounting says — the packet-budget assertion below could
        # not fail even with the model sabotaged. Three seconds is what a real
        # scan uses and what makes the filtered target produce the retransmit
        # train the assertion is about.
        "connect_timeout_ms": 3000,
        "max_concurrent_per_target": 4,
        "safety_mode": "safe",
    }
    (work / "job-discovery.json").write_text(json.dumps(job) + "\n")

    # ====================================================================
    # Phase two: the fingerprint engine, INTRUSIVE, with the real corpus.
    # ====================================================================
    #
    # The first phase measures a safe job, which sends no payloads at all. That
    # leaves the entire probe path — every payload this platform can put on a
    # wire — outside the only capture-based gate there is. An intrusive phase is
    # what puts it inside.
    fp_job = dict(job)
    fp_job["job_id"] = "safety-gate-fingerprint"
    fp_job["safety_mode"] = "intrusive"
    fp_job["ports"] = FINGERPRINT_PORTS
    fp_job["probes"] = corpus["probes"]
    fp_job["banner_matches"] = corpus["banner_matches"]
    fp_job["max_probes_per_port"] = corpus["max_probes_per_port"]
    (work / "job-fingerprint.json").write_text(json.dumps(fp_job) + "\n")

    # ====================================================================
    # Phase three: the same engine, the same targets, under a SAFE job.
    # ====================================================================
    #
    # ADR-021's central claim measured at the wire rather than asserted in a unit
    # test: a safe job sends NO PAYLOAD AT ALL. The runtime hands a safe job an
    # empty probe list, so there is nothing to send — but "nothing to send" is a
    # property of the whole runtime-to-engine path, and the only way to know it
    # holds is to look at what left the machine.
    #
    # The job below keeps the banner rules and drops the probes, which is exactly
    # what job.budget produces for a safe job.
    safe_job = dict(fp_job)
    safe_job["job_id"] = "safety-gate-fingerprint-safe"
    safe_job["safety_mode"] = "safe"
    safe_job["probes"] = []
    (work / "job-fingerprint-safe.json").write_text(json.dumps(safe_job) + "\n")

    for engine, phase in (("cvap-engine-discovery", "discovery"),
                          ("cvap-engine-fingerprint", "fingerprint"),
                          ("cvap-engine-fingerprint", "fingerprint-safe")):
        run = subprocess.run(
            ["docker", "run", "--rm", "--network", NETWORK,
             "--cap-add=NET_RAW", "--cap-add=NET_ADMIN",
             "-e", f"CVAP_ENGINE_DISCOVERY_PORTS={PORTS}",
             "-v", f"{work}:/w", capture_image, "/w/run.sh", engine, phase],
            capture_output=True, text=True,
        )
        if run.returncode != 0:
            print(f"safety: the {phase} capture container failed; the gate proved nothing",
                  file=sys.stderr)
            print(run.stdout[-2000:], file=sys.stderr)
            print(run.stderr[-2000:], file=sys.stderr)
            return 1
        cap = out / f"capture-{phase}.pcap"
        if not cap.exists() or cap.stat().st_size == 0:
            print(f"safety: no {phase} capture was produced; the gate proved nothing",
                  file=sys.stderr)
            return 1

    # Read the capture with tcpdump rather than a parser of our own: the format
    # is the evidence and a hand-rolled reader is a place to be wrong about it.
    def read_capture(phase):
        return subprocess.run(
            ["docker", "run", "--rm", "-v", f"{work}:/w", capture_image,
             "sh", "-c", f"tcpdump -n -r /w/out/capture-{phase}.pcap 2>/dev/null"],
            capture_output=True, text=True, check=False,
        ).stdout

    authorised = set(TARGETS)
    destinations = {}
    non_inert_payloads = []
    safe_payloads = []
    lines = []
    for phase in ("discovery", "fingerprint", "fingerprint-safe"):
        for line in read_capture(phase).splitlines():
            lines.append((phase == "fingerprint-safe", line))

    for in_safe_phase, line in lines:
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
        # Loopback traffic is labelled "In" by `tcpdump -i any` even when this
        # host originated it, so an egress-only test that keys on the direction
        # alone silently drops a resolver on 127.0.0.11 — which is exactly where
        # a container's DNS lives. Anything not explicitly inbound from a peer is
        # counted, and the target set below is what decides whether it was
        # authorised.
        direction = parts[i - 1] if i > 0 else ""
        if direction == "In" and not dst_is_local(parts[i + 3]):
            continue
        dst = parts[i + 3].rstrip(":")
        # Strip the port. IPv4 and IPv6 both put it after the final dot in
        # tcpdump's rendering.
        addr, _, port = dst.rpartition(".")
        destinations[addr] = destinations.get(addr, 0) + 1
        payload_len = 0
        if "length" in parts:
            i_len = parts.index("length")
            if i_len + 1 < len(parts):
                try:
                    payload_len = int(parts[i_len + 1].rstrip(":"))
                except ValueError:
                    payload_len = 0
        if in_safe_phase and payload_len > 0:
            safe_payloads.append((dst, payload_len))

        # Payload bytes to a non-inert port, which must be zero.
        #
        # tcpdump renders the TCP segment length at the end of the line; a
        # handshake or a FIN is `length 0` and a probe is not. Keyed on the
        # DESTINATION port so an answer coming back from one is not counted.
        if port in NON_INERT_PORTS and payload_len > 0:
            non_inert_payloads.append((dst, payload_len))

    fingerprint_services = []
    fp_obs = out / "observations-fingerprint.jsonl"
    if fp_obs.exists():
        for line in fp_obs.read_text().splitlines():
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("kind") != "observation":
                continue
            try:
                fingerprint_services.append(
                    json.loads(base64.b64decode(m["observation"]["payload"])))
            except (ValueError, KeyError, TypeError):
                continue

    # ====================================================================
    # The gate must have EXERCISED the TLS path, or it measured nothing.
    # ====================================================================
    #
    # An audit found this printing "the probe payloads and the TLS handshake are
    # inside the capture" while the shipped corpus contained no TLS probe at all:
    # zero handshakes, TLSHandshakeCost asserted by nothing, and a wire-to-charged
    # ratio that was honest about a workload nobody cared about. A gate that
    # cannot tell it did nothing is the failure this whole file exists against.
    if not any(p.get("tls") for p in fingerprint_services):
        print("safety: the intrusive phase completed NO TLS handshake.", file=sys.stderr)
        print("        The corpus has no TLS probe reaching a port in FINGERPRINT_PORTS,",
              file=sys.stderr)
        print("        so the handshake cost is measured by nothing and this gate is", file=sys.stderr)
        print("        weaker than its output claims.", file=sys.stderr)
        return 1

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

    # The engine's own count, so the packet budget can be checked against the
    # wire rather than trusted. ADR-024's ceiling is in packets and the engine
    # charges a model of them (synCost); a ratio far from 1 means the model is
    # wrong in whichever direction it leans.
    reported = 0
    for obs in sorted(out.glob("observations-*.jsonl")):
        for line in obs.read_text().splitlines():
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if m.get("kind") == "sent":
                reported += int(m.get("count", 0))

    actual = sum(destinations.values())
    print(f"safety: {actual} outbound packet(s) to {len(destinations)} address(es)")
    ratio = None
    if reported:
        ratio = actual / reported
        print(f"        engine charged {reported} against its budget "
              f"(wire/charged = {ratio:.2f})")
    for addr, count in sorted(destinations.items()):
        print(f"  {addr:<20} {count}")

    # The budget must not UNDERCHARGE, or ADR-024's ceilings are looser than the
    # ADR says by whatever the shortfall is.
    #
    # This started at 2.94 — the engine charged one token per connect attempt
    # while the kernel sent a SYN and two retransmits — so the 10 pps fragile cap
    # was really about 29. Asserted here rather than only reported, because a
    # number nobody checks drifts back.
    #
    # Over-charging is fine and is the direction the model deliberately leans.
    # ====================================================================
    # Not one payload byte to a port where bytes are not inert.
    # ====================================================================
    #
    # The static policy in internal/scanpoint/corpus.go is the whole safety
    # argument for letting a signed pack supply probes: a signature proves
    # origin, not that a payload is inert. This is that policy measured at the
    # wire instead of asserted in a unit test.
    if non_inert_payloads:
        total = sum(n for _, n in non_inert_payloads)
        failures.append(
            f"  {len(non_inert_payloads)} packet(s) carrying {total} payload byte(s) reached a "
            f"NON-INERT port: {non_inert_payloads[:5]}. On 9100 those bytes are a print job. "
            "Invariant 9: detection establishes evidence without achieving impact."
        )

    # ====================================================================
    # A SAFE job sent no payload at all.
    # ====================================================================
    #
    # ADR-021 makes safe the default for every policy, so it is the mode most
    # deployments run and the one that must be unable to provoke anything. The
    # enforcement is that the runtime hands a safe job an empty probe list — this
    # is that enforcement measured at the wire, which is the only place the claim
    # is actually about.
    if safe_payloads:
        total = sum(n for _, n in safe_payloads)
        failures.append(
            f"  a SAFE job put {total} payload byte(s) on the wire in "
            f"{len(safe_payloads)} packet(s): {safe_payloads[:5]}. ADR-021's safe mode "
            "sends nothing; a connect and a read are the whole of it."
        )

    if ratio is not None and ratio > MaxWireToChargedRatio:
        failures.append(
            f"  the engine sent {actual} packets and charged {reported} "
            f"(ratio {ratio:.2f}, limit {MaxWireToChargedRatio}). ADR-024's ceilings are in "
            "PACKETS, so undercharging makes every one of them looser by this factor."
        )

    # ====================================================================
    # The §6.3 scope-enforcement cases, driven through the runtime send-path.
    # ====================================================================
    #
    # The three phases above measure the ENGINE — packet budget, payload
    # inertness, safe mode. They cannot measure scope, because an engine holds no
    # scope check (ADR-027); the enforcing site is the runtime, which the phases
    # above never instantiate. safety_scope drives it (runtimedrive) and puts the
    # six §6.3 cases on the wire.
    import safety_scope
    scope_failures, scope_lines = safety_scope.run_scope_cases(work, capture_image)
    failures.extend(scope_failures)

    if failures:
        print("\nsafety: FAILED", file=sys.stderr)
        for f in failures:
            print(f, file=sys.stderr)
        if scope_lines:
            print("\nscope cases (for context):", file=sys.stderr)
            for ln in scope_lines:
                print(ln, file=sys.stderr)
        return 1

    print("\nsafety: every packet went to an authorised target inside lab/scope.txt")
    print("Engine phases: discovery under a SAFE job, fingerprint under an INTRUSIVE one with")
    print("the built-in corpus (so the probe payloads and the TLS handshake are inside the")
    print("capture), and fingerprint under a SAFE job that put no payload on the wire at all.")
    print("No payload byte reached 9100 or 631.")
    print("\nScope enforcement (§6.3), each driven through the runtime send-path and measured")
    print("at the wire on " + safety_scope.NET + ":")
    for ln in scope_lines:
        print(ln)
    print("\nThe capture filter is 'tcp or udp port 53' — this engine's traffic plus resolver")
    print("lookups. It MUST widen when an engine gains a method; a raw sender would not appear.")
    print("The scope-changed-mid-scan TRIGGER (a narrowing → a lost lease) is asserted in")
    print("internal/dispatch (TestALeaseIsNotRenewedAfterScopeNarrows, ADR-051); the wire half")
    print("above is that a halted scan stops sending. Still off this wire, and said so above:")
    print("a raw-socket engine, and the two coverage-statement cases.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
