#!/bin/sh
# Capture everything this container sends, run the engine, and print the capture.
#
# The assertion is made OUTSIDE, by safety_gate.py, against lab/scope.txt. This
# script's only job is to produce evidence — keeping the judgement out of the
# container means the thing being tested cannot influence the verdict.
set -e

OUT=/w/out
mkdir -p "$OUT"
# TCP only, and the filter is a claim about the engine under test rather than a
# convenience.
#
# The container's own stack emits IPv6 neighbour solicitations and multicast
# listener reports to ff02::/16 addresses that are not in lab/scope.txt and were
# not sent by the engine. Asserting on them would fail the gate on kernel
# housekeeping; excluding them by address would be a blocklist of the things
# noticed so far.
#
# The engine makes TCP connections and nothing else (ADR-047), so TCP is most of
# its traffic — and DNS is the rest.
#
# `tcp` alone was the first filter, and the gate's own docstring listed "a DNS
# lookup to a resolver" under what it covers. A packet-capture audit measured
# twelve UDP/53 queries in a run the gate reported as clean: two per connect
# attempt, to a resolver nobody authorised, naming every target. The filter made
# the exact traffic the docstring promised invisible.
#
# THIS FILTER MUST WIDEN AGAIN when the engine gains a method — a raw-socket
# engine sending SYN or ICMP would be invisible to this capture, which is the
# same "gate that silently proves less than it claims". It is named in the
# gate's own output for that reason.
tcpdump -i any -n -w "$OUT"/capture.pcap 'tcp or udp port 53' >/dev/null 2>&1 &
TCPDUMP=$!
# tcpdump needs a moment to attach before the first packet, or the evidence is
# missing exactly for the fastest part of the scan.
sleep 2

/w/cvap-engine-discovery < /w/job.json > "$OUT"/observations.jsonl 2>"$OUT"/engine.err || true

sleep 1
kill "$TCPDUMP" 2>/dev/null || true
wait "$TCPDUMP" 2>/dev/null || true
