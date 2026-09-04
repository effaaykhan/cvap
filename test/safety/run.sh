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
# The engine makes TCP connections and nothing else (ADR-047), so TCP is exactly
# its traffic. THIS FILTER MUST WIDEN when that stops being true — a raw-socket
# engine sending SYN or ICMP would be invisible to this capture, which is the
# same "gate that silently proves less than it claims" this repository keeps
# finding. The filter is named in the gate's own output for that reason.
tcpdump -i any -n -w "$OUT"/capture.pcap 'tcp' >/dev/null 2>&1 &
TCPDUMP=$!
# tcpdump needs a moment to attach before the first packet, or the evidence is
# missing exactly for the fastest part of the scan.
sleep 2

/w/cvap-engine-discovery < /w/job.json > "$OUT"/observations.jsonl 2>"$OUT"/engine.err || true

sleep 1
kill "$TCPDUMP" 2>/dev/null || true
wait "$TCPDUMP" 2>/dev/null || true
