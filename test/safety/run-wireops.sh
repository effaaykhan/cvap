#!/bin/sh
# Capture ONE fingerprint job's egress for the per-operation wire check (M0 R2a),
# then leave the pcap for safety_wire_ops.py to judge.
#
# Three differences from run.sh, all about what "captured" means:
#
#  - Segmentation offload is switched OFF first. With it on, the kernel hands
#    the interface one oversized segment and the NIC (or veth) splits it later,
#    so a capture here sees a 1505-byte ClientHello as ONE packet where a real
#    1460-MSS link carries two. A per-operation packet count read from such a
#    capture undercounts exactly the multi-segment writes R2a is about. No
#    ethtool, or an interface that refuses, is a failure, not a skip.
#  - MTU 576, so segments are as small as the model says they can be (below).
#  - eth0 only, not `any`, so no packet is counted twice.
#
# KILL_AFTER (seconds) SIGTERMs the engine mid-run: the cancellation case.
set -e

ENGINE="$1"
PHASE="$2"
OUT=/w/out
mkdir -p "$OUT"

# MTU 576: IPv4's minimum datagram, so the peer is offered an MSS of 536 — the
# smallest R2a's segment model (enginerate.SegmentPayload) claims to cover. At the
# lab's 1500 a write of 600 bytes is one segment and an admission that counted it
# as one would pass; here it is two and such an admission fails.
ip link set eth0 mtu 576 || { echo "wireops: cannot set MTU 576" >&2; exit 2; }
ip link show eth0 | grep -q 'mtu 576' || { echo "wireops: MTU is not 576" >&2; exit 2; }
ethtool -K eth0 tso off gso off >/dev/null 2>&1 || { echo "wireops: cannot disable segmentation offload" >&2; exit 2; }
ethtool -k eth0 | grep -qE '^tcp-segmentation-offload: off' || { echo "wireops: TSO still on" >&2; exit 2; }
ethtool -k eth0 | grep -qE '^generic-segmentation-offload: off' || { echo "wireops: GSO still on" >&2; exit 2; }

tcpdump -i eth0 -tt -n -w "$OUT/capture-$PHASE.pcap" 'tcp' >/dev/null 2>&1 &
TCPDUMP=$!
sleep 2

"/w/$ENGINE" < "/w/job-$PHASE.json" > "$OUT/observations-$PHASE.jsonl" 2>"$OUT/engine-$PHASE.err" &
ENG=$!
if [ -n "$KILL_AFTER" ]; then
	sleep "$KILL_AFTER"
	kill -TERM "$ENG" 2>/dev/null || true
fi
wait "$ENG" || true

sleep 2
kill "$TCPDUMP" 2>/dev/null || true
wait "$TCPDUMP" 2>/dev/null || true
