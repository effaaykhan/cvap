#!/bin/sh
# Capture egress while ONE job runs through the scan-point runtime's send-path
# scope check (runtimedrive), then leave the pcap for safety_scope.py to judge.
#
# The narrow gate's run.sh runs an engine directly; this runs runtimedrive, which
# instantiates the real engineHost — ADR-024's second enforcement site — and
# spawns the engine only for targets that site authorised. The judgement is made
# OUTSIDE, so the thing under test cannot influence the verdict.
set -e

ENGINE="$1"   # engine binary name under /w (runtimedrive spawns it)
PHASE="$2"

OUT=/w/out
mkdir -p "$OUT"

# -tt for epoch timestamps: the scope-changed-mid-scan case compares how much
# egress a stopped run produced against an unstopped one, and needs the times.
# Same filter as run.sh: this engine's TCP plus resolver UDP/53, which for the
# hostname case MUST be empty — a name the runtime refused is never resolved.
tcpdump -i any -tt -n -w "$OUT/capture-$PHASE.pcap" 'tcp or udp port 53' >/dev/null 2>&1 &
TCPDUMP=$!
sleep 2

# Bounded: a hung engine must not stall the gate. 45s is far beyond any single
# job here (the slowest is the filtered host at a 3s connect timeout), so hitting
# it is a defect to see, not a scan legitimately still running.
timeout 45 /w/runtimedrive "/w/$ENGINE" < "/w/job-$PHASE.json" \
	> "$OUT/result-$PHASE.json" 2>"$OUT/drive-$PHASE.err" || true

sleep 1
kill "$TCPDUMP" 2>/dev/null || true
wait "$TCPDUMP" 2>/dev/null || true
