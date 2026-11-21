#!/bin/bash
# Step-20 T1: flip_repro on the fixed build (coraza v3.8.1), 5x500 at PL1 and
# PL2 (docs/plan-dup-args.md fix protocol), plus a v3.7.0 PL1 comparison run.
# Per-round statuses are saved (--out) so a PL1 "pass" is provably a 200
# pass-through to the stub, not a transport error. Stub backend must already
# run on 127.0.0.1:13000 (tools/stub_backend.py, answers 200 to GET and POST).
# Usage: run_step20_t1_flip.sh <binary> <tag> <rounds> "<pls>"
set -u
cd "$(dirname "$0")/.."
BIN=${1:-out/s20-t1/engine-v381}
TAG=${2:-v381}
ROUNDS=${3:-500}
PLS=${4:-"1 2"}
REPS=${5:-5}
PORT=8093
RUNDIR=docs/logs/runs/s20-t1-flip-$TAG
mkdir -p "$RUNDIR"
echo "== flip_repro $TAG bin=$BIN sha256=$(sha256sum "$BIN" | cut -d' ' -f1) rounds=$ROUNDS reps=$REPS pls=$PLS =="
for PL in $PLS; do
  EV=$RUNDIR/events-pl$PL.jsonl; rm -f "$EV"
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
    KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$PL KORTEX_DETECTION_PARANOIA=$PL \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
    KORTEX_ENGINE_TIME_BUDGET_MS=2000 KORTEX_LISTEN_ADDR=127.0.0.1:$PORT \
    KORTEX_EVENTS_FILE=$EV KORTEX_AUDIT_LOG=$RUNDIR/audit-pl$PL.log \
    "$BIN" >"$RUNDIR/engine-pl$PL.log" 2>&1 &
  EP=$!
  for i in $(seq 1 40); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$PORT/ && break; sleep 0.5; done
  echo "== $TAG PL$PL rule29: $(grep -o 'effective config:.*' "$RUNDIR/engine-pl$PL.log" | head -1)"
  echo "load_start=[$(uptime | grep -o 'load average.*')]"
  for R in $(seq 1 "$REPS"); do
    .venv/bin/python tools/flip_repro.py --base-url http://127.0.0.1:$PORT --rounds "$ROUNDS" \
      --out "$RUNDIR/rounds-pl$PL-r$R.jsonl" 2>/dev/null | tail -1
  done
  echo "load_end=[$(uptime | grep -o 'load average.*')]"
  kill $EP 2>/dev/null; wait $EP 2>/dev/null
done
echo "FLIP-$TAG-DONE"
