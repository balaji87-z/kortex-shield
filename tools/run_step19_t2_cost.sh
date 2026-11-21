#!/bin/bash
# Step-19 T2: abandoned-call cost at the shipping configuration.
# PRE (1964793) vs POST engine, 3 reps each, uncontended, PL1 and PL2,
# budget 120 s so the body-processing call finishes.
# Bodies: text/plain (wcp-80a49c991b2d prefix) and benign JSON,
# exact sizes 16384/32768/65536/131072/131071 bytes.
set -u
cd "$(dirname "$0")/.."
OUT=docs/logs/step19-t2-cost.txt
PORT=8101
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
SIZES="16384 32768 65536 131072 131071"

: > $OUT
echo "== T2 cost: $(date -u +%FT%TZ) budget=120000ms uncontended, sequential ==" | tee -a $OUT

run_engine() { # $1=pre|post $2=pl $3=rep
  local which=$1 pl=$2 rep=$3 bin
  if [ "$which" = pre ]; then bin=/tmp/kortex-engine-prefix; else bin=/tmp/kortex-engine-v2; fi
  local ev=/tmp/kx-t2-ev.jsonl
  rm -f $ev
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
    KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
    KORTEX_ENGINE_TIME_BUDGET_MS=120000 KORTEX_LISTEN_ADDR=127.0.0.1:$PORT \
    KORTEX_EVENTS_FILE=$ev KORTEX_AUDIT_LOG=/tmp/kx-t2-audit.log \
    $bin >/tmp/kx-t2-$which-$pl-$rep.log 2>&1 &
  local pid=$!
  sleep 1.5
  for size in $SIZES; do
    for kind in textplain json; do
      local f=/tmp/kx-bodies/$kind-$size.bin
      [ -f "$f" ] || f=/tmp/kx-bodies/$kind-$size.json
      local ct="text/plain"; [ "$kind" = json ] && ct="application/json"
      local t
      t=$(curl -s -o /dev/null -w "%{http_code} %{time_total}" -X POST \
        -H "Content-Type: $ct" -H "X-Kortex-Sample-Id: t2-$which-$pl-$rep-$kind-$size" \
        -H "User-Agent: $UA" --data-binary @"$f" http://127.0.0.1:$PORT/)
      local la
      la=$(uptime | grep -o "load average.*")
      echo "$which pl=$pl rep=$rep $kind size=$size -> $t load=[$la]" | tee -a $OUT
    done
  done
  kill $pid 2>/dev/null; wait $pid 2>/dev/null
  local rundir=docs/logs/runs/s19-t2-$which-pl$pl-rep$rep
  mkdir -p $rundir; cp $ev $rundir/events.jsonl 2>/dev/null
  cp /tmp/kx-t2-$which-$pl-$rep.log $rundir/engine.log 2>/dev/null
}

for rep in 1 2 3; do
  for which in pre post; do
    for pl in 1 2; do
      run_engine $which $pl $rep
    done
  done
done
echo "T2-COST-DONE" | tee -a $OUT
