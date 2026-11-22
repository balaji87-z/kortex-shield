#!/bin/bash
# Step-21 T3: decision parity worker-mode vs in-process on 5 datasets (PL1)
# + flip_repro at PL2 in worker mode. Zero-diff is the acceptance bar.
set -u
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
OUT=docs/logs/runs/s21-t3-parity
mkdir -p $OUT
: > docs/logs/step21-t3-parity.txt

ps aux | grep stub200 | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done; sleep 1
setsid nohup python3 /tmp/stub200.py >/tmp/stub200.log 2>&1 &
sleep 1
curl -s -o /dev/null -X POST --max-time 2 http://127.0.0.1:13000/ || { echo "BACKEND NO RESPONDE"; exit 1; }

run_engine() { # $1=mode(inprocess|worker) $2=port $3=pl
  local mode=$1 port=$2 pl=$3
  local extra=""
  [ "$mode" = worker ] && extra="KORTEX_WORKER_MODE=on"
  env KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
    KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
    KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_MAX_INFLIGHT_BODY_LARGE=2 KORTEX_BODY_LANE_THRESHOLD=65536 \
    KORTEX_ENGINE_TIME_BUDGET_MS=2000 KORTEX_LISTEN_ADDR=127.0.0.1:$port \
    KORTEX_EVENTS_FILE=/tmp/kx-t3p-ev-$mode.jsonl KORTEX_AUDIT_LOG=/tmp/kx-t3p-aud-$mode.log \
    $extra /tmp/kortex-engine > $OUT/engine-$mode.log 2>&1 &
  for i in $(seq 1 60); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$port/ && return 0; sleep 0.5; done
  echo "engine $mode no levanto" && return 1
}

kill_engines() {
  ps aux | grep kortex-engine | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done
  sleep 1
}

DATASETS="attacks-v0 attacks-ct-v0 encoding-diff-v0 benign-browse-v1 benign-hard-v0"
for DS in $DATASETS; do
  for MODE in inprocess worker; do
    PORT=8097; [ "$MODE" = worker ] && PORT=8098
    kill_engines
    run_engine $MODE $PORT 1 || continue
    echo "== $DS [$MODE] rule29: $(curl -s http://127.0.0.1:$PORT/__kortex/config)" | tee -a docs/logs/step21-t3-parity.txt
    .venv/bin/python -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
      --base-url http://127.0.0.1:$PORT --out $OUT/$DS-$MODE --timeout 15 --workers 1 \
      --default-user-agent "$UA" --label engine=kortex --label mode=$MODE --label paranoia=1 \
      > $OUT/$DS-$MODE.runner.log 2>&1 || echo "runner nonzero (sample errors); continuing"
    kill_engines
  done
  echo "== diff $DS:" | tee -a docs/logs/step21-t3-parity.txt
  .venv/bin/python tools/step21_engine_diff.py $OUT/$DS-inprocess $OUT/$DS-worker \
    2>&1 | tee -a docs/logs/step21-t3-parity.txt
done
echo PARITY-DONE
