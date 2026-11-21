#!/bin/bash
# Step-19 T4: benign-wcp-v1 (HELD-OUT) — PRE y POST engine, PL1 y PL2, 2 runs cada uno.
# Contrato idéntico al step-18 (UA, marker, workers 1, engine fresco por run,
# prueba de config efectiva por run — regla 29 — y preservación — regla 42).
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step19-t4-runs.txt
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
DS=benign-wcp-v1

echo "== step-19 T4 runs on $DS — start $(date -u +%FT%TZ)" >> $RUN
echo "== load average at start: $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx19-stub-13000.log 2>&1 &)
  sleep 1
fi

start_engine() { # $1=binario $2=pl $3=tag
  local bin=$1 pl=$2 tag=$3
  rm -f /tmp/kx19t4-ev-$tag.jsonl /tmp/kx19t4-aud-$tag.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR="$PWD/engine/crs" \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
  KORTEX_EVENTS_FILE=/tmp/kx19t4-ev-$tag.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx19t4-aud-$tag.log \
  $bin > /tmp/kx19t4-eng-$tag.log 2>&1 &
  EPID=$!
  for i in $(seq 1 30); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break; done
  echo "== engine effective config ($tag): $(grep -o 'mode=[A-Za-z]*\|blocking_paranoia=[0-9]*\|detection_paranoia=[0-9]*\|max_inflight_body=[0-9]*\|engine_time_budget_ms=[0-9]*\|request_body_target_updates=[0-9]*' /tmp/kx19t4-eng-$tag.log | sort -u | tr '\n' ' ')" >> $RUN
  curl -s http://127.0.0.1:8090/__kortex/config >> $RUN; echo >> $RUN
}
stop_engine() { kill $EPID 2>/dev/null; wait $EPID 2>/dev/null; }

run_one() { # $1=tag $2=pl
  local tag=$1 pl=$2
  echo "== run $tag pl$pl $(date -u +%FT%TZ)" >> $RUN
  .venv/bin/python -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
    --base-url http://localhost:8090 --out out/s19-t4-$DS-$tag-pl$pl \
    --timeout 30 --workers 1 --block-status 403 \
    --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" >> $RUN 2>&1
  local O=out/s19-t4-$DS-$tag-pl$pl
  cp /tmp/kx19t4-aud-$tag.log $O/engine-audit-full.log
  cp /tmp/kx19t4-ev-$tag.jsonl $O/kortex-events-full.jsonl 2>/dev/null || true
  .venv/bin/python -m kortex_eval.crs_audit --logs $O/engine-audit-full.log \
    --out $O/audit.jsonl >> $RUN 2>&1
  .venv/bin/python -m kortex_eval.outcome --responses $O/responses.jsonl \
    --audit $O/audit.jsonl --out $O/outcomes.jsonl --engine-mode blocking >> $RUN 2>&1
  tools/preserve_run.sh $O
}

# POST (engine actual, 166 updates) — 2 runs por PL
for PL in 1 2; do
  for R in 1 2; do
    start_engine /tmp/kortex-engine-v2 $PL post-r$R
    run_one post-r$R $PL
    stop_engine
  done
done
# PRE (worktree 1964793, sin updates) — 2 runs por PL
for PL in 1 2; do
  for R in 1 2; do
    start_engine /tmp/kortex-engine-prefix $PL pre-r$R
    run_one pre-r$R $PL
    stop_engine
  done
done
echo "== load average at end: $(uptime)" >> $RUN
echo T4-RUNS-DONE >> $RUN
