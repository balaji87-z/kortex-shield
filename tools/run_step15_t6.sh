#!/bin/bash
# Step-15 T6 (DIAGNOSTIC): evaluate the engine skeleton on smoke, attacks-v0,
# benign-browse-v1, benign-hard-v0, attacks-ct-v0 at PL1/PL2.
# Block classification uses the engine's own marker (docs/block-discriminator.md):
# a first pass with the default nginx marker scored every engine block as
# blocked=false (status 403 was right, body marker was not) — see
# docs/logs/step15-t6-runs-firstpass-nginxmarker.txt.
# Usage: bash tools/run_step15_t6.sh
set -u
cd /home/Kavinharish/kortexshield
RUN=docs/logs/step15-t6-runs.txt
mkdir -p out
: > $RUN

start_engine() { # $1 = pl
  local pl=$1
  rm -f /tmp/kx-events-$pl.jsonl /tmp/kx-audit-$pl.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR=/home/Kavinharish/kortexshield/engine/crs \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
  KORTEX_EVENTS_FILE=/tmp/kx-events-$pl.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx-audit-$pl.log \
  /tmp/kortex-engine > /tmp/kx-engine-$pl.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do
    sleep 1
    curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break
  done
  echo "== engine effective config (PL$pl):" >> $RUN
  cat /tmp/kx-engine-$pl.log >> $RUN
  echo "== /__kortex/config:" >> $RUN
  curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
  echo >> $RUN
}

stop_engine() {
  kill $EPID 2>/dev/null || true
  wait $EPID 2>/dev/null || true
}

for PL in 1 2; do
  start_engine $PL
  for DS in smoke attacks-v0 benign-browse-v1 benign-hard-v0 attacks-ct-v0; do
    echo "== run engine $DS pl$PL $(date -u +%FT%TZ)" >> $RUN
    echo "events-before=$(wc -l < /tmp/kx-events-$PL.jsonl 2>/dev/null || echo 0) audit-before=$(grep -c '"transaction"' /tmp/kx-audit-$PL.log 2>/dev/null || echo 0)" >> $RUN
    .venv/bin/python -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
      --base-url http://localhost:8090 --out out/s15-t6-engine-$DS-pl$PL \
      --timeout 30 --workers 1 --block-status 403 \
      --block-marker 'kortex-decision=block' >> $RUN 2>&1
    echo "events-after=$(wc -l < /tmp/kx-events-$PL.jsonl 2>/dev/null || echo 0) audit-after=$(grep -c '"transaction"' /tmp/kx-audit-$PL.log 2>/dev/null || echo 0)" >> $RUN
    cp /tmp/kx-audit-$PL.log out/s15-t6-engine-$DS-pl$PL/engine-audit-full.log
    cp /tmp/kx-events-$PL.jsonl out/s15-t6-engine-$DS-pl$PL/kortex-events-full.jsonl 2>/dev/null || true
  done
  stop_engine
done
echo ALL-DONE >> $RUN
