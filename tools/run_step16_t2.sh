#!/bin/bash
# Step-16 T2: re-run all five datasets at PL1/PL2 on the FIXED engine and on
# the connector reference, into NEW dirs (step-15 T6 artifacts preserved).
# Engine side follows tools/run_step15_t6.sh (marker kortex-decision=block,
# block-status 403; 400 denies classify as waf_deny_status via the audit).
# Ref side follows tools/run_coraza_parity.sh (fresh container per run, rule
# 13; rule-29 effective-config line printed per run).
# Usage: bash tools/run_step16_t2.sh   (ENGINE_ONLY=1 skips the ref side)
set -u
cd /home/Kavinharish/kortexshield
RUN=docs/logs/step16-t2-runs.txt
mkdir -p out
: > $RUN

# Same UA for BOTH sides (harness parity): the CRS missing-user-agent rule
# 920320 (NOTICE, +2 at PL2) fires when the request has no User-Agent, which
# flips marginal warning-score detections to blocks. The first T2 engine run
# omitted the UA (script bug, found 2026-11-20): the engine saw UA-less
# requests while the connector saw the Chrome UA. Fixed here and re-run.
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

echo "== load average at start: $(uptime)" >> $RUN

start_engine() { # $1 = pl
  local pl=$1
  rm -f /tmp/kx16-events-$pl.jsonl /tmp/kx16-audit-$pl.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR=/home/Kavinharish/kortexshield/engine/crs \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
  KORTEX_EVENTS_FILE=/tmp/kx16-events-$pl.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx16-audit-$pl.log \
  /tmp/kortex-engine > /tmp/kx16-engine-$pl.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do
    sleep 1
    curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break
  done
  echo "== engine effective config (PL$pl):" >> $RUN
  cat /tmp/kx16-engine-$pl.log >> $RUN
  echo "== /__kortex/config:" >> $RUN
  curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
  echo >> $RUN
}

stop_engine() {
  kill $EPID 2>/dev/null || true
  wait $EPID 2>/dev/null || true
}

# --- engine side ---
export PATH=$PATH:/usr/local/go/bin
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine .) || { echo "BUILD FAILED" >> $RUN; exit 1; }
echo "== engine binary rebuilt: $(md5sum /tmp/kortex-engine)" >> $RUN

for PL in 1 2; do
  start_engine $PL
  for DS in smoke attacks-v0 benign-browse-v1 benign-hard-v0 attacks-ct-v0; do
    echo "== run engine $DS pl$PL $(date -u +%FT%TZ)" >> $RUN
    echo "events-before=$(wc -l < /tmp/kx16-events-$PL.jsonl 2>/dev/null || echo 0) audit-before=$(grep -c '"transaction"' /tmp/kx16-audit-$PL.log 2>/dev/null || echo 0)" >> $RUN
    .venv/bin/python -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
      --base-url http://localhost:8090 --out out/s16-t2-engine-$DS-pl$PL \
      --timeout 30 --workers 1 --block-status 403 \
      --block-marker 'kortex-decision=block' \
      --default-user-agent "$UA" >> $RUN 2>&1
    echo "events-after=$(wc -l < /tmp/kx16-events-$PL.jsonl 2>/dev/null || echo 0) audit-after=$(grep -c '"transaction"' /tmp/kx16-audit-$PL.log 2>/dev/null || echo 0)" >> $RUN
    cp /tmp/kx16-audit-$PL.log out/s16-t2-engine-$DS-pl$PL/engine-audit-full.log
    cp /tmp/kx16-events-$PL.jsonl out/s16-t2-engine-$DS-pl$PL/kortex-events-full.jsonl 2>/dev/null || true
  done
  stop_engine
done

# --- connector reference side ---
UA="${UA}"  # defined above; kept for the ref-side invocation below
run_ref() {  # $1=dataset name $2=manifest $3=paranoia level
  docker compose -f deploy/compose.yml down > /dev/null 2>&1 || true
  for try in 1 2 3; do
    MODSEC_RULE_ENGINE=On PARANOIA=$3 BLOCKING_PARANOIA=$3 DETECTION_PARANOIA=$3 \
      CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
      docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null
    sleep 8
    if curl -s -o /dev/null --max-time 5 http://localhost:8082/; then break; fi
    echo "coraza container not answering (try $try) - retrying" >> $RUN
  done
  docker exec deploy-coraza-crs-1 sh -c 'echo "rule29-coraza: E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA env_CT=[$ALLOWED_REQUEST_CONTENT_TYPE] env_body=[nofiles=$CORAZA_REQ_BODY_NOFILES_LIMIT total=$CORAZA_REQ_BODY_LIMIT]"; grep -A8 "id:900000" /opt/coraza/config/crs-setup.conf | grep -o "tx.blocking_paranoia_level=[0-9]*"; grep -A8 "id:900001" /opt/coraza/config/crs-setup.conf | grep -o "tx.detection_paranoia_level=[0-9]*"; grep -o "tx.crs_setup_version=[0-9]*" /opt/coraza/config/crs-setup.conf' >> $RUN 2>&1
  curl -s -o /dev/null -w "pre-run probe: %{http_code}\n" http://localhost:8082/ >> $RUN
  .venv/bin/python -m kortex_eval.runner --manifest "$2" --base-url http://localhost:8082 \
    --out "out/s16-t2-coraza-$1-pl$3" --timeout 15 --workers 1 \
    --default-user-agent "$UA" --label engine=coraza --label paranoia=$3 \
    --label stub_drain=fixed --label body_limit=131072 >> $RUN 2>&1 \
    || echo "runner exited non-zero (sample errors); continuing audit processing" >> $RUN
  docker cp deploy-coraza-crs-1:/var/log/coraza/audit/audit.log "out/s16-t2-coraza-$1-pl$3/coraza-audit.log"
  .venv/bin/python tools/coraza_audit.py --logs "out/s16-t2-coraza-$1-pl$3/coraza-audit.log" --out "out/s16-t2-coraza-$1-pl$3/audit.jsonl" >> $RUN 2>&1
  .venv/bin/python -m kortex_eval.outcome --responses "out/s16-t2-coraza-$1-pl$3/responses.jsonl" \
    --audit "out/s16-t2-coraza-$1-pl$3/audit.jsonl" --out "out/s16-t2-coraza-$1-pl$3/outcomes.jsonl" --engine-mode blocking >> $RUN 2>&1
  echo "=== done coraza $1 pl$3" >> $RUN
}

if [ "${ENGINE_ONLY:-0}" != "1" ]; then
for PL in 1 2; do
  for DS in smoke attacks-v0 benign-browse-v1 benign-hard-v0 attacks-ct-v0; do
    run_ref $DS data/$DS/manifest.jsonl $PL
  done
done
fi

echo "== load average at end: $(uptime)" >> $RUN
if [ "${ENGINE_ONLY:-0}" = "1" ]; then echo ENGINE-ONLY-DONE >> $RUN; else echo ALL-DONE >> $RUN; fi
