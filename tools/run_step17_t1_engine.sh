#!/bin/bash
# Step-17 T1 replay: attacks-ct-v0 through the ENGINE at PL1/PL2 (default
# config), into NEW dirs. Re-measures the C4 per-carrier table on the current
# host (the s16-t2 engine runs it re-checks were produced on the lab host and
# live only in gitignored out/ there). Same UA contract and marker contract
# as tools/run_step16_t2.sh; rule-29 config proof printed per run.
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step17-t1-engine-runs.txt
mkdir -p out
: > $RUN

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

echo "== load average at start: $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx17-stub-13000.log 2>&1 &)
  sleep 1
fi
curl -s -o /dev/null -w "stub probe: %{http_code}\n" http://127.0.0.1:13000/ >> $RUN

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine .) || { echo "BUILD FAILED" >> $RUN; exit 1; }
echo "== engine binary: $(md5sum /tmp/kortex-engine)" >> $RUN

start_engine() { # $1 = pl
  local pl=$1
  rm -f /tmp/kx17t1-events-$pl.jsonl /tmp/kx17t1-audit-$pl.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR="$PWD/engine/crs" \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
  KORTEX_EVENTS_FILE=/tmp/kx17t1-events-$pl.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx17t1-audit-$pl.log \
  /tmp/kortex-engine > /tmp/kx17t1-engine-$pl.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do
    sleep 1
    curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break
  done
  echo "== engine effective config (PL$pl):" >> $RUN
  cat /tmp/kx17t1-engine-$pl.log >> $RUN
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
  echo "== run engine attacks-ct-v0 pl$PL $(date -u +%FT%TZ)" >> $RUN
  .venv/bin/python -m kortex_eval.runner --manifest data/attacks-ct-v0/manifest.jsonl \
    --base-url http://localhost:8090 --out out/s17-t1-engine-attacks-ct-v0-pl$PL \
    --timeout 30 --workers 1 --block-status 403 \
    --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" >> $RUN 2>&1
  cp /tmp/kx17t1-audit-$PL.log out/s17-t1-engine-attacks-ct-v0-pl$PL/engine-audit-full.log
  cp /tmp/kx17t1-events-$PL.jsonl out/s17-t1-engine-attacks-ct-v0-pl$PL/kortex-events-full.jsonl 2>/dev/null || true
  .venv/bin/python -m kortex_eval.crs_audit --logs out/s17-t1-engine-attacks-ct-v0-pl$PL/engine-audit-full.log \
    --out out/s17-t1-engine-attacks-ct-v0-pl$PL/audit.jsonl >> $RUN 2>&1
  .venv/bin/python -m kortex_eval.outcome --responses out/s17-t1-engine-attacks-ct-v0-pl$PL/responses.jsonl \
    --audit out/s17-t1-engine-attacks-ct-v0-pl$PL/audit.jsonl \
    --out out/s17-t1-engine-attacks-ct-v0-pl$PL/outcomes.jsonl --engine-mode blocking >> $RUN 2>&1
  stop_engine
done

echo "== load average at end: $(uptime)" >> $RUN
echo ALL-DONE >> $RUN
