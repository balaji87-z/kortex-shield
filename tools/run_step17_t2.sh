#!/bin/bash
# Step-17 T2: re-run smoke + benign-browse-v1 at PL1 on the engine WITH the
# method allow-list (KORTEX_ALLOWED_METHODS -> CRS 911100 via tx.allowed_methods).
# Engine-only: the connector reference is unchanged (s16-t2 ref runs reused).
# Same UA contract and marker contract as tools/run_step16_t2.sh.
set -u
cd /home/Kavinharish/kortexshield
RUN=docs/logs/step17-t2-runs.txt
mkdir -p out
: > $RUN

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

echo "== load average at start: $(uptime)" >> $RUN

# stub backend on 13000 (compose stack is down after the redeploy)
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx17-stub-13000.log 2>&1 &)
  sleep 1
fi
curl -s -o /dev/null -w "stub probe: %{http_code}\n" http://127.0.0.1:13000/ >> $RUN

export PATH=$PATH:/usr/local/go/bin
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine .) || { echo "BUILD FAILED" >> $RUN; exit 1; }
echo "== engine binary rebuilt: $(md5sum /tmp/kortex-engine)" >> $RUN

PL=1
rm -f /tmp/kx17t2-events.jsonl /tmp/kx17t2-audit.log
KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
KORTEX_RULES_DIR=/home/Kavinharish/kortexshield/engine/crs \
KORTEX_RULE_ENGINE=On \
KORTEX_BLOCKING_PARANOIA=$PL KORTEX_DETECTION_PARANOIA=$PL \
KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
KORTEX_EVENTS_FILE=/tmp/kx17t2-events.jsonl \
KORTEX_AUDIT_LOG=/tmp/kx17t2-audit.log \
/tmp/kortex-engine > /tmp/kx17t2-engine.log 2>&1 &
EPID=$!
for i in $(seq 1 20); do
  sleep 1
  curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break
done
echo "== engine effective config (PL$PL):" >> $RUN
cat /tmp/kx17t2-engine.log >> $RUN
echo "== /__kortex/config:" >> $RUN
curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
echo >> $RUN

for DS in smoke benign-browse-v1; do
  echo "== run engine $DS pl$PL $(date -u +%FT%TZ)" >> $RUN
  echo "events-before=$(wc -l < /tmp/kx17t2-events.jsonl 2>/dev/null || echo 0) audit-before=$(grep -c '"transaction"' /tmp/kx17t2-audit.log 2>/dev/null || echo 0)" >> $RUN
  .venv/bin/python -m kortex_eval.runner --manifest data/$DS/manifest.jsonl \
    --base-url http://localhost:8090 --out out/s17-t2-engine-$DS-pl$PL \
    --timeout 30 --workers 1 --block-status 403 \
    --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" >> $RUN 2>&1
  echo "events-after=$(wc -l < /tmp/kx17t2-events.jsonl 2>/dev/null || echo 0) audit-after=$(grep -c '"transaction"' /tmp/kx17t2-audit.log 2>/dev/null || echo 0)" >> $RUN
  cp /tmp/kx17t2-audit.log out/s17-t2-engine-$DS-pl$PL/engine-audit-full.log
  cp /tmp/kx17t2-events.jsonl out/s17-t2-engine-$DS-pl$PL/kortex-events-full.jsonl 2>/dev/null || true
done

kill $EPID 2>/dev/null || true
wait $EPID 2>/dev/null || true
echo "== load average at end: $(uptime)" >> $RUN
echo ALL-DONE >> $RUN
