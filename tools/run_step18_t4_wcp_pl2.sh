#!/bin/bash
# Step-18 T4 recovery: re-run benign-wcp-v0 POST-fix at PL2 only (the first
# attempt was killed by a platform restart mid-run; /tmp was wiped). Same
# config/UA/marker contract as tools/run_step18_t4.sh; evidence appended to
# the same run log. PL1 post-fix WCP completed and is preserved.
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step18-t4-runs.txt

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

echo "== load average at start (WCP PL2 recovery): $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx18-stub-13000.log 2>&1 &)
  sleep 1
fi
export PATH=$PATH:$HOME/go/bin
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine-post .) || { echo "POST BUILD FAILED" >> $RUN; exit 1; }
echo "== POST engine binary rebuilt: $(md5sum /tmp/kortex-engine-post)" >> $RUN

rm -f /tmp/kx18t4-events-post-2.jsonl /tmp/kx18t4-audit-post-2.log
KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
KORTEX_RULES_DIR="$PWD/engine/crs" \
KORTEX_RULE_ENGINE=On \
KORTEX_BLOCKING_PARANOIA=2 KORTEX_DETECTION_PARANOIA=2 \
KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
KORTEX_EVENTS_FILE=/tmp/kx18t4-events-post-2.jsonl \
KORTEX_AUDIT_LOG=/tmp/kx18t4-audit-post-2.log \
/tmp/kortex-engine-post > /tmp/kx18t4-engine-post-2.log 2>&1 &
EPID=$!
for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break; done
echo "== engine effective config (post PL2, recovery):" >> $RUN
cat /tmp/kx18t4-engine-post-2.log >> $RUN
echo "== /__kortex/config:" >> $RUN
curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
echo >> $RUN

echo "== run engine benign-wcp-v0 post pl2 (recovery) $(date -u +%FT%TZ)" >> $RUN
.venv/bin/python -m kortex_eval.runner --manifest data/benign-wcp-v0/manifest.jsonl \
  --base-url http://localhost:8090 --out out/s18-t4-engine-benign-wcp-v0-post-pl2 \
  --timeout 30 --workers 1 --block-status 403 \
  --block-marker 'kortex-decision=block' \
  --default-user-agent "$UA" >> $RUN 2>&1
cp /tmp/kx18t4-audit-post-2.log out/s18-t4-engine-benign-wcp-v0-post-pl2/engine-audit-full.log
cp /tmp/kx18t4-events-post-2.jsonl out/s18-t4-engine-benign-wcp-v0-post-pl2/kortex-events-full.jsonl 2>/dev/null || true
.venv/bin/python -m kortex_eval.crs_audit --logs out/s18-t4-engine-benign-wcp-v0-post-pl2/engine-audit-full.log \
  --out out/s18-t4-engine-benign-wcp-v0-post-pl2/audit.jsonl >> $RUN 2>&1
.venv/bin/python -m kortex_eval.outcome --responses out/s18-t4-engine-benign-wcp-v0-post-pl2/responses.jsonl \
  --audit out/s18-t4-engine-benign-wcp-v0-post-pl2/audit.jsonl \
  --out out/s18-t4-engine-benign-wcp-v0-post-pl2/outcomes.jsonl --engine-mode blocking >> $RUN 2>&1
kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
tools/preserve_run.sh out/s18-t4-engine-benign-wcp-v0-post-pl2
echo "== load average at end (WCP PL2 recovery): $(uptime)" >> $RUN
echo WCP-PL2-RECOVERED >> $RUN
