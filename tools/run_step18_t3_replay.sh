#!/bin/bash
# Step-18 T3: replay the 3 step-17 ConnectionResetError ids
# (wcp-1140885081e1, wcp-f83f7556fc66, wcp-908ef72be103 - all 413-limit ids,
# ~1.5 MB bodies) through the FIXED engine and report status + marker each.
# Same engine config, UA contract and marker contract as
# tools/run_step17_t4.sh (PL1; the step-17 errors were identical at both PLs).
# The filtered manifest is a derived input (frozen dataset untouched, rule 10).
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step18-t3-replay.txt
mkdir -p out
: > $RUN

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
IDS="wcp-1140885081e1 wcp-f83f7556fc66 wcp-908ef72be103"

echo "== load average at start: $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx18-stub-13000.log 2>&1 &)
  sleep 1
fi

export PATH=$PATH:$HOME/go/bin
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine .) || { echo "BUILD FAILED" >> $RUN; exit 1; }
echo "== engine binary: $(md5sum /tmp/kortex-engine) (includes the step-18 T3 drain fix)" >> $RUN

# frozen-manifest integrity proof (rule 29/10)
echo "== manifest sha: $(sha256sum data/benign-wcp-v0/MANIFEST.sha256 | cut -d' ' -f1) (frozen value below)" >> $RUN
cat data/benign-wcp-v0/MANIFEST.sha256 >> $RUN

grep -E "\"id\": \"(wcp-1140885081e1|wcp-f83f7556fc66|wcp-908ef72be103)\"" \
  data/benign-wcp-v0/manifest.jsonl > out/s18-t3-reset-ids.jsonl
echo "== filtered manifest lines: $(wc -l < out/s18-t3-reset-ids.jsonl)" >> $RUN

rm -f /tmp/kx18t3-events.jsonl /tmp/kx18t3-audit.log
KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
KORTEX_RULES_DIR="$PWD/engine/crs" \
KORTEX_RULE_ENGINE=On \
KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
KORTEX_EVENTS_FILE=/tmp/kx18t3-events.jsonl \
KORTEX_AUDIT_LOG=/tmp/kx18t3-audit.log \
/tmp/kortex-engine > /tmp/kx18t3-engine.log 2>&1 &
EPID=$!
for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break; done
echo "== engine effective config (PL1):" >> $RUN
cat /tmp/kx18t3-engine.log >> $RUN
echo "== /__kortex/config:" >> $RUN
curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
echo >> $RUN

echo "== replay 3 reset ids $(date -u +%FT%TZ)" >> $RUN
.venv/bin/python -m kortex_eval.runner --manifest out/s18-t3-reset-ids.jsonl \
  --base-url http://localhost:8090 --out out/s18-t3-reset-ids \
  --timeout 30 --workers 1 --block-status 403 \
  --block-marker 'kortex-decision=block' \
  --default-user-agent "$UA" >> $RUN 2>&1
cp /tmp/kx18t3-audit.log out/s18-t3-reset-ids/engine-audit-full.log
cp /tmp/kx18t3-events.jsonl out/s18-t3-reset-ids/kortex-events-full.jsonl 2>/dev/null || true
.venv/bin/python -m kortex_eval.crs_audit --logs out/s18-t3-reset-ids/engine-audit-full.log \
  --out out/s18-t3-reset-ids/audit.jsonl >> $RUN 2>&1
.venv/bin/python -m kortex_eval.outcome --responses out/s18-t3-reset-ids/responses.jsonl \
  --audit out/s18-t3-reset-ids/audit.jsonl \
  --out out/s18-t3-reset-ids/outcomes.jsonl --engine-mode blocking >> $RUN 2>&1

kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
echo "== load average at end: $(uptime)" >> $RUN
echo ALL-DONE >> $RUN
# Rule 42 (step-18): durable evidence copy before the next task starts.
tools/preserve_run.sh out/s18-t3-reset-ids
