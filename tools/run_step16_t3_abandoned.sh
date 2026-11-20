#!/bin/bash
# Step-16 T3 addendum: single replay of the wcp body against ONE fresh engine,
# watching when the abandoned ProcessRequestBody call actually finishes
# (instrumented abandoned-body-processing-finished event).
set -u
cd /home/Kavinharish/kortexshield
pkill -f kortex-engine 2>/dev/null; sleep 1
(cd /tmp && python3 -m http.server 13001 > /tmp/kxstub16.log 2>&1 &)
sleep 1
rm -f /tmp/kxt3e-events.jsonl /tmp/kxt3e-audit.log
KORTEX_BACKEND_URL=http://127.0.0.1:13001 \
KORTEX_RULES_DIR=/home/Kavinharish/kortexshield/engine/crs \
KORTEX_RULE_ENGINE=On \
KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=13107200 \
KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
KORTEX_LISTEN_ADDR=127.0.0.1:8101 \
KORTEX_EVENTS_FILE=/tmp/kxt3e-events.jsonl \
KORTEX_AUDIT_LOG=/tmp/kxt3e-audit.log \
/tmp/kortex-engine > /tmp/kxt3e-engine.log 2>&1 &
EPID=$!
sleep 2
head -1 /tmp/kxt3e-engine.log
grep -c . /tmp/kxt3e-engine.log
curl -s -o /dev/null -w "replay: status=%{http_code} time_total_s=%{time_total}\n" --max-time 30 \
  -H 'X-Kortex-Sample-Id: t3e-single' -H 'Content-Type: text/plain' \
  --data-binary @/home/Kavinharish/kortexshield/out/step14-t5/wcp-80a49c991b2d.body http://127.0.0.1:8101/
for i in $(seq 1 24); do
  sleep 5
  if grep -q abandoned-body-processing-finished /tmp/kxt3e-events.jsonl 2>/dev/null; then
    echo "abandoned call finished at ~t+$((i*5))s:"; cat /tmp/kxt3e-events.jsonl; break
  fi
  echo "t+$((i*5))s: no abandoned-finished event yet"
done
kill $EPID 2>/dev/null
pkill -f "http.server 13001" 2>/dev/null
echo MEASURE-DONE
