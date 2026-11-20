#!/bin/bash
# Step-16 T3 measurements on the FIXED engine (budget-bounded body processing):
#  1. single wcp body replay: 503 within budget+500ms; abandoned-call finish
#     time from the events log (DoS-risk evidence)
#  2. 20 concurrent copies of the same body: all answered, none wedging the
#     engine; benign-request latency before/after
# Run after the T2 re-run has finished (load average hygiene, rule 38).
set -u
cd /home/Kavinharish/kortexshield
RUN=docs/logs/step16-t3-runs.txt
BODY=out/step14-t5/wcp-80a49c991b2d.body
: > $RUN
echo "# RE-RUN 2026-11-20: E17 showed the first pass measured the handler tx.Close()" >> $RUN
echo "# killing the abandoned call (finished at budget+12ms, stale 949110). This" >> $RUN
echo "# re-run measures the real abandoned-call behaviour after the ownership fix." >> $RUN
echo "== load average at start: $(uptime)" >> $RUN

(cd engine && export PATH=$PATH:/usr/local/go/bin && go build -buildvcs=false -o /tmp/kortex-engine .) || exit 1
(cd /tmp && python3 -m http.server 13001 > /tmp/kxstub16.log 2>&1 &) 
sleep 1
rm -f /tmp/kxt3-events.jsonl /tmp/kxt3-audit.log
KORTEX_BACKEND_URL=http://127.0.0.1:13001 \
KORTEX_RULES_DIR=/home/Kavinharish/kortexshield/engine/crs \
KORTEX_RULE_ENGINE=On \
KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=13107200 \
KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
KORTEX_LISTEN_ADDR=127.0.0.1:8098 \
KORTEX_EVENTS_FILE=/tmp/kxt3-events.jsonl \
KORTEX_AUDIT_LOG=/tmp/kxt3-audit.log \
/tmp/kortex-engine > /tmp/kxt3-engine.log 2>&1 &
EPID=$!
sleep 2
echo "== engine effective config:" >> $RUN
cat /tmp/kxt3-engine.log >> $RUN
echo "body bytes: $(wc -c < $BODY)" >> $RUN

echo "== single replay (budget 2000ms):" >> $RUN
curl -s -o /tmp/kxt3-single.out -w "status=%{http_code} time_total_s=%{time_total}\n" \
  -H 'X-Kortex-Sample-Id: t3-single' -H 'Content-Type: text/plain' \
  --data-binary @$BODY http://127.0.0.1:8098/ >> $RUN
head -c 60 /tmp/kxt3-single.out >> $RUN; echo >> $RUN
# wait for the abandoned call to finish and log it (worst case ~45s)
for i in $(seq 1 60); do
  grep -q abandoned-body-processing-finished /tmp/kxt3-events.jsonl 2>/dev/null && break
  sleep 1
done
echo "== events after single replay:" >> $RUN
cat /tmp/kxt3-events.jsonl >> $RUN

echo "== benign latency before concurrency:" >> $RUN
curl -s -o /dev/null -w "benign status=%{http_code} time_total_s=%{time_total}\n" \
  http://127.0.0.1:8098/?q=hello >> $RUN

echo "== 20 concurrent copies:" >> $RUN
CURLPIDS=""
for i in $(seq 1 20); do
  curl -s -o /tmp/kxt3-conc-$i.out -w "copy$i status=%{http_code} time_total_s=%{time_total}\n" \
    -H "X-Kortex-Sample-Id: t3-conc-$i" -H 'Content-Type: text/plain' \
    --data-binary @$BODY http://127.0.0.1:8098/ >> $RUN &
  CURLPIDS="$CURLPIDS $!"
done
# wait only for the curls; the engine keeps running (first pass: a bare
# `wait` returned early because the tx.Close use-after-close CRASHED the
# engine - copy16 and the post-concurrency benign probe got status 000)
wait $CURLPIDS
grep -c "status=503" $RUN >> $RUN 2>/dev/null || true
echo "== benign latency +8s (20 abandoned ~45s CPU-bound goroutines running):" >> $RUN
sleep 8
curl -s -o /dev/null -w "benign status=%{http_code} time_total_s=%{time_total}\n" \
  http://127.0.0.1:8098/?q=hello >> $RUN
echo "== waiting 50s for the abandoned calls to finish" >> $RUN
sleep 50
echo "== events after concurrency (tail):" >> $RUN
tail -25 /tmp/kxt3-events.jsonl >> $RUN
echo "== benign latency after the abandoned calls finished:" >> $RUN
curl -s -o /dev/null -w "benign status=%{http_code} time_total_s=%{time_total}\n" \
  http://127.0.0.1:8098/?q=hello >> $RUN

kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
pkill -f "http.server 13001" 2>/dev/null
echo "== load average at end: $(uptime)" >> $RUN
echo ALL-DONE >> $RUN
