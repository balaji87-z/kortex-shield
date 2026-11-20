#!/bin/bash
# Step-17 T3 measurement (v2): in-flight body-processing cap.
#
# The lab container was twice restarted by the platform while 20 abandoned
# body-processing goroutines ground ~840 CPU-s for ~3.5 minutes
# (docs/logs/step17-t3-runs-firstpass.txt ends mid-run at 11:31 and 11:53;
# container "up 0 min" at 12:17). v2 therefore splits the measurement into
# SHORT grind phases and kills the engine promptly after each:
#   Phase A  cap=32 (raised), 20 concurrent 481,798-byte bodies: CPU seconds
#            from /proc/<pid>/stat at start / deadline (+2 s) / +60 s; benign
#            latency before / at-deadline / +8 s / +59 s; engine killed at
#            +60 s (the 20 abandoned calls die with it - their finish events
#            are captured in phases A2/B instead).
#   Phase A2 cap=32, 4 concurrent copies (reduced wave): wait for the
#            abandoned-body-processing-finished events and record elapsed_ms.
#   Phase B  cap=8 (default), 20 concurrent copies: expect 8 processed
#            (abandoned) + 12 x 503 kortex-decision=overload; benign probe
#            during the overload window; then wait up to 150 s for the 8
#            finish events; benign after recovery.
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step17-t3-runs.txt
BODY=out/step14-t5/wcp-80a49c991b2d.body
mkdir -p out
: > $RUN

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"

echo "== load average at start: $(uptime)" >> $RUN

if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx17-stub-13000.log 2>&1 &)
  sleep 1
fi

export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine .) || { echo "BUILD FAILED" >> $RUN; exit 1; }
echo "== engine binary: $(md5sum /tmp/kortex-engine)" >> $RUN

cpu_of() { awk '{printf "%.2f %.2f", $14/100, $15/100}' /proc/$1/stat 2>/dev/null || echo "gone gone"; }

start_engine() { # $1 = cap $2 = port $3 = events file
  rm -f $3 /tmp/kx17t3-audit.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR="$PWD/engine/crs" \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=13107200 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_MAX_INFLIGHT_BODY=$1 \
  KORTEX_LISTEN_ADDR=127.0.0.1:$2 \
  KORTEX_EVENTS_FILE=$3 \
  KORTEX_AUDIT_LOG=/tmp/kx17t3-audit.log \
  /tmp/kortex-engine > /tmp/kx17t3-engine-$2.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:$2/ && break; done
  echo "== engine effective config (port $2):" >> $RUN
  curl -s http://127.0.0.1:$2/__kortex/config >> $RUN; echo >> $RUN
}

kill_engine() {
  kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
  echo "== engine killed" >> $RUN
}

benign() { curl -s -o /dev/null -w "benign[$2] status=%{http_code} time_total_s=%{time_total}\n" \
    -H "User-Agent: $UA" "http://127.0.0.1:$1/?q=hello" >> $RUN; }

burst() { # $1=port $2=prefix $3=count
  CURLPIDS=""
  for i in $(seq 1 $3); do
    curl -s -o /tmp/kxt3-$2-$i.out -w "copy$i status=%{http_code} time_total_s=%{time_total}\n" \
      -H "X-Kortex-Sample-Id: t3-$2-$i" -H "User-Agent: $UA" -H 'Content-Type: text/plain' \
      --data-binary @$BODY http://127.0.0.1:$1/ >> $RUN &
    CURLPIDS="$CURLPIDS $!"
  done
}

# ---------- Phase A: cap raised, CPU + latency ----------
echo "===== PHASE A: cap=32, 20 concurrent 481,798-byte bodies (CPU + latency)" >> $RUN
start_engine 32 8096 /tmp/kx17t3-events.jsonl
benign 8096 before
echo "== cpu at start (utime_s stime_s): $(cpu_of $EPID)" >> $RUN
T0=$(date +%s.%N)
burst 8096 a 20
sleep 2
echo "== cpu at deadline (+$(echo "$(date +%s.%N) - $T0" | bc)s): $(cpu_of $EPID)" >> $RUN
benign 8096 at-deadline
wait $CURLPIDS
echo "== all copies answered" >> $RUN
sleep 6
benign 8096 at-plus8s
sleep 43
benign 8096 at-plus59s
echo "== cpu at +60s: $(cpu_of $EPID)" >> $RUN
echo "== load average phase A end: $(uptime)" >> $RUN
kill_engine   # the 20 abandoned calls die here; finish events come from A2/B

# ---------- Phase A2: finish events, reduced wave ----------
echo "===== PHASE A2: cap=32, 4 concurrent copies (abandoned-finish events)" >> $RUN
start_engine 32 8096 /tmp/kx17t3a2-events.jsonl
burst 8096 a2 4
wait $CURLPIDS
echo "== copies answered; waiting up to 150s for 4 abandoned-finish events" >> $RUN
for i in $(seq 1 15); do
  N=$(grep -c "abandoned-body-processing-finished" /tmp/kx17t3a2-events.jsonl 2>/dev/null || echo 0)
  [ "$N" -ge 4 ] && break
  sleep 10
done
echo "== abandoned-finish events captured: $N" >> $RUN
grep "abandoned-body-processing-finished" /tmp/kx17t3a2-events.jsonl >> $RUN 2>/dev/null || true
echo "== load average phase A2 end: $(uptime)" >> $RUN
kill_engine

# ---------- Phase B: default cap ----------
echo "===== PHASE B: cap=8 (default), 20 concurrent 481,798-byte bodies" >> $RUN
start_engine 8 8097 /tmp/kx17t3b-events.jsonl
benign 8097 before
burst 8097 b 20
sleep 1
benign 8097 during-overload-window
wait $CURLPIDS
echo "== response bodies:" >> $RUN
for i in $(seq 1 20); do { head -c 40 /tmp/kxt3-b-$i.out | tr '\n' ' '; echo " [copy$i]"; } >> $RUN; done
echo "== overload events: $(grep -c '"decision":"overload"' /tmp/kx17t3b-events.jsonl 2>/dev/null || echo 0)" >> $RUN
echo "== timeout events: $(grep -c '"decision":"timeout"' /tmp/kx17t3b-events.jsonl 2>/dev/null || echo 0)" >> $RUN
echo "== waiting up to 150s for the 8 abandoned-finish events" >> $RUN
for i in $(seq 1 15); do
  NB=$(grep -c "abandoned-body-processing-finished" /tmp/kx17t3b-events.jsonl 2>/dev/null || echo 0)
  [ "$NB" -ge 8 ] && break
  sleep 10
done
echo "== abandoned-finish events captured: $NB" >> $RUN
grep "abandoned-body-processing-finished" /tmp/kx17t3b-events.jsonl >> $RUN 2>/dev/null || true
benign 8097 after-recovery
echo "== load average phase B end: $(uptime)" >> $RUN
kill_engine

echo "== load average at end: $(uptime)" >> $RUN
echo ALL-DONE >> $RUN
