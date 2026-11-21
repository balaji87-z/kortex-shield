#!/bin/bash
# Step-20 T2: availability under sustained slow requests WITH size-class lanes.
# Usage: run_step20_t2_lanes.sh large|small
#   large: 8 workers x 131071-B text/plain (LARGE lane, cap 2), PL1, 300 s
#   small: 8 workers x 32768-B text/plain (SMALL lane, cap 8), PL2, 300 s
# Benign: 1 POST/s (must reach a backend answering 200) + 1 GET/s.
set -u
cd "$(dirname "$0")/.."
MODE=${1:?large|small}
PORT=8105
if [ "$MODE" = large ]; then PL=1; BODYSZ=131071; else PL=2; BODYSZ=32768; fi
OUT=docs/logs/step20-t2-$MODE-lane.txt
RUNDIR=docs/logs/runs/s20-t2-$MODE-lane
mkdir -p $RUNDIR
EV=/tmp/kx-t20-ev-$MODE.jsonl; rm -f $EV

pkill -f "http.server 13000" 2>/dev/null; pkill -f stub200.py 2>/dev/null; sleep 1
setsid nohup python3 /tmp/stub200.py >/tmp/stub200.log 2>&1 &
sleep 1
curl -s -o /dev/null -X POST --max-time 2 http://127.0.0.1:13000/ && echo "backend 200 OK" || echo "BACKEND NO RESPONDE"

: > $OUT
echo "== T2 lanes[$MODE]: $(date -u +%FT%TZ) body=$BODYSZ PL=$PL small_cap=8 large_cap=2 threshold=65536 budget=2000ms ==" | tee -a $OUT
KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
  KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$PL KORTEX_DETECTION_PARANOIA=$PL \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_MAX_INFLIGHT_BODY_LARGE=2 KORTEX_BODY_LANE_THRESHOLD=65536 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:$PORT KORTEX_EVENTS_FILE=$EV \
  KORTEX_AUDIT_LOG=/tmp/kx-t20-aud-$MODE.log \
  /tmp/kortex-engine-lanes >$RUNDIR/engine.log 2>&1 &
EPID=$!
for i in $(seq 1 40); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$PORT/ && break; sleep 0.5; done
echo "rule29 config proof:" | tee -a $OUT
curl -s http://127.0.0.1:$PORT/__kortex/config | tee -a $OUT

cpu() { awk '{print $14+$15}' /proc/$EPID/stat 2>/dev/null; }
C0=$(cpu); echo "cpu_ticks_start=$C0 (hz=100)" | tee -a $OUT
echo "load_start=[$(uptime | grep -o 'load average.*')]" | tee -a $OUT

BODY=/tmp/kx-bodies/textplain-$BODYSZ.bin
[ -f $BODY ] || python3 -c "open('$BODY','wb').write((b'ab*|c$d%22 e' * 6000)[:$BODYSZ])"
setsid nohup python3 - <<PYEOF > $RUNDIR/probe-results.txt 2>&1 &
import http.client, json, threading, time
PORT=$PORT
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
body=open("$BODY","rb").read()
small=b'{"k0":"'+b'a'*1000+b'"}'
stop=time.monotonic()+300
def attacker():
    while time.monotonic()<stop:
        try:
            c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=30)
            c.request("POST","/attack",body=body,
              headers={"Content-Type":"text/plain","Content-Length":str(len(body)),
                       "User-Agent":UA,"X-Kortex-Sample-Id":"t20-attack-$MODE"})
            r=c.getresponse(); r.read(); c.close()
        except Exception: pass
threads=[threading.Thread(target=attacker,daemon=True) for _ in range(8)]
for t in threads: t.start()
results=[]
while time.monotonic()<stop:
    ts=time.monotonic()
    st=None; lat=None
    try:
        c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=30)
        c.request("POST","/benign",body=small,
          headers={"Content-Type":"application/json","Content-Length":str(len(small)),
                   "User-Agent":UA,"X-Kortex-Sample-Id":"t20-benign-post-$MODE"})
        r=c.getresponse(); r.read(); c.close()
        st=r.status; lat=(time.monotonic()-ts)*1000
    except Exception as e: st=f"err:{type(e).__name__}"; lat=(time.monotonic()-ts)*1000
    st2=None; lat2=None
    try:
        t2=time.monotonic()
        c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=30)
        c.request("GET","/benign-get",headers={"User-Agent":UA,"X-Kortex-Sample-Id":"t20-benign-get-$MODE"})
        r=c.getresponse(); r.read(); c.close()
        st2=r.status; lat2=(time.monotonic()-t2)*1000
    except Exception as e: st2=f"err:{type(e).__name__}"; lat2=(time.monotonic()-t2)*1000
    results.append({"t":round(ts),"post_status":str(st),"post_ms":round(lat,1),
                    "get_status":str(st2),"get_ms":round(lat2,1)})
    time.sleep(max(0,1.0-(time.monotonic()-ts)))
json.dump(results,open("$RUNDIR/benign-probes.jsonl","w"),indent=0)
print("probe rows:",len(results))
PYEOF
PROBE_PID=$!
sleep 60
C60=$(cpu); echo "cpu_ticks_at_60s=$C60" | tee -a $OUT
echo "load_at_60s=[$(uptime | grep -o 'load average.*')]" | tee -a $OUT
wait $PROBE_PID 2>/dev/null
sleep 1
C1=$(cpu); echo "cpu_ticks_end=$C1" | tee -a $OUT
echo "load_end=[$(uptime | grep -o 'load average.*')]" | tee -a $OUT
echo "attack window ended $(date -u +%FT%TZ); measuring recovery" | tee -a $OUT
python3 - <<PYEOF >> $OUT 2>&1
import http.client, time, json
PORT=$PORT
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
small=b'{"k0":"'+b'a'*1000+b'"}'
t0=time.monotonic(); recovered=None; rows=[]
while time.monotonic()-t0 < 120:
    ts=time.monotonic()
    try:
        c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=30)
        c.request("POST","/benign",body=small,
          headers={"Content-Type":"application/json","Content-Length":str(len(small)),
                   "User-Agent":UA,"X-Kortex-Sample-Id":"t20-recovery-$MODE"})
        r=c.getresponse(); r.read(); c.close()
        st=r.status; lat=(time.monotonic()-ts)*1000
    except Exception as e:
        st=f"err:{type(e).__name__}"; lat=(time.monotonic()-ts)*1000
    rows.append((round(time.monotonic()-t0,1),str(st),round(lat,1)))
    if recovered is None and st==200 and lat<500:
        recovered=round(time.monotonic()-t0,1); break
    time.sleep(1)
print("recovery: first benign POST with status 200 and <500 ms after attack stop:",
      f"{recovered}s" if recovered is not None else "NOT within 120s", flush=True)
print("recovery rows:", json.dumps(rows[:30]), flush=True)
PYEOF
kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
cp $EV $RUNDIR/events.jsonl 2>/dev/null
python3 - <<PYEOF >> $OUT 2>&1
import json, collections, statistics
rows=json.load(open("$RUNDIR/benign-probes.jsonl"))
overload=sum(1 for r in rows if r["post_status"]=="503")
ok=sum(1 for r in rows if r["post_status"]=="200")
print(f"benign POSTs: n={len(rows)} status200={ok} status503_overload={overload} other={len(rows)-ok-overload}")
print(f"benign POST success rate: {ok}/{len(rows)}")
lat_ok=[r["post_ms"] for r in rows if r["post_status"]=="200"]
if lat_ok: print(f"benign POST latency when not overloaded: median={statistics.median(lat_ok):.0f}ms max={max(lat_ok):.0f}ms")
gl=[r["get_ms"] for r in rows]
print(f"benign GET latency: median={statistics.median(gl):.0f}ms p90={sorted(gl)[int(0.9*len(gl))]:.0f}ms max={max(gl):.0f}ms")
ev=[json.loads(l) for l in open("$EV")]
ab=[e for e in ev if e["decision"]=="abandoned-body-processing-finished"]
hold=[e["elapsed_ms"] for e in ab]
to=[e for e in ev if e["decision"]=="timeout"]
ov=[e for e in ev if e["decision"]=="overload"]
print(f"engine events: overload={len(ov)} timeout={len(to)} abandoned_finished={len(ab)}")
if hold: print(f"slot hold (abandoned calls): n={len(hold)} median={statistics.median(hold)/1000:.1f}s max={max(hold)/1000:.1f}s")
PYEOF
pkill -f stub200.py 2>/dev/null
echo "T2-$MODE-DONE"
