#!/bin/bash
# Step-19 T3: availability under sustained slow requests (DIAGNOSTIC, this host only).
# Default settings: cap 8, inspected 131072, budget 2000 ms, PL1.
# Attack: 8 workers re-sending the 131071-byte text/plain body (T2's slowest
# under-cap body, ~18-20 s per completed call) for 5 minutes so all 8 slots
# stay held. Meanwhile: 1 benign body-bearing POST per second + 1 benign GET
# per second. Reports overload count, benign success rate, GET latency, slot
# hold times (abandoned-finish events), recovery time, CPU seconds.
set -u
cd "$(dirname "$0")/.."
PORT=8104
OUT=docs/logs/step19-t3-availability.txt
RUNDIR=docs/logs/runs/s19-t3-availability
mkdir -p $RUNDIR
EV=/tmp/kx-t3-ev.jsonl; rm -f $EV

: > $OUT
echo "== T3 availability: $(date -u +%FT%TZ) cap=8 inspected=131072 budget=2000ms PL1 ==" | tee -a $OUT
KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
  KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:$PORT KORTEX_EVENTS_FILE=$EV \
  KORTEX_AUDIT_LOG=/tmp/kx-t3-audit.log \
  /tmp/kortex-engine-v2 >$RUNDIR/engine.log 2>&1 &
EPID=$!
for i in $(seq 1 40); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$PORT/ && break; sleep 0.5; done
grep -o "request_body_target_updates=[0-9]*\|max_inflight_body=[0-9]*\|engine_time_budget_ms=[0-9]*\|max_inspected_bytes=[0-9]*" $RUNDIR/engine.log | sort -u | tee -a $OUT

cpu() { awk '{print $14+$15}' /proc/$EPID/stat 2>/dev/null; }
C0=$(cpu); echo "cpu_ticks_start=$C0 (hz=100)" | tee -a $OUT
echo "load_start=[$(uptime | grep -o 'load average.*')]" | tee -a $OUT

# attack: 8 workers, 300 s; benign: 1 POST + 1 GET per second (300 s)
setsid nohup python3 - <<PYEOF > $RUNDIR/probe-results.txt 2>&1 &
import http.client, json, threading, time
PORT=$PORT
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
body=open("/tmp/kx-bodies/textplain-131071.bin","rb").read()
small=b'{"k0":"'+b'a'*1000+b'"}'
stop=time.monotonic()+300
def attacker():
    while time.monotonic()<stop:
        try:
            c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=30)
            c.request("POST","/attack",body=body,
              headers={"Content-Type":"text/plain","Content-Length":str(len(body)),
                       "User-Agent":UA,"X-Kortex-Sample-Id":"t3-attack"})
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
                   "User-Agent":UA,"X-Kortex-Sample-Id":"t3-benign-post"})
        r=c.getresponse(); r.read(); c.close()
        st=r.status; lat=(time.monotonic()-ts)*1000
    except Exception as e: st=f"err:{type(e).__name__}"; lat=(time.monotonic()-ts)*1000
    st2=None; lat2=None
    try:
        t2=time.monotonic()
        c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=30)
        c.request("GET","/benign-get",headers={"User-Agent":UA,"X-Kortex-Sample-Id":"t3-benign-get"})
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
                   "User-Agent":UA,"X-Kortex-Sample-Id":"t3-recovery"})
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
post=[r for r in rows]; gets=rows
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
print(f"engine events: timeouts(benign+attack 503 budget)={len(to)} overload={len(ov)} abandoned-finished={len(ab)}")
if hold:
    print(f"slot hold time (abandoned call runtime): median={statistics.median(hold):.0f}ms max={max(hold):.0f}ms n={len(hold)}")
PYEOF
echo "T3-DONE" | tee -a $OUT
