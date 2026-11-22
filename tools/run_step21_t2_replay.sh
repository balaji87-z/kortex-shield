#!/bin/bash
# Step-21 T2: 60 s large-lane replay with /__kortex/stats sampled every 1 s.
# Answers: are slots released, when, and are abandoned-finished events logged?
set -u
cd "$(dirname "$0")/.."
PORT=8105
PL=1
BODYSZ=131071
OUT=docs/logs/step21-t2-large-replay.txt
RUNDIR=docs/logs/runs/s21-t2-large-replay
mkdir -p $RUNDIR
EV=/tmp/kx-t21-ev.jsonl; rm -f $EV

ps aux | grep stub200 | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done; sleep 1
setsid nohup python3 /tmp/stub200.py >/tmp/stub200.log 2>&1 &
sleep 1
curl -s -o /dev/null -X POST --max-time 2 http://127.0.0.1:13000/ && echo "backend 200 OK" || echo "BACKEND NO RESPONDE"

: > $OUT
echo "== T2 large replay 60s: $(date -u +%FT%TZ) body=$BODYSZ PL=$PL small_cap=8 large_cap=2 threshold=65536 budget=2000ms ==" | tee -a $OUT
KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
  KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$PL KORTEX_DETECTION_PARANOIA=$PL \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_MAX_INFLIGHT_BODY_LARGE=2 KORTEX_BODY_LANE_THRESHOLD=65536 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:$PORT KORTEX_EVENTS_FILE=$EV \
  KORTEX_AUDIT_LOG=/tmp/kx-t21-aud.log \
  /tmp/kortex-engine >$RUNDIR/engine.log 2>&1 &
EPID=$!
for i in $(seq 1 40); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$PORT/ && break; sleep 0.5; done
echo "rule29 config proof:" | tee -a $OUT
curl -s http://127.0.0.1:$PORT/__kortex/config | tee -a $OUT

cpu() { awk '{print $14+$15}' /proc/$EPID/stat 2>/dev/null; }
C0=$(cpu); echo "cpu_ticks_start=$C0 (hz=100)" | tee -a $OUT
echo "load_start=[$(uptime | grep -o 'load average.*')]" | tee -a $OUT

BODY=/tmp/kx-bodies/textplain-$BODYSZ.bin
mkdir -p /tmp/kx-bodies
[ -f $BODY ] || python3 -c "open('$BODY','wb').write(open('/tmp/kx-wcp-body.bin','rb').read()[:$BODYSZ])"
setsid nohup python3 - <<PYEOF > $RUNDIR/probe-results.txt 2>&1 &
import http.client, json, threading, time
PORT=$PORT
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
body=open("$BODY","rb").read()
small=b'{"k0":"'+b'a'*1000+b'"}'
stop=time.monotonic()+60
stats_samples=[]
def sampler():
    while time.monotonic()<stop+5:
        try:
            c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=5)
            c.request("GET","/__kortex/stats",headers={"User-Agent":UA})
            r=c.getresponse(); d=r.read(); c.close()
            stats_samples.append((round(time.monotonic(),1), json.loads(d)))
        except Exception as e:
            stats_samples.append((round(time.monotonic(),1), {"error":str(e)}))
        time.sleep(1.0)
threading.Thread(target=sampler,daemon=True).start()
def attacker():
    while time.monotonic()<stop:
        try:
            c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=30)
            c.request("POST","/attack",body=body,
              headers={"Content-Type":"text/plain","Content-Length":str(len(body)),
                       "User-Agent":UA,"X-Kortex-Sample-Id":"t21-attack"})
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
                   "User-Agent":UA,"X-Kortex-Sample-Id":"t21-benign-post"})
        r=c.getresponse(); r.read(); c.close()
        st=r.status; lat=(time.monotonic()-ts)*1000
    except Exception as e: st=f"err:{type(e).__name__}"; lat=(time.monotonic()-ts)*1000
    st2=None; lat2=None
    try:
        t2=time.monotonic()
        c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=30)
        c.request("GET","/benign-get",headers={"User-Agent":UA,"X-Kortex-Sample-Id":"t21-benign-get"})
        r=c.getresponse(); r.read(); c.close()
        st2=r.status; lat2=(time.monotonic()-t2)*1000
    except Exception as e: st2=f"err:{type(e).__name__}"; lat2=(time.monotonic()-t2)*1000
    results.append((st,round(lat,1),st2,round(lat2,1)))
    time.sleep(max(0, 1.0-(time.monotonic()-ts)))
# 10 s de cola: seguir muestreando stats para ver la recuperacion
tail_stop=time.monotonic()+10
while time.monotonic()<tail_stop:
    try:
        c=http.client.HTTPConnection("127.0.0.1",PORT,timeout=5)
        c.request("GET","/__kortex/stats",headers={"User-Agent":UA})
        r=c.getresponse(); d=r.read(); c.close()
        stats_samples.append((round(time.monotonic(),1), json.loads(d)))
    except Exception as e:
        stats_samples.append((round(time.monotonic(),1), {"error":str(e)}))
    time.sleep(1.0)
served=sum(1 for r in results if r[0]==200)
print(f"benign POSTs served {served}/{len(results)}")
getok=sum(1 for r in results if r[2]==200)
print(f"benign GETs served {getok}/{len(results)}")
lats=sorted(r[1] for r in results if isinstance(r[1],float))
if lats: print(f"POST latency ms median={lats[len(lats)//2]} p90={lats[int(len(lats)*0.9)]} max={lats[-1]}")
json.dump(stats_samples, open("$RUNDIR/stats-samples.json","w"))
print("stats samples:", len(stats_samples))
PYEOF
sleep 75
C1=$(cpu); echo "cpu_ticks_end=$C1 delta=$((C1-C0)) ticks (~$(( (C1-C0)/100 )) s CPU)" | tee -a $OUT
echo "load_end=[$(uptime | grep -o 'load average.*')]" | tee -a $OUT
kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
echo "== engine events (resumen) ==" | tee -a $OUT
python3 - <<PYEOF | tee -a $OUT
import json, collections
c = collections.Counter()
for l in open("$EV"):
    try: e = json.loads(l)
    except: continue
    c[e.get("decision","?")+":"+e.get("reason","")[:40]] += 1
for k,v in c.most_common(10): print(f"  {v:6} {k}")
PYEOF
cp $EV $RUNDIR/events.jsonl; cp $RUNDIR/probe-results.txt $OUT 2>/dev/null
cp /tmp/kx-t21-aud.log $RUNDIR/audit.log 2>/dev/null
echo T21-REPLAY-DONE
