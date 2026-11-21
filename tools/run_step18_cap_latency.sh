#!/bin/bash
# Step-18 (addendum R3): cap latency test, DIAGNOSTIC, this-host only.
# Phase A (cap 32) and phase B (cap 8) run back to back on the SAME host in
# ONE script, three repeats each. During each phase a wave of 20 concurrent
# 481,798-byte bodies is sent; benign probes are sent during the overload
# window. Median benign latency per phase is reported.
# Every repeat copies its artifacts to docs/logs/runs/ (rule 42).
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step18-cap-latency.txt
BODY=/tmp/kx-wcp-body.bin

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
echo "== DIAGNOSTIC, this-host only; load average at start: $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx18-stub-13000.log 2>&1 &)
  sleep 1
fi
export PATH=$PATH:$HOME/go/bin
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine-cap .) || { echo "BUILD FAILED" >> $RUN; exit 1; }

start_engine() { # $1=cap $2=repeat
  local cap=$1 rep=$2
  rm -f /tmp/kxcap-events-$2.jsonl /tmp/kxcap-audit-$2.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR="$PWD/engine/crs" \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=13107200 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_MAX_INFLIGHT_BODY=$cap \
  KORTEX_LISTEN_ADDR=127.0.0.1:8091 \
  KORTEX_EVENTS_FILE=/tmp/kxcap-events-$2.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kxcap-audit-$2.log \
  /tmp/kortex-engine-cap > /tmp/kxcap-engine-$2.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8091/ && break; done
  echo "== repeat $rep phase cap=$cap engine config: $(head -1 /tmp/kxcap-engine-$2.log)" >> $RUN
}
stop_engine() { kill $EPID 2>/dev/null; wait $EPID 2>/dev/null
  local d=docs/logs/runs/s18-cap-latency-repeat-$1
  mkdir -p $d
  cp /tmp/kxcap-events-$1.jsonl $d/ 2>/dev/null
  cp /tmp/kxcap-engine-$1.log $d/ 2>/dev/null
  cp docs/logs/kxcap-probes-$1.txt $d/ 2>/dev/null
}

wave_and_probes() { # $1=repeat $2=phase-label
  local rep=$1 phase=$2
  # wave: 20 concurrent 481,798-byte bodies
  for i in $(seq 1 20); do
    nohup python3 - "$i" "$phase" <<'PYEOF' > /dev/null 2>&1 &
import http.client, sys
body=open("/tmp/kx-wcp-body.bin","rb").read()
c=http.client.HTTPConnection("127.0.0.1",8091,timeout=30)
c.request("POST","/",body=body,headers={"Host":"localhost","X-Kortex-Sample-Id":"cap-wave-%s-%s"%(sys.argv[1],sys.argv[2]),"Content-Type":"text/plain","Content-Length":str(len(body))})
r=c.getresponse(); r.read(); c.close()
PYEOF
  done
  # benign probes during the overload window
  for i in $(seq 1 15); do
    t0=$(date +%s%N)
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 30 http://127.0.0.1:8091/ 2>/dev/null)
    t1=$(date +%s%N)
    echo "$phase repeat$rep probe$i $code $(( (t1-t0)/1000000 ))ms" >> docs/logs/kxcap-probes-$rep.txt
    sleep 0.15
  done
  sleep 2
}

REPEAT=1
for repeat in 1 2 3; do
  start_engine 32 $repeat
  wave_and_probes $repeat "phaseA-cap32"
  stop_engine $repeat
  sleep 3
done
for repeat in 4 5 6; do
  start_engine 8 $repeat
  wave_and_probes $repeat "phaseB-cap8"
  stop_engine $repeat
  sleep 3
done

echo "== median benign latency per phase (ms), per repeat and overall:" >> $RUN
python3 - <<'PYEOF' >> $RUN
import re, statistics, glob
for phase in ("phaseA-cap32","phaseB-cap8"):
    per_rep={}
    for rep_file in sorted(glob.glob("docs/logs/kxcap-probes-*.txt")):
        vals=[]
        for line in open(rep_file):
            m=re.match(r"(\S+) repeat(\d+) probe\d+ (\d+) (\d+)ms", line)
            if m and m.group(1)==phase:
                vals.append(int(m.group(4)))
        if vals:
            rep=rep_file.split("probes-")[1].split(".")[0]
            per_rep[rep]=(statistics.median(vals), len(vals), vals)
    allv=[v for _,(m,n,vals) in sorted(per_rep.items()) for v in vals]
    print(f"{phase}:")
    for rep,(med,n,vals) in sorted(per_rep.items()):
        print(f"  repeat {rep}: median={med:.1f} ms n={n} vals={vals}")
    if allv:
        print(f"  OVERALL median={statistics.median(allv):.1f} ms n={len(allv)}")
PYEOF
echo "== load average at end: $(uptime)" >> $RUN
echo CAP-DONE >> $RUN
