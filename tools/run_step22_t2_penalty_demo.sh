#!/bin/bash
# Step-22 T2 design risk (b): demonstrate the single-peer-address penalty.
# With no trusted proxies configured, the client key is the peer address,
# so ALL users behind one address share one penalty bucket. Demo:
# 1) a kill via a budget-exceeding held request from 127.0.0.1
# 2) an innocent POST from 127.0.0.1 (same address, "another user") -> 503
# 3) an innocent POST from 127.0.0.5 (different address) -> 200
set -u
cd "$(dirname "$0")/.."
OUT=docs/logs/runs/s22-t2-penalty-demo
mkdir -p $OUT

ps aux | grep stub200 | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done
ps aux | grep kortex-engine | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done
sleep 1
setsid nohup python3 /tmp/stub200.py >/tmp/stub200.log 2>&1 &
sleep 1
env KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
  KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=1 KORTEX_DETECTION_PARANOIA=1 \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_MAX_INFLIGHT_BODY_LARGE=2 KORTEX_BODY_LANE_THRESHOLD=65536 \
  KORTEX_ENGINE_TIME_BUDGET_MS=300 KORTEX_TEST_HOLD_BODY_MS=5000 \
  KORTEX_CLIENT_PENALTY_MS=3000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8099 \
  KORTEX_EVENTS_FILE=/tmp/kx-s22demo-ev.jsonl KORTEX_AUDIT_LOG=/tmp/kx-s22demo-aud.log \
  KORTEX_WORKER_MODE=on KORTEX_WORKER_POOL=2 KORTEX_WORKER_SPARES=1 \
  /tmp/kortex-engine > $OUT/engine.log 2>&1 &
for i in $(seq 1 60); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:8099/ && break; sleep 0.5; done
echo "rule29: $(curl -s http://127.0.0.1:8099/__kortex/config)" | tee $OUT/demo.txt

# 1) the kill: held large-lane request from 127.0.0.1
python3 - <<'EOF' | tee -a $OUT/demo.txt
import urllib.request
body = b"a" * 131072
req = urllib.request.Request("http://127.0.0.1:8099/", data=body, method="POST")
req.add_header("Content-Type", "text/plain")
req.add_header("X-Kortex-Test-Hold", "1")
req.add_header("X-Kortex-Sample-Id", "demo-kill")
try:
    r = urllib.request.urlopen(req, timeout=30); print("kill request status", r.status)
except urllib.error.HTTPError as e:
    print("kill request status", e.code)
except Exception as e:
    print("kill request error", str(e)[:100])
EOF
sleep 1
# 2) innocent request from the SAME address 127.0.0.1 (source port differs)
curl -s -o /dev/null -w "same-address innocent POST -> %{http_code}\n" \
  --interface 127.0.0.1 -X POST --data-binary "hello world benign note" \
  -H "Content-Type: text/plain" -H "X-Kortex-Sample-Id: demo-same-addr" \
  --max-time 10 http://127.0.0.1:8099/ | tee -a $OUT/demo.txt
# 3) innocent request from a DIFFERENT address 127.0.0.5
curl -s -o /dev/null -w "other-address innocent POST -> %{http_code}\n" \
  --interface 127.0.0.5 -X POST --data-binary "hello world benign note" \
  -H "Content-Type: text/plain" -H "X-Kortex-Sample-Id: demo-other-addr" \
  --max-time 10 http://127.0.0.1:8099/ | tee -a $OUT/demo.txt
echo "stats: $(curl -s http://127.0.0.1:8099/__kortex/stats)" | tee -a $OUT/demo.txt
ps aux | grep kortex-engine | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done
echo DEMO-DONE
