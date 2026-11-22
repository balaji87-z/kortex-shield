#!/bin/bash
# Step-22 T4: re-run the 402-sample big-body manifest (PL1 and PL2) with
# durable audit logs, so per-sample rule ids and size bands can be
# attributed. Manifest: docs/logs/runs/s21-t4-bigbodies/manifest-41.jsonl is
# the 41-block set; the full 402 set is the gzipped derived manifest.
set -u
cd "$(dirname "$0")/.."
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
OUT=docs/logs/runs/s22-t4-bigbodies-audit
mkdir -p $OUT
MAN=docs/logs/runs/s21-t4-bigbodies/manifest-derived-nobodies.jsonl
# rebuild the full manifest with bodies from the frozen datasets (local temp only)
TMPMAN=/tmp/kx-s22-t4-manifest.jsonl
.venv/bin/python - "$MAN" "$TMPMAN" <<'EOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
bodies = {}
for ds in ["benign-wcp-v0", "benign-wcp-v1"]:
    for line in open(f"data/{ds}/manifest.jsonl"):
        e = json.loads(line)
        bodies[e["id"]] = e
n = 0
with open(dst, "w") as f:
    for line in open(src):
        e = json.loads(line)
        full = bodies[e["id"]]
        # keep ONLY frozen-sample fields
        out = {k: full[k] for k in full if k in
               ("id", "method", "path", "query", "headers", "body", "content_type")}
        f.write(json.dumps(out) + "\n")
        n += 1
print(f"manifest rebuilt: {n} samples", file=sys.stderr)
EOF

ps aux | grep stub200 | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done; sleep 1
setsid nohup python3 /tmp/stub200.py >/tmp/stub200.log 2>&1 &
sleep 1
curl -s -o /dev/null -X POST --max-time 2 http://127.0.0.1:13000/ || { echo "BACKEND NO RESPONDE"; exit 1; }

for PL in 1 2; do
  ps aux | grep kortex-engine | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done
  sleep 1
  env KORTEX_BACKEND_URL=http://127.0.0.1:13000 KORTEX_RULES_DIR=$PWD/engine/crs \
    KORTEX_RULE_ENGINE=On KORTEX_BLOCKING_PARANOIA=$PL KORTEX_DETECTION_PARANOIA=$PL \
    KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
    KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_MAX_INFLIGHT_BODY_LARGE=2 KORTEX_BODY_LANE_THRESHOLD=65536 \
    KORTEX_ENGINE_TIME_BUDGET_MS=120000 KORTEX_LISTEN_ADDR=127.0.0.1:8099 \
    KORTEX_EVENTS_FILE=/tmp/kx-s22t4-ev-pl$PL.jsonl KORTEX_AUDIT_LOG=/tmp/kx-s22t4-aud-pl$PL.log \
    /tmp/kortex-engine > $OUT/engine-pl$PL.log 2>&1 &
  for i in $(seq 1 120); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:8099/ && break; sleep 0.5; done
  echo "== bigbodies PL$PL rule29: $(curl -s http://127.0.0.1:8099/__kortex/config)" | tee -a docs/logs/step22-t4-bigbodies-audit.txt
  .venv/bin/python -m kortex_eval.runner --manifest $TMPMAN \
    --base-url http://127.0.0.1:8099 --out $OUT/bigbodies-pl$PL --timeout 125 --workers 1 \
    --default-user-agent "$UA" --label engine=kortex --label paranoia=$PL \
    > $OUT/bigbodies-pl$PL.runner.log 2>&1 || echo "runner nonzero; continuing"
  cp /tmp/kx-s22t4-aud-pl$PL.log $OUT/audit-pl$PL.log
  .venv/bin/python -m kortex_eval.crs_audit --logs $OUT/audit-pl$PL.log --out $OUT/audit-pl$PL-parsed.jsonl || true
done
ps aux | grep kortex-engine | grep -v grep | awk '{print $2}' | while read p; do kill -9 $p 2>/dev/null; done
echo S22-T4-BIGBODIES-DONE
