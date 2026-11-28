#!/bin/bash
# Step-23 T4, DIAGNOSTIC (rule 34): can kortex_eval see a real 503 overload?
# The engine answers 503 kortex-decision=overload when a body request finds
# its size-class lane full. With the runner at --workers 1 (rule 13, every
# other run) that cannot happen, so this run uses --workers 8 on purpose.
# Nothing else is special: the engine has the limits of every step-22/23
# run (small lane 8, large lane 2, lane threshold 65,536 bytes, budget
# 2,000 ms), no test hook is set, and the requests are 48 hand-written
# benign POSTs of my own with a 100,000-byte body each (large lane).
# In-process and worker mode, PL1. No baseline or parity number comes from
# this script.
# Usage: [STUB_PORT=13004] run_step23_overload.sh
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
DUR=docs/logs/runs/s23-overload-DIAGNOSTIC
LOG=docs/logs/step23-overload-DIAGNOSTIC.txt
mkdir -p out/s23-overload $DUR
: > $LOG
MANIFEST=out/s23-overload/manifest.jsonl
$PY - "$MANIFEST" <<'EOF'
import json, sys
words = "the quick brown fox jumps over the lazy dog and keeps running through the quiet field ".split()
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    for i in range(48):
        parts, size = [], 0
        k = i
        while size < 100000 - 12:
            w = words[k % len(words)]
            parts.append(w)
            size += len(w) + 1
            k += 7
        text = "note=" + "+".join(parts)
        text = text[:100000]
        fh.write(json.dumps({"id": f"ovl-{i:02d}", "label": "benign", "family": "benign",
                             "source": "hand-written-step23-overload", "method": "POST", "path": "/form",
                             "query": "", "body": text, "content_type": "application/x-www-form-urlencoded",
                             "headers": {}}) + "\n")
EOF
echo "# Step-23 T4 DIAGNOSTIC: 503 overload through the runner with concurrent workers" | tee -a $LOG
echo "== $(date -u +%FT%TZ), git $(git rev-parse HEAD), tracked paths changed: $(git status --porcelain -uno | wc -l | tr -d ' '), $(go version), $($PY --version), load at start: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
$PY - "$MANIFEST" <<'EOF' | tee -a $LOG
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8")]
sizes = sorted({len(r["body"].encode()) for r in rows})
types = sorted({r["content_type"] for r in rows})
print(f"== manifest (hand-written, not committed): {len(rows)} POST /form requests, content type {types}, "
      f"size in bytes {sizes}, ids {rows[0]['id']} to {rows[-1]['id']}")
EOF
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then
  echo "port $STUB_PORT already answers; set STUB_PORT to a free port" | tee -a $LOG; exit 1
fi
build_engine $LOG || exit 1
start_stub || exit 1
for MODE in inprocess worker; do
  PORT=8097; [ "$MODE" = worker ] && PORT=8098
  NAME=DIAGNOSTIC-overload-$MODE-pl1-workers8
  start_engine s23-$NAME $MODE $PORT 1 2000 out/s23-$NAME.engine.log || { echo "engine did not start for $NAME" | tee -a $LOG; continue; }
  config_proof "$NAME" $PORT $LOG
  $PY -m kortex_eval.runner --manifest "$MANIFEST" --base-url $BASE:$PORT --out out/s23-$NAME \
    --timeout 30 --workers 8 --block-status 403 --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" --label engine=kortex --label mode=$MODE --label run=DIAGNOSTIC --label workers=8 \
    > out/s23-$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME (sample errors)" | tee -a $LOG
  echo "== $NAME stats after run: $(curl -s http://127.0.0.1:$PORT/__kortex/stats)" | tee -a $LOG
  stop_engine
  echo "== $NAME kortex_eval.crs_audit and kortex_eval.outcome output:" | tee -a $LOG
  finish_run out/s23-$NAME $DUR/$NAME $LOG
  $PY tools/step23_events_index.py "$ENGINE_EVENTS" $DUR/$NAME/events.index.jsonl | sed "s|^|== $NAME events: |" | tee -a $LOG
  $PY - $DUR/$NAME <<'EOF' | tee -a $LOG
import collections, json, sys
d = sys.argv[1]
resp = [json.loads(l) for l in open(f"{d}/responses.jsonl") if l.strip()]
ev = [json.loads(l) for l in open(f"{d}/events.index.jsonl") if l.strip()]
print("   responses by (status, engine_decision): " + ", ".join(
    f"{k}={v}" for k, v in sorted(collections.Counter((r["status"], r["engine_decision"]) for r in resp).items(), key=str)))
print("   overload events by reason: " + (", ".join(
    f"{k}={v}" for k, v in sorted(collections.Counter(e["reason"] for e in ev if e["decision"] == "overload").items())) or "none"))
print("   run.json: " + json.dumps({k: v for k, v in json.load(open(f"{d}/run.json")).items()
                                    if k in ("total_samples", "responses_ok", "blocked", "error_count", "load_avg_start", "load_avg_end")}))
EOF
done
stop_stub
echo "S23-OVERLOAD-DONE" | tee -a $LOG
