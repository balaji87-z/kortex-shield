#!/bin/bash
# Step-22 close-out C6, DIAGNOSTIC (rule 34): do the real engine's 400
# framing and 503 timeout answers reach kortex_eval as fail-closed outcomes?
# Three hand-written requests of my own (no external data), replayed through
# kortex_eval.runner, crs_audit and outcome against the in-process engine:
#   run "normal"   budget 2000 ms: c6-get and c6-post pass, c6-te-cl (a POST
#                  with Transfer-Encoding and Content-Length) is refused by
#                  the framing gate
#   run "budget0"  KORTEX_ENGINE_TIME_BUDGET_MS=0 ("expire immediately", as in
#                  engine test E6): the engine answers 503 timeout
# 503 overload is not produced here (it needs concurrent body requests).
# No baseline or parity number comes from this script.
# Usage: [STUB_PORT=13004] run_step22_c6_check.sh
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
PORT=8096
DUR=docs/logs/runs/s22-c6-check-DIAGNOSTIC
LOG=docs/logs/step22-c6-engine-check-DIAGNOSTIC.txt
mkdir -p out/s22-c6-check "$DUR"
: > "$LOG"
MANIFEST=out/s22-c6-check/manifest.jsonl
$PY - "$MANIFEST" <<'EOF'
import json, sys
base = {"label": "benign", "family": "benign", "source": "hand-written-step22-c6", "query": "", "body": "",
        "content_type": "", "headers": {}}
rows = [
    dict(base, id="c6-get", method="GET", path="/", query="q=hello"),
    dict(base, id="c6-post", method="POST", path="/form", body="a=1&b=2",
         content_type="application/x-www-form-urlencoded"),
    dict(base, id="c6-te-cl", method="POST", path="/form", body="a=1&b=2",
         content_type="application/x-www-form-urlencoded", headers={"Transfer-Encoding": "chunked"}),
]
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    for r in rows:
        fh.write(json.dumps(r) + "\n")
EOF
echo "== step-22 C6 DIAGNOSTIC engine check, $(date -u +%FT%TZ), git $(git rev-parse HEAD), tracked paths changed: $(git status --porcelain -uno | wc -l | tr -d ' ')" | tee -a "$LOG"
echo "== manifest (hand-written, 3 requests; bodies not printed, the pre-push scan refuses body fields in logs):" | tee -a "$LOG"
$PY -c 'import json, sys
for line in open(sys.argv[1], encoding="utf-8"):
    r = json.loads(line)
    print("   ", r["id"], r["method"], r["path"] + ("?" + r["query"] if r["query"] else ""),
          "content-type:", r["content_type"] or "-", "body bytes:", len(r["body"].encode()),
          "extra headers:", r["headers"] or "-")' "$MANIFEST" | tee -a "$LOG"
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then
  echo "port $STUB_PORT already answers; set STUB_PORT to a free port" | tee -a "$LOG"; exit 1
fi
build_engine "$LOG" || exit 1
start_stub || exit 1
for RUN in normal:2000 budget0:0; do
  NAME=DIAGNOSTIC-${RUN%%:*}
  start_engine c6-$NAME inprocess $PORT 1 ${RUN##*:} out/s22-c6-$NAME.engine.log || continue
  config_proof "$NAME" $PORT "$LOG"
  $PY -m kortex_eval.runner --manifest "$MANIFEST" --base-url $BASE:$PORT --out out/s22-c6-$NAME \
    --timeout 15 --workers 1 --block-status 403 --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" --label engine=kortex --label run=DIAGNOSTIC --label paranoia=1 \
    > out/s22-c6-$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME" | tee -a "$LOG"
  stop_engine
  echo "== $NAME engine events:" | tee -a "$LOG"
  grep '"sample_id":"c6-' "$ENGINE_EVENTS" | tee -a "$LOG"
  echo "== $NAME responses.jsonl:" | tee -a "$LOG"
  cat out/s22-c6-$NAME/responses.jsonl | tee -a "$LOG"
  echo "== $NAME kortex_eval.crs_audit and kortex_eval.outcome output:" | tee -a "$LOG"
  finish_run out/s22-c6-$NAME $DUR/$NAME "$LOG"
  echo "== $NAME outcomes.jsonl:" | tee -a "$LOG"
  cat out/s22-c6-$NAME/outcomes.jsonl | tee -a "$LOG"
done
stop_stub
echo "C6-CHECK-DONE" | tee -a "$LOG"
