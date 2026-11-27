#!/bin/bash
# Step-22 T4: re-run the 402-sample big-body set (bodies over 16 KB from
# benign-wcp-v0 and benign-wcp-v1; PL1 and PL2; in-process mode, 120 s
# budget) keeping audit evidence, so rule ids can be attributed per sample
# and per size band. The id list is the committed body-less index
# docs/logs/runs/s21-t4-bigbodies/manifest-derived-nobodies.jsonl; the
# replay manifest is rebuilt under out/ as a pure filter of the frozen
# manifests (rows unchanged). Raw audit logs stay under out/ (rule 51);
# docs/logs/runs/s22-t4-bigbodies-audit/ holds responses, outcomes, run.json
# and a body-less audit index per run.
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
DUR=docs/logs/runs/s22-t4-bigbodies-audit
LOG=docs/logs/step22-t4-bigbodies-audit.txt
IDS=docs/logs/runs/s21-t4-bigbodies/manifest-derived-nobodies.jsonl
MAN=out/s22-t4-manifest.jsonl
mkdir -p out $DUR
: > $LOG
echo "# Step-22 T4: big-body audited re-run (402 benign wcp samples, in-process, budget 120 s)" >> $LOG
echo "== host: $(uname -srm); $(python3 --version); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG
$PY - "$IDS" "$MAN" >> $LOG <<'PYEOF'
import json, sys
src, dst = sys.argv[1], sys.argv[2]
want = [json.loads(l)["id"] for l in open(src)]
want_set = set(want)
rows = {}
for ds in ("benign-wcp-v0", "benign-wcp-v1"):
    for line in open(f"data/{ds}/manifest.jsonl"):
        i = json.loads(line)["id"]
        if i in want_set:
            rows[i] = line
missing = [i for i in want if i not in rows]
with open(dst, "w") as f:
    for i in want:
        if i in rows:
            f.write(rows[i])
print(f"== manifest rebuilt: {len(want) - len(missing)}/{len(want)} ids found in the frozen manifests, missing {len(missing)} {missing[:5]}")
PYEOF
build_engine $LOG || exit 1
start_stub || exit 1

for PL in 1 2; do
  NAME=bigbodies-pl$PL
  start_engine t4-$NAME inprocess 8099 $PL 120000 $DUR/engine-$NAME.log || continue
  config_proof "$NAME" 8099 $LOG
  $PY -m kortex_eval.runner --manifest $MAN \
    --base-url $BASE:8099 --out out/s22-t4-$NAME --timeout 125 --workers 1 \
    --block-status 403 --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" --label engine=kortex --label mode=inprocess --label paranoia=$PL \
    > $DUR/$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME; continuing" >> $LOG
  echo "== $NAME stats after run: $(curl -s http://127.0.0.1:8099/__kortex/stats)" >> $LOG
  stop_engine
  finish_run out/s22-t4-$NAME $DUR/$NAME $LOG
done
stop_stub
$PY tools/step22_t4_bigbodies_analysis.py $IDS $DUR docs/logs/runs/s21-t4-bigbodies >> $LOG 2>&1
echo "== load at end: $(uptime | sed 's/.*load/load/')" >> $LOG
echo S22-T4-BIGBODIES-DONE
