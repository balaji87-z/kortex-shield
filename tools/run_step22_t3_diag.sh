#!/bin/bash
# Step-22 T3 DIAGNOSTIC runs (rule 34). Never a baseline or parity number.
#
#  A. coraza version: the last recorded PL2 run of benign-wcp-v1 (step 19)
#     used coraza v3.7.0 on another host. A scratch copy of engine/ with ONLY
#     go.mod changed to coraza v3.7.0 (out/DIAGNOSTIC-engine-coraza370, not
#     committed) replays benign-wcp-v1 at PL2 on this host with the same stub,
#     and its block set is compared per id with the step-22 v3.8.1 run and
#     with the step-19 run.
#  B. rule-id set stability: two benign-wcp-v0 ids had different rule-id sets
#     (same status) between the in-process and worker PL2 runs. Each is
#     replayed 200 times per mode; the distinct rule-id sets are counted.
# Log: docs/logs/step22-t3-DIAGNOSTIC.txt
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
LOG=docs/logs/step22-t3-DIAGNOSTIC.txt
DUR=docs/logs/runs/s22-t3-DIAGNOSTIC
mkdir -p out $DUR
: > $LOG
echo "# Step-22 T3 DIAGNOSTIC runs (never a baseline or parity number)" >> $LOG
echo "== host: $(uname -srm); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG
start_stub || exit 1

# --- A: scratch build with coraza v3.7.0
SCR=out/DIAGNOSTIC-engine-coraza370
rm -rf $SCR && mkdir -p $SCR && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $SCR && tar xf -)
(cd $SCR && go mod edit -require github.com/corazawaf/coraza/v3@v3.7.0 && go mod tidy >/dev/null 2>&1 \
  && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-coraza370 .) || { echo "SCRATCH BUILD FAILED" | tee -a $LOG; exit 1; }
echo "== A: scratch engine sha256 $(sha256_of out/kortex-engine-DIAGNOSTIC-coraza370); diff of go.mod against engine/go.mod:" >> $LOG
diff engine/go.mod $SCR/go.mod >> $LOG
echo "   diff -r of the .go files against engine/: $(diff -rq --exclude=go.mod --exclude=go.sum --exclude=engine --exclude='*.log' engine $SCR | wc -l | tr -d ' ') files differ" >> $LOG
SAVED_BIN=$ENGINE_BIN
ENGINE_BIN=out/kortex-engine-DIAGNOSTIC-coraza370
NAME=DIAGNOSTIC-coraza370-benign-wcp-v1-pl2
start_engine t3-$NAME inprocess 8097 2 2000 $DUR/engine-$NAME.log && {
  config_proof "$NAME" 8097 $LOG
  $PY -m kortex_eval.runner --manifest data/benign-wcp-v1/manifest.jsonl \
    --base-url $BASE:8097 --out out/s22-t3-$NAME --timeout 15 --workers 1 \
    --block-status 403 --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" --label engine=kortex --label run=DIAGNOSTIC --label coraza=v3.7.0 --label paranoia=2 \
    > $DUR/$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME; continuing" >> $LOG
  stop_engine
  finish_run out/s22-t3-$NAME $DUR/$NAME $LOG
}
ENGINE_BIN=$SAVED_BIN
$PY - $DUR/$NAME docs/logs/runs/s22-t3-parity/benign-wcp-v1-inprocess-pl2 docs/logs/runs/s19-t4-benign-wcp-v1-post-r1-pl2 >> $LOG <<'PYEOF'
import collections, gzip, json, os, sys
def rd(d):
    p = d + "/outcomes.jsonl"
    if not os.path.exists(p): p += ".gz"
    op = gzip.open if p.endswith(".gz") else open
    return {r["id"]: r for r in map(json.loads, op(p, "rt"))}
diag, s22, s19 = (rd(d) for d in sys.argv[1:4])
def blocked(o): return {i for i, r in o.items() if r["outcome"] == "waf_block"}
print(f"   blocked: scratch v3.7.0 on this host {len(blocked(diag))}; step-22 v3.8.1 on this host {len(blocked(s22))}; step-19 v3.7.0 on the step-19 host {len(blocked(s19))} (n=10000 each)")
for name, a, b in (("scratch v3.7.0 vs step-19 v3.7.0", diag, s19), ("scratch v3.7.0 vs step-22 v3.8.1", diag, s22)):
    oa, ob = blocked(a) - blocked(b), blocked(b) - blocked(a)
    print(f"   {name}: blocked only in the first {len(oa)}, only in the second {len(ob)}")
    for label, ids, src in (("first", oa, a), ("second", ob, b)):
        sets = collections.Counter(",".join(r for r in src[i]["rule_ids"] if r != "949110") for i in ids)
        if ids:
            print(f"      only in the {label}: rule-id sets {dict(sets.most_common(4))}; ids {sorted(ids)[:12]}{' ...' if len(ids) > 12 else ''}")
PYEOF

# --- B: rule-id set stability of two ids, 200 replays per mode
$PY - > out/s22-t3-diag-two.jsonl <<'PYEOF'
import json
want = {"wcp-35f82c1417df", "wcp-7b0bdeda7bc7"}
for line in open("data/benign-wcp-v0/manifest.jsonl"):
    if json.loads(line)["id"] in want:
        print(line, end="")
PYEOF
for MODE in inprocess worker; do
  PORT=8097; [ "$MODE" = worker ] && PORT=8098
  NAME=DIAGNOSTIC-ruleset-$MODE-pl2
  start_engine t3-$NAME $MODE $PORT 2 2000 $DUR/engine-$NAME.log || continue
  config_proof "$NAME" $PORT $LOG
  for REP in $(seq 1 200); do
    $PY -m kortex_eval.runner --manifest out/s22-t3-diag-two.jsonl --base-url $BASE:$PORT \
      --out out/s22-t3-$NAME-rep --timeout 15 --workers 1 --block-status 403 \
      --block-marker 'kortex-decision=block' --default-user-agent "$UA" > /dev/null 2>&1
  done
  stop_engine
  $PY tools/step22_body_index.py $ENGINE_AUDIT $DUR/$NAME.audit.index.jsonl >> $LOG
  $PY - $DUR/$NAME.audit.index.jsonl "$MODE" >> $LOG <<'PYEOF'
import collections, json, sys
sets = collections.defaultdict(collections.Counter)
for e in map(json.loads, open(sys.argv[1])):
    sets[e["sample_id"]][",".join(e["rule_ids"])] += 1
base = {}
for sid, c in sorted(sets.items()):
    common = set.intersection(*(set(k.split(",")) for k in c))
    print(f"   B [{sys.argv[2]}] {sid}: {sum(c.values())} audit entries, {len(c)} distinct rule-id sets")
    for k, n in c.most_common():
        print(f"        x{n}: rules outside the common core: {sorted(set(k.split(',')) - common) or 'none'}")
PYEOF
done
stop_stub
echo "== load at end: $(uptime | sed 's/.*load/load/')" >> $LOG
echo S22-T3-DIAG-DONE
