#!/bin/bash
# Step-22 close-out C2: outcome counts on the two wcp sets with the
# kortex_eval change (engine 413/415 answers as waf_fail_closed_413 /
# waf_fail_closed_415). In-process engine built from the working tree, PL1
# and PL2, one engine process and one audit log per run, runner --workers 1
# (rule 13), requests to "localhost" (see tools/step22_lib.sh).
#
# Usage: [STUB_PORT=13004] [WCP_DATA_DIR=dir-with-benign-wcp-v0-and-v1] run_step22_c2_outcomes.sh
# The wcp manifests are not committed (rule 25); each one's SHA-256 is
# checked against the committed MANIFEST.sha256 before it is replayed.
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
DATA=${WCP_DATA_DIR:-data}
PORT=8097
DUR=docs/logs/runs/s22-c2-outcomes
LOG=docs/logs/step22-c2-outcomes.txt
mkdir -p out "$DUR"
: > "$LOG"

echo "== step-22 C2 outcome counts, $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), $(go version), $($PY --version)" | tee -a "$LOG"
echo "== git $(git rev-parse HEAD), tracked paths changed in the working tree: $(git status --porcelain -uno | wc -l | tr -d ' ')" | tee -a "$LOG"
for DS in benign-wcp-v0 benign-wcp-v1; do
  WANT=$(awk '{print $1}' data/$DS/MANIFEST.sha256)
  GOT=$(sha256_of "$DATA/$DS/manifest.jsonl")
  echo "== manifest $DATA/$DS/manifest.jsonl sha256 $GOT (frozen: $WANT)" | tee -a "$LOG"
  [ "$GOT" = "$WANT" ] || { echo "MANIFEST HASH MISMATCH, stopping" | tee -a "$LOG"; exit 1; }
done
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then
  echo "port $STUB_PORT already answers; set STUB_PORT to a free port" | tee -a "$LOG"; exit 1
fi
build_engine "$LOG" || exit 1
start_stub || exit 1

for PL in 1 2; do
  for DS in benign-wcp-v0 benign-wcp-v1; do
    NAME=$DS-inprocess-pl$PL
    start_engine c2-$NAME inprocess $PORT $PL 2000 out/s22-c2-$NAME.engine.log || continue
    config_proof "$NAME" $PORT "$LOG"
    $PY -m kortex_eval.runner --manifest "$DATA/$DS/manifest.jsonl" \
      --base-url $BASE:$PORT --out out/s22-c2-$NAME --timeout 15 --workers 1 \
      --block-status 403 --block-marker 'kortex-decision=block' \
      --default-user-agent "$UA" --label engine=kortex --label mode=inprocess --label paranoia=$PL \
      > out/s22-c2-$NAME.runner.log 2>&1 || echo "runner nonzero for $NAME (sample errors); continuing" | tee -a "$LOG"
    echo "== $NAME stats after run: $(curl -s http://127.0.0.1:$PORT/__kortex/stats)" >> "$LOG"
    stop_engine
    echo "== $NAME kortex_eval.crs_audit and kortex_eval.outcome output:" >> "$LOG"
    finish_run out/s22-c2-$NAME $DUR/$NAME "$LOG"
  done
done
stop_stub
echo "== load at end: $(uptime | sed 's/.*load/load/')" | tee -a "$LOG"

$PY - "$DUR" <<'EOF' | tee -a "$LOG"
import collections, importlib.util, sys
spec = importlib.util.spec_from_file_location("t3", "tools/step22_t3_summary.py")
t3 = importlib.util.module_from_spec(spec); spec.loader.exec_module(t3)
base = sys.argv[1]
print("\n== outcome counts (benign-labelled external traffic; every block or refusal is a potential false positive)")
for ds in ("benign-wcp-v0", "benign-wcp-v1"):
    for pl in (1, 2):
        run = f"{base}/{ds}-inprocess-pl{pl}"
        outc = t3.read(f"{run}/outcomes.jsonl")
        resp = t3.read(f"{run}/responses.jsonl")
        oc = collections.Counter(r["outcome"] for r in outc)
        st = collections.Counter(r.get("status") for r in resp)
        dec = collections.Counter(r.get("engine_decision") for r in resp)
        print("\n".join(t3.rate_lines(ds, pl, "inprocess", oc, len(outc))))
        print(f"    statuses: {dict(sorted(st.items(), key=lambda kv: (kv[0] is None, kv[0])))}")
        print(f"    engine_decision: {dict(sorted(dec.items(), key=lambda kv: str(kv[0])))}")
        by = collections.Counter((r["outcome"], r.get("status")) for r in outc)
        print("    outcome x status: " + ", ".join(f"{o}/{s}={c}" for (o, s), c in sorted(by.items(), key=lambda kv: (kv[0][0], str(kv[0][1])))))
        idx = t3.read(f"{run}/audit.index.jsonl")
        hits = collections.Counter(r for e in idx for r in set(e.get("rule_ids") or []))
        common = [(r, c) for r, c in hits.most_common() if c >= 0.2 * len(idx)]
        print(f"    rule 18: {len(idx)} audit entries; rule ids in >=20% of them: "
              + (", ".join(f"{r}={c}" for r, c in common) or "none"))
EOF
echo "C2-OUTCOMES-DONE" | tee -a "$LOG"
