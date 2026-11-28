#!/bin/bash
# Step-22 close-out: tools/flip_repro.py (step-19 T1) against the engine built
# from the working tree (coraza version: engine/go.mod), in-process, one
# engine process per host form, REPS repeats of ROUNDS rounds each. Same
# protocol as tools/run_step20_t1_flip.sh, made runnable on macOS through
# tools/step22_lib.sh (that script needs sha256sum and a stub on 13000).
#
# Host forms: "localhost" is the step-22 convention; "127.0.0.1" is what
# steps 19 and 20 used and adds CRS 920350 (numeric Host, +3) to every
# request, so it is run as well for a like-for-like comparison.
#
# flip_repro.py counts every answer other than 403 as a flip; the summary
# below splits the answers by status so a 503 or an error is not read as one.
#
# FLIP_CONTROL=coraza370 runs the same thing as a DIAGNOSTIC positive control
# (rules 34, 47): a scratch copy of engine/ with only go.mod changed to coraza
# v3.7.0, the version on which steps 19 and 20 recorded the flip. It shows
# whether this reproducer can see a flip on this host; it gives no baseline
# number and writes to its own log and run directory.
#
# Usage: [STUB_PORT=13004] [WCP_V0_MANIFEST=path] [FLIP_CONTROL=coraza370] [FLIP_STEP=23] run_step22_flip.sh [pl] [rounds] [reps] ["hosts"]
# The wcp manifest is not committed (rule 25); its SHA-256 is checked against
# data/benign-wcp-v0/MANIFEST.sha256. The raw audit log quotes request data
# and stays under out/ (rule 51); rounds and engine events (ids, statuses,
# rule ids) go to docs/logs/runs/s22-flip-pl<pl>/.
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
PL=${1:-2}
ROUNDS=${2:-500}
REPS=${3:-5}
HOSTS=${4:-"localhost 127.0.0.1"}
MANIFEST=${WCP_V0_MANIFEST:-data/benign-wcp-v0/manifest.jsonl}
PORT=8093
CONTROL=${FLIP_CONTROL:-}
SUFFIX=""
[ -n "$CONTROL" ] && SUFFIX=-DIAGNOSTIC-$CONTROL
STEP=${FLIP_STEP:-22}   # FLIP_STEP=23 writes step23-* / s23-* so earlier evidence is kept
DUR=docs/logs/runs/s$STEP-flip-pl$PL$SUFFIX
LOG=docs/logs/step$STEP-flip-pl$PL$SUFFIX.txt
mkdir -p out "$DUR"
: > "$LOG"

echo "== step-$STEP flip_repro${CONTROL:+ DIAGNOSTIC positive control ($CONTROL)}, $(date -u +%FT%TZ), $(sw_vers -productName 2>/dev/null) $(sw_vers -productVersion 2>/dev/null) $(uname -srm), $(go version), $($PY --version)" | tee -a "$LOG"
echo "== git $(git rev-parse HEAD), engine/ paths changed in the working tree: $(git status --porcelain -- engine | wc -l | tr -d ' ')" | tee -a "$LOG"
echo "== $(grep -E 'corazawaf/(coraza/v3|libinjection-go) ' engine/go.mod | tr -s '\t ' ' ' | tr '\n' ';')" | tee -a "$LOG"
echo "== coraza module of engine/: $(cd engine && go list -m github.com/corazawaf/coraza/v3)" | tee -a "$LOG"
WANT=$(awk '{print $1}' data/benign-wcp-v0/MANIFEST.sha256)
GOT=$(sha256_of "$MANIFEST")
echo "== manifest $MANIFEST sha256 $GOT (frozen: $WANT)" | tee -a "$LOG"
[ "$GOT" = "$WANT" ] || { echo "MANIFEST HASH MISMATCH, stopping" | tee -a "$LOG"; exit 1; }
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then
  echo "port $STUB_PORT already answers; set STUB_PORT to a free port" | tee -a "$LOG"; exit 1
fi
if [ "$CONTROL" = coraza370 ]; then
  SCR=out/DIAGNOSTIC-engine-coraza370
  rm -rf $SCR && mkdir -p $SCR && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $SCR && tar xf -)
  # since step 23 engine/go.mod replaces coraza with the patched v3.8.1 copy;
  # the control must build against the real v3.7.0 module, so the replace is
  # dropped in the scratch copy (and its vendored tree removed)
  rm -rf $SCR/third_party
  (cd $SCR && go mod edit -dropreplace github.com/corazawaf/coraza/v3 \
    && go mod edit -require github.com/corazawaf/coraza/v3@v3.7.0 && go mod tidy >/dev/null 2>&1 \
    && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-coraza370 .) || { echo "SCRATCH BUILD FAILED" | tee -a "$LOG"; exit 1; }
  echo "== DIAGNOSTIC scratch engine coraza module: $(cd $SCR && go list -m github.com/corazawaf/coraza/v3)" | tee -a "$LOG"
  ENGINE_BIN=out/kortex-engine-DIAGNOSTIC-coraza370
  echo "== DIAGNOSTIC scratch engine sha256 $(sha256_of $ENGINE_BIN); .go files that differ from engine/: $(diff -rq --exclude=go.mod --exclude=go.sum --exclude=engine --exclude='*.log' engine $SCR | wc -l | tr -d ' '); diff of go.mod against engine/go.mod:" | tee -a "$LOG"
  diff engine/go.mod $SCR/go.mod | tee -a "$LOG"
elif [ -n "$CONTROL" ]; then
  echo "unknown FLIP_CONTROL=$CONTROL" | tee -a "$LOG"; exit 1
else
  build_engine "$LOG" || exit 1
fi
start_stub || exit 1
echo "== stub backend tools/stub_backend.py on 127.0.0.1:$STUB_PORT; pl=$PL rounds=$ROUNDS reps=$REPS hosts=$HOSTS" | tee -a "$LOG"

for H in $HOSTS; do
  TAG=flip-pl$PL$SUFFIX-$H
  start_engine $TAG inprocess $PORT $PL 2000 out/s22-$TAG.engine.log || { stop_stub; exit 1; }
  config_proof "$TAG" $PORT "$LOG"
  echo "== host $H: load at start: $(uptime | sed 's/.*load/load/')" | tee -a "$LOG"
  for R in $(seq 1 "$REPS"); do
    echo "host=$H rep=$R :: $($PY tools/flip_repro.py --base-url http://$H:$PORT --manifest "$MANIFEST" \
      --rounds "$ROUNDS" --out "$DUR/rounds-$H-r$R.jsonl" 2>&1 | tail -1)" | tee -a "$LOG"
  done
  echo "== host $H: load at end: $(uptime | sed 's/.*load/load/')" | tee -a "$LOG"
  echo "== host $H: engine stats at end: $(curl -s http://127.0.0.1:$PORT/__kortex/stats)" | tee -a "$LOG"
  stop_engine
  gzip -9 -c "$ENGINE_EVENTS" > "$DUR/events-$H.jsonl.gz"
  echo "== host $H: audit entries $(grep -c '^{\"transaction\"' "$ENGINE_AUDIT") in $ENGINE_AUDIT (not committed, rule 51)" | tee -a "$LOG"
done
stop_stub

$PY - "$DUR" "$REPS" $HOSTS <<'EOF' | tee -a "$LOG"
import collections, gzip, json, sys
dur, reps, hosts = sys.argv[1], int(sys.argv[2]), sys.argv[3:]
print("\n== summary: answers by status, per repeat (a flip is a 200; rule 20: every request counted)")
for h in hosts:
    total = collections.Counter()
    rounds_total = flip_rounds_total = 0
    for r in range(1, reps + 1):
        rows = [json.loads(l) for l in open(f"{dur}/rounds-{h}-r{r}.jsonl") if l.strip()]
        st = collections.Counter()
        flip_rounds = 0
        for row in rows:
            got = [v["status"] for k, v in row.items() if k.startswith("wcp-")]
            st.update(got)
            flip_rounds += any(s == "200" for s in got)
        total.update(st)
        rounds_total += len(rows)
        flip_rounds_total += flip_rounds
        print(f"host={h} rep={r}: rounds={len(rows)} rounds with a 200 (flip)={flip_rounds} "
              f"flips/round={flip_rounds / len(rows):.4f} statuses={dict(sorted(st.items()))}")
    print(f"host={h} all repeats: rounds={rounds_total} rounds with a flip={flip_rounds_total} "
          f"flips/round={flip_rounds_total / rounds_total:.4f} statuses={dict(sorted(total.items()))}")
    sets = collections.defaultdict(collections.Counter)
    for line in gzip.open(f"{dur}/events-{h}.jsonl.gz", "rt", encoding="utf-8"):
        ev = json.loads(line)
        # the start-up probe of start_engine has no sample id
        sets[ev["sample_id"] or "(no sample id)"][(ev["decision"], ev["status"], ev["reason"])] += 1
    for sid in sorted(sets):
        print(f"host={h} engine events {sid}: {len(sets[sid])} distinct (decision, status, rule ids)")
        for (dec, status, reason), n in sets[sid].most_common():
            print(f"    x{n}: {dec} {status} {reason}")
EOF
echo "FLIP-DONE" | tee -a "$LOG"
