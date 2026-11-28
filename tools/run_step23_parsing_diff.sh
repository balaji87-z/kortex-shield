#!/bin/bash
# Step-23 T5: strict-parsing differential, first slice. Local backends only
# (rule 6): a Python http.server (tools/step23_parsing_backend.py) and a Go
# net/http server (tools/parsing-diff-gobackend), each once behind the
# engine and once on its own. Cases are hand-written
# (tools/step23_parsing_diff.py). The engine runs in-process, blocking, PL1,
# with the limits of the other step-22/23 runs; effective config in the log
# (rule 29). The cases are chosen, so the output is counts and a list of
# cases, never a rate (rule 35).
#
# Usage: run_step23_parsing_diff.sh
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
PY_PORT=13011
GO_PORT=13012
ENG_PY_PORT=8101
ENG_GO_PORT=8102
DUR=docs/logs/runs/s23-parsing-diff
LOG=docs/logs/step23-parsing-diff.txt
mkdir -p out $DUR
: > $LOG
echo "# Step-23 T5: strict-parsing differential, first slice" | tee -a $LOG
echo "== $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), $(go version), $($PY --version), system python3 for the backend: $(python3 --version)" | tee -a $LOG
echo "== git $(git rev-parse HEAD), tracked paths changed in the working tree: $(git status --porcelain -uno | wc -l | tr -d ' ')" | tee -a $LOG
echo "== coraza module of engine/: $(cd engine && go list -m github.com/corazawaf/coraza/v3)" | tee -a $LOG
for P in $PY_PORT $GO_PORT $ENG_PY_PORT $ENG_GO_PORT; do
  if curl -s -o /dev/null --max-time 1 http://127.0.0.1:$P/; then echo "port $P already answers" | tee -a $LOG; exit 1; fi
done
build_engine $LOG || exit 1
(cd tools/parsing-diff-gobackend && go build -buildvcs=false -o ../../out/parsing-diff-gobackend .) || { echo "GO BACKEND BUILD FAILED" | tee -a $LOG; exit 1; }
echo "== go backend binary sha256 $(sha256_of out/parsing-diff-gobackend)" | tee -a $LOG

$PY tools/step23_parsing_backend.py $PY_PORT > out/s23-parsing-pybackend.log 2>&1 &
PYB=$!
out/parsing-diff-gobackend $GO_PORT > out/s23-parsing-gobackend.log 2>&1 &
GOB=$!
cleanup() { kill $PYB $GOB ${EPY:-} ${EGO:-} 2>/dev/null; }
trap cleanup EXIT
for P in $PY_PORT $GO_PORT; do
  for i in $(seq 1 40); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$P/ && break; sleep 0.25; done
done
echo "== python backend answers: $(curl -s --max-time 2 http://127.0.0.1:$PY_PORT/ping | cut -c1-80)" | tee -a $LOG
echo "== go backend answers:     $(curl -s --max-time 2 http://127.0.0.1:$GO_PORT/ping | cut -c1-80)" | tee -a $LOG

# two engines, one per backend (start_engine takes the backend from STUB_PORT)
STUB_PORT=$PY_PORT start_engine s23-parsing-py inprocess $ENG_PY_PORT 1 2000 out/s23-parsing-engine-py.log || exit 1
EPY=$ENGINE_PID; EV_PY=$ENGINE_EVENTS
config_proof "engine-before-python" $ENG_PY_PORT $LOG
STUB_PORT=$GO_PORT start_engine s23-parsing-go inprocess $ENG_GO_PORT 1 2000 out/s23-parsing-engine-go.log || exit 1
EGO=$ENGINE_PID; EV_GO=$ENGINE_EVENTS
config_proof "engine-before-go" $ENG_GO_PORT $LOG

$PY tools/step23_parsing_diff.py --engine-py-port $ENG_PY_PORT --engine-go-port $ENG_GO_PORT \
  --py-port $PY_PORT --go-port $GO_PORT --events-py $EV_PY --events-go $EV_GO --out $DUR 2>&1 | tee -a $LOG
echo "== engine stats at end (python-backed): $(curl -s http://127.0.0.1:$ENG_PY_PORT/__kortex/stats)" | tee -a $LOG
echo "== engine stats at end (go-backed):     $(curl -s http://127.0.0.1:$ENG_GO_PORT/__kortex/stats)" | tee -a $LOG
cleanup
trap - EXIT
echo "S23-PARSING-DIFF-DONE" | tee -a $LOG
