#!/bin/bash
# Step-27 T3/T4: parsing differential, second slice (heads) and first body
# slice (docs/plan-step27-parsing.md). Three backends, the frameworks in
# scope: Python http.server and Go net/http on the host, Node.js http in a
# container with its port published on 127.0.0.1 (rule 6). Each backend once
# behind its own engine process and once on its own. Engine in-process,
# blocking, PL1 then PL2; effective config in the log (rule 29). The cases
# are chosen, so the output is counts and lists, never a rate (rule 35).
# Usage: [S27_DIFF_TAG=-name] run_step27_parsing_diff.sh   (needs docker for the Node backend)
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
PY_PORT=13011; GO_PORT=13012; NODE_PORT=13013
ENG_PY=8101; ENG_GO=8102; ENG_NODE=8103
NODE_IMAGE=node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
# S27_DIFF_TAG names another run of the same cases (for example -run1, or
# -DIAGNOSTIC-xml-attr with KORTEX_XML_ATTR_INSPECT=on exported: the engine
# inherits the environment).
TAG=${S27_DIFF_TAG:-}
DUR=docs/logs/runs/s27-parsing-diff$TAG
LOG=docs/logs/step27-parsing-diff$TAG.txt
mkdir -p out $DUR; : > $LOG
echo "# Step-27: parsing differential, 61 step-23 cases, new head cases and body cases; three backends; PL1 and PL2" | tee -a $LOG
echo "== $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), $(go version), $($PY --version), system python3 for the backend: $(python3 --version)" | tee -a $LOG
echo "== git $(git rev-parse HEAD), tracked paths changed under engine/: $(git status --porcelain engine | wc -l | tr -d ' ')" | tee -a $LOG
for P in $PY_PORT $GO_PORT $NODE_PORT $ENG_PY $ENG_GO $ENG_NODE; do
  if curl -s -o /dev/null --max-time 1 http://127.0.0.1:$P/; then echo "port $P already answers" | tee -a $LOG; exit 1; fi
done
build_engine $LOG || exit 1
(cd tools/parsing-diff-gobackend && go build -buildvcs=false -o ../../out/parsing-diff-gobackend .) || { echo "GO BACKEND BUILD FAILED" | tee -a $LOG; exit 1; }
echo "== go backend binary sha256 $(sha256_of out/parsing-diff-gobackend)" | tee -a $LOG
python3 tools/step23_parsing_backend.py $PY_PORT > out/s27-parsing-pybackend.log 2>&1 &
PYB=$!
out/parsing-diff-gobackend $GO_PORT > out/s27-parsing-gobackend.log 2>&1 &
GOB=$!
docker rm -f s27-node-backend > /dev/null 2>&1
docker run -d --name s27-node-backend -p 127.0.0.1:$NODE_PORT:3000 -v "$PWD/tools/parsing-diff-nodebackend:/app:ro" $NODE_IMAGE node /app/server.js 3000 > /dev/null \
  || { echo "NODE BACKEND DID NOT START" | tee -a $LOG; kill $PYB $GOB; exit 1; }
cleanup() { kill $PYB $GOB ${E1:-} ${E2:-} ${E3:-} 2>/dev/null; docker rm -f s27-node-backend > /dev/null 2>&1; }
trap cleanup EXIT
for P in $PY_PORT $GO_PORT $NODE_PORT; do
  for i in $(seq 1 60); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$P/ && break; sleep 0.25; done
done
echo "== node backend: image $(docker inspect --format '{{.Config.Image}} id {{.Image}}' s27-node-backend), $(docker exec s27-node-backend node -p '"node "+process.version+" llhttp "+process.versions.llhttp')" | tee -a $LOG
for B in python:$PY_PORT go:$GO_PORT node:$NODE_PORT; do
  echo "== ${B%%:*} backend answers: $(curl -s --max-time 2 http://127.0.0.1:${B##*:}/ping | cut -c1-70)" | tee -a $LOG
done
for PL in 1 2; do
  echo | tee -a $LOG
  echo "## PL$PL" | tee -a $LOG
  STUB_PORT=$PY_PORT start_engine s27-parsing-py-pl$PL inprocess $ENG_PY $PL 2000 out/s27-parsing-engine-py.log || exit 1
  E1=$ENGINE_PID; EV1=$ENGINE_EVENTS
  config_proof "engine-before-python-pl$PL" $ENG_PY $LOG
  STUB_PORT=$GO_PORT start_engine s27-parsing-go-pl$PL inprocess $ENG_GO $PL 2000 out/s27-parsing-engine-go.log || exit 1
  E2=$ENGINE_PID; EV2=$ENGINE_EVENTS
  config_proof "engine-before-go-pl$PL" $ENG_GO $LOG
  STUB_PORT=$NODE_PORT start_engine s27-parsing-node-pl$PL inprocess $ENG_NODE $PL 2000 out/s27-parsing-engine-node.log || exit 1
  E3=$ENGINE_PID; EV3=$ENGINE_EVENTS
  config_proof "engine-before-node-pl$PL" $ENG_NODE $LOG
  $PY tools/step27_parsing_diff.py --backend python=$ENG_PY,$PY_PORT,$EV1 --backend go=$ENG_GO,$GO_PORT,$EV2 \
    --backend node=$ENG_NODE,$NODE_PORT,$EV3 --out $DUR/pl$PL 2>&1 | tee -a $LOG
  for E in $ENG_PY $ENG_GO $ENG_NODE; do echo "== engine stats at end (port $E): $(curl -s http://127.0.0.1:$E/__kortex/stats)" | tee -a $LOG; done
  kill $E1 $E2 $E3 2>/dev/null; wait $E1 $E2 $E3 2>/dev/null; E1=; E2=; E3=
  sleep 1
done
cleanup
trap - EXIT
echo | tee -a $LOG
echo "# $PY tools/step27_pl_effect.py out/s22-s27-parsing-py-pl1.audit.log out/s22-s27-parsing-py-pl2.audit.log" | tee -a $LOG
$PY tools/step27_pl_effect.py out/s22-s27-parsing-py-pl1.audit.log out/s22-s27-parsing-py-pl2.audit.log | tee -a $LOG
echo "== load at end: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo "S27-PARSING-DIFF-DONE" | tee -a $LOG
