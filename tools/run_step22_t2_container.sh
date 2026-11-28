#!/bin/bash
# Step-22 T2: run the worker-mode attack cells (tools/run_step22_t2_attack.py)
# in a Linux container, for hosts that are not Linux (the script needs /proc
# and source addresses 127.0.0.2-10). Everything runs inside ONE container on
# its own loopback: stub backend, engine and attackers (rule 6).
# The engine binary and the rules are copied to the container's own disk so
# worker start-up does not read rules through the host file share.
# Usage: run_step22_t2_container.sh [all|rest|storm|<cell>]   (default all)
# Output: docs/logs/runs/s22-t2-cells-v2/ and docs/logs/step22-t2-cells-v2-<which>.txt
set -u
cd "$(dirname "$0")/.."
IMAGE=${KORTEX_T2_IMAGE:-python:3.12-alpine@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89}
OUT=${KORTEX_T2_OUT_DIR:-docs/logs/runs/s22-t2-cells-v2}
WHICH=${1:-all}
LOG=${KORTEX_T2_LOG:-docs/logs/step22-t2-cells-v2-$WHICH.txt}
mkdir -p out $OUT
ARCH=$(docker version --format '{{.Server.Arch}}')
# DIAGNOSTIC options (rule 34), one factor at a time against the re-run:
#   KORTEX_T2_ENGINE_REF=<git ref>  build the engine (and take the rules) from that commit
#   KORTEX_T2_OLD_PROBE=1           benign probe of the first recording (numeric Host, no User-Agent)
#   KORTEX_T2_OUT_DIR, KORTEX_T2_LOG  where the cell files and the log go
REF=${KORTEX_T2_ENGINE_REF:-}
SRC=engine
BIN=out/kortex-engine-linux-$ARCH
if [ -n "$REF" ]; then
  SRC=out/t2-engine-src-$REF/engine
  BIN=out/kortex-engine-linux-$ARCH-$REF
  rm -rf out/t2-engine-src-$REF && mkdir -p out/t2-engine-src-$REF
  git archive "$REF" engine | tar -x -C out/t2-engine-src-$REF || { echo "git archive $REF failed"; exit 1; }
fi
(cd $SRC && GOOS=linux GOARCH=$ARCH CGO_ENABLED=0 go build -buildvcs=false -o "$OLDPWD/$BIN" .) || { echo "ENGINE BUILD FAILED"; exit 1; }
{
  if [ -n "$REF" ] || [ "${KORTEX_T2_OLD_PROBE:-}" = 1 ]; then
    echo "# Step-22 T2 DIAGNOSTIC (rule 34, never a baseline number): engine source ${REF:-working tree} ($(git rev-parse ${REF:-HEAD})), benign probe $([ "${KORTEX_T2_OLD_PROBE:-}" = 1 ] && echo old || echo new)"
  fi
  echo "# Step-22 T2 attack cells, re-run after the per-lane per-client clamp (5dfdd19), in a Linux container"
  echo "== host: $(uname -srm); docker client $(docker version --format '{{.Client.Version}}') server $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}} kernel {{.Server.KernelVersion}}')"
  echo "== image: $IMAGE $(docker image inspect --format '{{index .RepoDigests 0}} id {{.Id}}' $IMAGE 2>/dev/null || echo '(pulled on first run)')"
  echo "== engine: linux/$ARCH sha256 $(shasum -a 256 $BIN | awk '{print $1}') built from $(git rev-parse ${REF:-HEAD}) with $(go version)"
  echo "== VM: $(docker info --format '{{.NCPU}} cpus, {{.MemTotal}} bytes memory, {{.OperatingSystem}}')"
} | tee $LOG
docker run --rm --name kx-s22-t2 -v "$PWD":/repo -w /repo \
  -e KORTEX_T2_ENGINE=/work/kortex-engine -e KORTEX_T2_RULES=/work/crs -e KORTEX_T2_OUT=$OUT \
  -e KORTEX_T2_OLD_PROBE=${KORTEX_T2_OLD_PROBE:-0} \
  $IMAGE sh -c "
    mkdir -p /work && cp $BIN /work/kortex-engine && cp -r $SRC/crs /work/crs &&
    echo \"== in container: \$(uname -srm); \$(python3 --version); cpus \$(nproc); load \$(cat /proc/loadavg)\" &&
    (python3 tools/stub_backend.py 13000 > /tmp/stub.log 2>&1 &) && sleep 1 &&
    python3 tools/run_step22_t2_attack.py $WHICH;
    echo \"== load at end: \$(cat /proc/loadavg)\"" 2>&1 | tee -a $LOG
echo "== image digest used: $(docker image inspect --format '{{index .RepoDigests 0}}' $IMAGE)" | tee -a $LOG
echo S22-T2-CONTAINER-DONE
