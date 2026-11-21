#!/bin/bash
# Step-18 T4 re-runs: measure the REQUEST_BODY target fix (commit 3f3f440)
# against a PRE-fix engine built from commit 1964793 (failing tests committed,
# implementation not yet applied) - same host, same config, only the fix
# differs (rule 16 unchanged-result check; rule 27 the fix was derived from
# attacks-ct-v0 observations, so attacks-ct-v0/attacks-v0 are IN-SAMPLE and
# benign-browse-v1/benign-hard-v0/benign-wcp-v0 are the held-out side).
# Datasets: attacks-ct-v0, attacks-v0, benign-browse-v1, benign-hard-v0 at
# PL1+PL2 on BOTH sides; benign-wcp-v0 (20,000) POST-fix only at PL1+PL2
# (the PRE-fix WCP baseline is the preserved step-17 run on this host,
# docs/logs/runs/s17-t4-engine-benign-wcp-v0-pl{1,2}).
# Rule 13/29/36 hygiene: one engine process per dataset batch, config proof
# per PL, frozen manifest shas printed, workers 1, same UA contract.
set -u
cd "$(cd "$(dirname "$0")/.." && pwd)"
RUN=docs/logs/step18-t4-runs.txt
mkdir -p out
: > $RUN

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
DSS="attacks-ct-v0 attacks-v0 benign-browse-v1 benign-hard-v0"

echo "== load average at start: $(uptime)" >> $RUN
if ! curl -s -o /dev/null --max-time 2 http://127.0.0.1:13000/; then
  (cd /tmp && nohup python3 -m http.server 13000 >/tmp/kx18-stub-13000.log 2>&1 &)
  sleep 1
fi
curl -s -o /dev/null -w "stub probe: %{http_code}\n" http://127.0.0.1:13000/ >> $RUN

export PATH=$PATH:$HOME/go/bin

# frozen-manifest integrity proofs (rule 10/29)
for DS in $DSS benign-wcp-v0; do
  echo "== manifest sha $DS: $(sha256sum data/$DS/MANIFEST.sha256 2>/dev/null | cut -d' ' -f1) frozen: $(cat data/$DS/MANIFEST.sha256 2>/dev/null)" >> $RUN
done

# PRE-fix engine: worktree at the failing-tests commit (pre-implementation)
git worktree add -f /tmp/kortex-prefix 1964793 >> $RUN 2>&1 || true
(cd /tmp/kortex-prefix/engine && go build -buildvcs=false -o /tmp/kortex-engine-prefix .) || { echo "PRE BUILD FAILED" >> $RUN; exit 1; }
echo "== PRE engine binary: $(md5sum /tmp/kortex-engine-prefix) (1964793, pre-REQUEST_BODY-fix)" >> $RUN
(cd engine && go build -buildvcs=false -o /tmp/kortex-engine-post .) || { echo "POST BUILD FAILED" >> $RUN; exit 1; }
echo "== POST engine binary: $(md5sum /tmp/kortex-engine-post) (3f3f440, REQUEST_BODY fix)" >> $RUN

start_engine() { # $1=pl $2=bin $3=tag
  local pl=$1 bin=$2 tag=$3
  rm -f /tmp/kx18t4-events-$tag-$pl.jsonl /tmp/kx18t4-audit-$tag-$pl.log
  KORTEX_BACKEND_URL=http://127.0.0.1:13000 \
  KORTEX_RULES_DIR="$PWD/engine/crs" \
  KORTEX_RULE_ENGINE=On \
  KORTEX_BLOCKING_PARANOIA=$pl KORTEX_DETECTION_PARANOIA=$pl \
  KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
  KORTEX_ENGINE_TIME_BUDGET_MS=2000 \
  KORTEX_LISTEN_ADDR=127.0.0.1:8090 \
  KORTEX_EVENTS_FILE=/tmp/kx18t4-events-$tag-$pl.jsonl \
  KORTEX_AUDIT_LOG=/tmp/kx18t4-audit-$tag-$pl.log \
  $bin > /tmp/kx18t4-engine-$tag-$pl.log 2>&1 &
  EPID=$!
  for i in $(seq 1 20); do sleep 1; curl -s -o /dev/null --max-time 3 http://127.0.0.1:8090/ && break; done
  echo "== engine effective config ($tag PL$pl):" >> $RUN
  cat /tmp/kx18t4-engine-$tag-$pl.log >> $RUN
  echo "== /__kortex/config:" >> $RUN
  curl -s http://127.0.0.1:8090/__kortex/config >> $RUN
  echo >> $RUN
}
stop_engine() { kill $EPID 2>/dev/null; wait $EPID 2>/dev/null; }

run_ds() { # $1=ds $2=tag $3=pl
  local ds=$1 tag=$2 pl=$3
  echo "== run engine $ds $tag pl$pl $(date -u +%FT%TZ)" >> $RUN
  .venv/bin/python -m kortex_eval.runner --manifest data/$ds/manifest.jsonl \
    --base-url http://localhost:8090 --out out/s18-t4-engine-$ds-$tag-pl$pl \
    --timeout 30 --workers 1 --block-status 403 \
    --block-marker 'kortex-decision=block' \
    --default-user-agent "$UA" >> $RUN 2>&1
  cp /tmp/kx18t4-audit-$tag-$pl.log out/s18-t4-engine-$ds-$tag-pl$pl/engine-audit-full.log
  cp /tmp/kx18t4-events-$tag-$pl.jsonl out/s18-t4-engine-$ds-$tag-pl$pl/kortex-events-full.jsonl 2>/dev/null || true
  .venv/bin/python -m kortex_eval.crs_audit --logs out/s18-t4-engine-$ds-$tag-pl$pl/engine-audit-full.log \
    --out out/s18-t4-engine-$ds-$tag-pl$pl/audit.jsonl >> $RUN 2>&1
  .venv/bin/python -m kortex_eval.outcome --responses out/s18-t4-engine-$ds-$tag-pl$pl/responses.jsonl \
    --audit out/s18-t4-engine-$ds-$tag-pl$pl/audit.jsonl \
    --out out/s18-t4-engine-$ds-$tag-pl$pl/outcomes.jsonl --engine-mode blocking >> $RUN 2>&1
}

for TAG in pre post; do
  BIN=/tmp/kortex-engine-prefix
  for PL in 1 2; do
    start_engine $PL $BIN $TAG
    for DS in $DSS; do
      run_ds $DS $TAG $PL
    done
    stop_engine
    # rule 42: durable evidence before the next task starts
    for DS in $DSS; do tools/preserve_run.sh out/s18-t4-engine-$DS-$TAG-pl$PL; done
  done
done

# POST-fix WCP (held-out benign, 20,000): PL1 + PL2
for PL in 1 2; do
  start_engine $PL /tmp/kortex-engine-post post
  run_ds benign-wcp-v0 post $PL
  stop_engine
  tools/preserve_run.sh out/s18-t4-engine-benign-wcp-v0-post-pl$PL
done

git worktree remove --force /tmp/kortex-prefix >> $RUN 2>&1 || true
echo "== load average at end: $(uptime)" >> $RUN
echo ALL-DONE >> $RUN
