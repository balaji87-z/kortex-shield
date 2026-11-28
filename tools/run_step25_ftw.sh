#!/bin/bash
# Step-25: the CRS v4.25.2 regression suite (go-ftw) against the engine and
# against the reference (docs/plan-step25-crs-regression.md). One WAF process,
# one error log, one go-ftw process and a fresh albedo per run.
#
# Usage: run_step25_ftw.sh [TAG=<suffix>] <run> [<run> ...]
#   ref-asis         stock coraza v3.8.1 middleware (tools/crs-ftw-reference) with
#                    coraza's harness configuration as written (no rule 900511), no overrides
#   ref-strict       the same middleware plus rule 900511, no overrides
#   ref-upstream     same, with the CRS project's coraza-overrides.yaml
#   engine-strict    engine at HEAD, in-process, no overrides (A1 headline)
#   engine-upstream  same, with coraza-overrides.yaml
#   engine-worker    engine in worker mode, no overrides
#   engine-repeat    as engine-strict (repeatability)
#   engine-ftw270    as engine-strict, go-ftw v2.7.0
#   stock            DIAGNOSTIC: the engine built against stock coraza v3.8.1
#   diag-no-body-targets  DIAGNOSTIC: scratch build without the step-18 REQUEST_BODY target updates
#   diag-no-900220        DIAGNOSTIC: scratch build without rule 900220 (so the CRS content-type list applies)
#   all              the nine runs in that order
# Env: S25_LABEL (default s25-ftw) names the durable directory and the log,
#      so a re-run after a fix keeps the earlier recording.
# Needs tools/fetch/fetch_crs_regression.sh to have run. Durable files:
# docs/logs/runs/<label>/<run>/ (rule 42); raw error logs stay under out/.
set -u
cd "$(dirname "$0")/.."
export GOPROXY=off GOFLAGS=-mod=mod
LABEL=${S25_LABEL:-s25-ftw}
CRS=data/external/crs-v4.25.2/coreruleset-4.25.2
TESTS=$CRS/tests/regression/tests
OVERRIDES=$CRS/tests/regression/coraza-overrides.yaml
BIN=out/step25/bin
WAF_PORT=${S25_WAF_PORT:-18025}
BACKEND_PORT=${S25_BACKEND_PORT:-13025}
DUR=docs/logs/runs/$LABEL
LOG=docs/logs/$LABEL.txt
PY=.venv/bin/python
sha() { shasum -a 256 "$@" | awk '{print $1}'; }

RUNS="$*"
[ -n "$RUNS" ] || { echo "usage: run_step25_ftw.sh <run>...|all"; exit 2; }
[ "$RUNS" = all ] && RUNS="ref-asis ref-strict ref-upstream engine-strict engine-upstream engine-worker engine-repeat engine-ftw270 stock"

mkdir -p out/step25/runs "$DUR"
[ -f "$LOG" ] || : > "$LOG"
say() { echo "$*" | tee -a "$LOG"; }

say "# Step-25: CRS v4.25.2 regression suite, runs: $RUNS"
say "== $(date -u +%FT%TZ), $(sw_vers -productName) $(sw_vers -productVersion) $(uname -srm), $(go version), load at start: $(uptime | sed 's/.*load/load/')"
say "== git $(git rev-parse HEAD), tracked paths changed in the working tree: $(git status --porcelain -uno | wc -l | tr -d ' ')"
bash tools/fetch/fetch_crs_regression.sh 2>&1 | sed 's/^/== fetch: /' | tee -a "$LOG"
[ "${PIPESTATUS[0]}" = 0 ] || { say "FETCH CHECK FAILED, stopping"; exit 1; }
say "== rules set hash file engine/RULES.sha256: $(grep -v '^#' engine/RULES.sha256 | head -1)"
for p in $WAF_PORT $BACKEND_PORT; do
  if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$p/; then say "port $p already answers; set S25_WAF_PORT / S25_BACKEND_PORT"; exit 1; fi
done

build_engine() {
  (cd engine && go build -buildvcs=false -o ../out/kortex-engine .) || { say "ENGINE BUILD FAILED"; return 1; }
  say "== engine binary sha256 $(sha out/kortex-engine), coraza module: $(cd engine && go list -m github.com/corazawaf/coraza/v3)"
  $PY tools/step23_coraza_vendor.py check 2>&1 | tail -1 | tee -a "$LOG"
}

build_stock() {
  local scr=out/DIAGNOSTIC-engine-stock-coraza
  rm -rf $scr && mkdir -p $scr && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $scr && tar xf -)
  rm -rf $scr/third_party
  (cd $scr && go mod edit -dropreplace github.com/corazawaf/coraza/v3 \
    && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-stock-coraza .) || { say "SCRATCH BUILD FAILED"; return 1; }
  say "== DIAGNOSTIC scratch engine sha256 $(sha out/kortex-engine-DIAGNOSTIC-stock-coraza), coraza module: $(cd $scr && go list -m github.com/corazawaf/coraza/v3); files that differ from engine/ other than go.mod, go.sum and third_party: $(diff -rq --exclude=go.mod --exclude=go.sum --exclude=third_party --exclude=engine --exclude='*.log' engine $scr | wc -l | tr -d ' ')"
}

# build_scratch <name> <python-edit>: copy engine/, apply one edit to
# config.go (must change the file), build out/kortex-engine-DIAGNOSTIC-<name>
build_scratch() {
  local name=$1 edit=$2 scr=out/DIAGNOSTIC-engine-$1
  rm -rf $scr && mkdir -p $scr && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $scr && tar xf -)
  python3 - "$scr/config.go" "$edit" <<'PYEOF' || { say "SCRATCH EDIT FAILED ($name)"; return 1; }
import sys
path, edit = sys.argv[1], sys.argv[2]
s = open(path).read()
if edit == "no-body-targets":
    old = "return base + renderBodyTargetUpdates(bodyTargets), nil"
    new = "return base, nil"
elif edit == "no-900220":
    start = s.index('SecRule REQUEST_HEADERS:Content-Type "@rx ^[^;\\s]+" "id:900220')
    end = s.index("\n", start)
    old, new = s[start:end], ""
else:
    raise SystemExit("unknown edit")
assert s.count(old) == 1, s.count(old)
open(path, "w").write(s.replace(old, new))
PYEOF
  (cd $scr && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-$name .) || { say "SCRATCH BUILD FAILED ($name)"; return 1; }
  say "== DIAGNOSTIC scratch engine $name sha256 $(sha out/kortex-engine-DIAGNOSTIC-$name); diff of config.go against engine/config.go:"
  diff engine/config.go $scr/config.go | cut -c1-200 | tee -a "$LOG"
}

build_reference() {
  (cd tools/crs-ftw-reference && go build -buildvcs=false -o ../../$BIN/crs-ftw-reference .) || { say "REFERENCE BUILD FAILED"; return 1; }
  say "== reference binary sha256 $(sha $BIN/crs-ftw-reference): $(go version -m $BIN/crs-ftw-reference | awk '$1=="dep" && ($2 ~ /coraza\/v3$/ || $2 ~ /albedo$/) {printf "%s %s %s; ", $2, $3, $4}')"
}

WAF_PID=""; BACKEND_PID=""
stop_all() {
  if [ -n "$WAF_PID" ]; then
    local kids; kids=$(pgrep -P $WAF_PID)
    kill $WAF_PID 2>/dev/null; wait $WAF_PID 2>/dev/null
    [ -n "$kids" ] && kill -9 $kids 2>/dev/null
    WAF_PID=""
  fi
  if [ -n "$BACKEND_PID" ]; then kill $BACKEND_PID 2>/dev/null; wait $BACKEND_PID 2>/dev/null; BACKEND_PID=""; fi
  sleep 1
}
trap stop_all EXIT

wait_port() { for i in $(seq 1 120); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$1/ && return 0; sleep 0.5; done; return 1; }

one_run() {
  local run=$1 kind engine_bin=out/kortex-engine ftw=out/step25/bin210/go-ftw overrides="" worker="" title refargs="-xml-attr-inspect"
  case $run in
    ref-asis)        kind=ref;    refargs=""; title="reference: stock coraza v3.8.1 middleware, coraza's harness configuration as written (no rule 900511), no overrides" ;;
    ref-strict)      kind=ref;    title="reference: stock coraza v3.8.1 middleware plus rule 900511, no overrides" ;;
    ref-upstream)    kind=ref;    overrides=$OVERRIDES; title="reference: stock coraza v3.8.1 middleware plus rule 900511, CRS coraza-overrides.yaml" ;;
    engine-strict)   kind=engine; title="engine, in-process, no overrides" ;;
    engine-upstream) kind=engine; overrides=$OVERRIDES; title="engine, in-process, CRS coraza-overrides.yaml" ;;
    engine-worker)   kind=engine; worker="KORTEX_WORKER_MODE=on KORTEX_WORKER_POOL=3 KORTEX_WORKER_SPARES=1"; title="engine, worker mode, no overrides" ;;
    engine-repeat)   kind=engine; title="engine, in-process, no overrides, repeat" ;;
    engine-ftw270)   kind=engine; ftw=$BIN/go-ftw; title="engine, in-process, no overrides, go-ftw v2.7.0" ;;
    stock)           kind=engine; engine_bin=out/kortex-engine-DIAGNOSTIC-stock-coraza; run=DIAGNOSTIC-stock; title="DIAGNOSTIC: engine built against stock coraza v3.8.1, in-process, no overrides" ;;
    diag-no-body-targets) kind=engine; engine_bin=out/kortex-engine-DIAGNOSTIC-no-body-targets; run=DIAGNOSTIC-no-body-targets; title="DIAGNOSTIC: engine without the REQUEST_BODY target updates, in-process, no overrides" ;;
    diag-no-900220)  kind=engine; engine_bin=out/kortex-engine-DIAGNOSTIC-no-900220; run=DIAGNOSTIC-no-900220; title="DIAGNOSTIC: engine without rule 900220, in-process, no overrides" ;;
    *) say "unknown run $run"; return 1 ;;
  esac
  local out=$PWD/out/step25/runs/$LABEL-$run dur=$DUR/$run
  rm -rf "$out" "$dur"; mkdir -p "$out" "$dur"
  say ""
  say "## run $run: $title"
  if [ $kind = ref ]; then
    $BIN/crs-ftw-reference -listen 127.0.0.1:$WAF_PORT \
      -coraza-conf "$(go env GOMODCACHE)/github.com/corazawaf/coraza/v3@v3.8.1/coraza.conf-recommended" \
      -crs-setup $PWD/$CRS/crs-setup.conf.example -rules $PWD/engine/crs/owasp-crs/rules \
      -error-log "$out/error.log" $refargs > "$out/waf.log" 2>&1 &
    WAF_PID=$!
    wait_port $WAF_PORT || { say "reference did not start"; stop_all; return 1; }
    say "== $run WAF: $(head -1 "$out/waf.log"); coraza.conf-recommended sha256 $(sha "$(go env GOMODCACHE)/github.com/corazawaf/coraza/v3@v3.8.1/coraza.conf-recommended"), crs-setup.conf.example sha256 $(sha $CRS/crs-setup.conf.example)"
  else
    $BIN/albedo --bind 127.0.0.1 --port $BACKEND_PORT > "$out/albedo.log" 2>&1 &
    BACKEND_PID=$!
    wait_port $BACKEND_PORT || { say "albedo did not start"; stop_all; return 1; }
    env KORTEX_BACKEND_URL=http://127.0.0.1:$BACKEND_PORT KORTEX_RULES_DIR=$PWD/engine/crs \
      KORTEX_RULE_ENGINE=DetectionOnly KORTEX_BLOCKING_PARANOIA=4 KORTEX_DETECTION_PARANOIA=4 \
      KORTEX_MAX_BODY_BYTES=13107200 KORTEX_MAX_INSPECTED_BYTES=131072 \
      KORTEX_MAX_INFLIGHT_BODY=8 KORTEX_MAX_INFLIGHT_BODY_LARGE=2 KORTEX_BODY_LANE_THRESHOLD=65536 \
      KORTEX_ENGINE_TIME_BUDGET_MS=2000 KORTEX_LISTEN_ADDR=127.0.0.1:$WAF_PORT \
      KORTEX_EVENTS_FILE="$out/events.jsonl" KORTEX_AUDIT_LOG="$out/audit.log" \
      KORTEX_ERROR_LOG="$out/error.log" KORTEX_CRS_TEST_SETUP=on $worker \
      $engine_bin > "$out/waf.log" 2>&1 &
    WAF_PID=$!
    wait_port $WAF_PORT || { say "engine did not start"; stop_all; return 1; }
    say "== $run rule29 $(date -u +%FT%TZ) load: $(uptime | sed 's/.*load/load/'): $(curl -s http://127.0.0.1:$WAF_PORT/__kortex/config)"
    say "== $run engine binary sha256 $(sha $engine_bin)"
  fi
  printf 'logfile: %s\nlogmarkerheadername: X-CRS-TEST\ntestoverride:\n  input:\n    port: %s\n' "$out/error.log" $WAF_PORT > "$out/.ftw.yaml"
  local args="--config $out/.ftw.yaml"
  [ -n "$overrides" ] && args="$args --overrides $overrides"
  say "== $run go-ftw: $ftw ($(go version -m $ftw | awk '$1=="mod"{print $3}'), sha256 $(sha $ftw)); overrides: ${overrides:-none}"
  say "== $run command: go-ftw run $args -d $TESTS -o json --report-triggered-rules --read-timeout 10s"
  # go-ftw stops the whole run when a test marked retry_once fails twice
  # ("Error: retry-once"). Such a test is recorded as having aborted the
  # runner, counted as failed, excluded, and the run starts again from a
  # fresh error log.
  local t0=$(date +%s) rc aborted="" attempt=0 excl
  : > "$out/aborted.txt"; : > "$out/unsent.txt"
  while :; do
    attempt=$((attempt + 1))
    excl=""
    [ -n "$aborted" ] && excl="-e ^(${aborted})\$"
    : > "$out/error.log"
    [ -f "$out/events.jsonl" ] && : > "$out/events.jsonl"
    $ftw run $args -d $TESTS -o json --report-triggered-rules --read-timeout 10s $excl > "$out/ftw.json" 2> "$out/ftw.stderr"
    rc=$?
    if grep -q '^Error: .*retry-once$' "$out/ftw.stderr" && [ $attempt -lt 30 ]; then
      local tid; tid=$(sed -n 's/.*Retrying test once: \([0-9]*-[0-9]*\).*/\1/p' "$out/ftw.stderr" | tail -1)
      [ -n "$tid" ] || { say "== $run go-ftw aborted with retry-once but named no test"; break; }
      say "== $run attempt $attempt: go-ftw aborted (exit $rc, 'Error: retry-once') at test $tid, which failed twice; counted as failed, excluded, run restarted"
      echo "$tid" >> "$out/aborted.txt"
      aborted="${aborted:+$aborted|}$tid"
      continue
    fi
    # the runner itself refuses to send a test (go-ftw 2.7.0 and raw CR / LF
    # in a header): recorded as not sent by the runner, excluded, restarted
    if grep -q 'failed sending request to destination.*fatal error building request' "$out/ftw.stderr" && [ $attempt -lt 30 ]; then
      local tid; tid=$(sed -n 's/^Error: .*(test \([0-9]*-[0-9]*\)).*/\1/p' "$out/ftw.stderr" | tail -1)
      [ -n "$tid" ] || { say "== $run go-ftw refused to send a test but named none"; break; }
      say "== $run attempt $attempt: go-ftw refused to build the request of test $tid (exit $rc: $(sed -n 's/^Error: .*fatal error building request: \(.*\)$/\1/p' "$out/ftw.stderr" | tail -1 | cut -c1-90)); recorded as not sent by the runner, excluded, run restarted"
      echo "$tid" >> "$out/unsent.txt"
      aborted="${aborted:+$aborted|}$tid"
      continue
    fi
    break
  done
  say "== $run go-ftw exit status $rc after $attempt attempt(s), $(( $(date +%s) - t0 )) s, exclude option: ${excl:-none}, stderr lines $(wc -l < "$out/ftw.stderr" | tr -d ' '), load at end: $(uptime | sed 's/.*load/load/')"
  stop_all
  # durable, small evidence; the raw error log quotes the suite's payloads and stays under out/
  cp "$out/ftw.json" "$dur/ftw.json"
  cp "$out/.ftw.yaml" "$dur/ftw.yaml"
  cp "$out/aborted.txt" "$dur/aborted.txt"
  cp "$out/unsent.txt" "$dur/unsent.txt"
  head -c 200000 "$out/ftw.stderr" > "$dur/ftw.stderr.txt"
  [ -f "$out/events.jsonl" ] && $PY tools/step25_ftw_summary.py compact "$out/events.jsonl" "$dur"
  grep -h 'effective config' "$out/waf.log" > "$dur/waf-startup.txt" 2>/dev/null
  say "== $run error log: $(wc -l < "$out/error.log" | tr -d ' ') lines, $(wc -c < "$out/error.log" | tr -d ' ') bytes, sha256 $(sha "$out/error.log") (out/step25/runs/$LABEL-$run/error.log, not committed)"
  $PY tools/step25_ftw_summary.py one "$dur" 2>&1 | tee -a "$LOG"
}

need_engine=0; need_stock=0; need_ref=0; need_nbt=0; need_n9=0
for r in $RUNS; do
  case $r in ref-*) need_ref=1 ;; stock) need_stock=1 ;; diag-no-body-targets) need_nbt=1 ;; diag-no-900220) need_n9=1 ;; *) need_engine=1 ;; esac
done
[ $need_nbt = 1 ] && { build_scratch no-body-targets no-body-targets || exit 1; }
[ $need_n9 = 1 ] && { build_scratch no-900220 no-900220 || exit 1; }
[ $need_ref = 1 ] && { build_reference || exit 1; }
[ $need_engine = 1 ] && { build_engine || exit 1; }
[ $need_stock = 1 ] && { build_stock || exit 1; }
for r in $RUNS; do one_run $r; done
say ""
say "== done $(date -u +%FT%TZ), load: $(uptime | sed 's/.*load/load/')"
