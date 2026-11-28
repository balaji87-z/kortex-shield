#!/bin/bash
# Step-25: what the engine itself did with each failed test of a go-ftw run
# that is not a response-rule test (ids outside 950000-959999). One engine,
# DetectionOnly, PL4, suite setup, as in tools/run_step25_ftw.sh. Per test
# the events file is emptied, go-ftw runs that one test, and the events the
# engine wrote are listed: the first and the last belong to go-ftw's marker
# requests, the ones between to the test. Output: ids, decisions, statuses
# and reasons only.
# Usage: run_step25_failed_probe.sh <run-dir with ftw.json> > docs/logs/<name>.txt
set -u
cd "$(dirname "$0")/.."
export GOPROXY=off GOFLAGS=-mod=mod
RUN=${1:?run dir}
CRS=data/external/crs-v4.25.2/coreruleset-4.25.2
TESTS=$CRS/tests/regression/tests
BIN=out/step25/bin
WAF_PORT=${S25_WAF_PORT:-18026}
BACKEND_PORT=${S25_BACKEND_PORT:-13026}
OUT=$PWD/out/step25/probe-run
PY=.venv/bin/python
rm -rf "$OUT"; mkdir -p "$OUT"
(cd engine && go build -buildvcs=false -o ../out/kortex-engine .) || { echo "ENGINE BUILD FAILED"; exit 1; }
$BIN/albedo --bind 127.0.0.1 --port $BACKEND_PORT > "$OUT/albedo.log" 2>&1 &
BACKEND_PID=$!
env KORTEX_BACKEND_URL=http://127.0.0.1:$BACKEND_PORT KORTEX_RULES_DIR=$PWD/engine/crs \
  KORTEX_RULE_ENGINE=DetectionOnly KORTEX_BLOCKING_PARANOIA=4 KORTEX_DETECTION_PARANOIA=4 \
  KORTEX_LISTEN_ADDR=127.0.0.1:$WAF_PORT KORTEX_EVENTS_FILE="$OUT/events.jsonl" KORTEX_AUDIT_LOG="$OUT/audit.log" \
  KORTEX_ERROR_LOG="$OUT/error.log" KORTEX_CRS_TEST_SETUP=on out/kortex-engine > "$OUT/waf.log" 2>&1 &
WAF_PID=$!
trap 'kill $WAF_PID $BACKEND_PID 2>/dev/null' EXIT
for i in $(seq 1 120); do curl -s -o /dev/null --max-time 1 http://127.0.0.1:$WAF_PORT/ && break; sleep 0.5; done
printf 'logfile: %s\nlogmarkerheadername: X-CRS-TEST\ntestoverride:\n  input:\n    port: %s\n' "$OUT/error.log" $WAF_PORT > "$OUT/.ftw.yaml"
echo "# step-25: the engine's own record for each failed test outside the response rules"
echo "# $(date -u +%FT%TZ) git $(git rev-parse HEAD), engine sha256 $(shasum -a 256 out/kortex-engine | awk '{print $1}'), run $RUN"
echo "# rule29: $(curl -s http://127.0.0.1:$WAF_PORT/__kortex/config)"
echo "| test | engine events for the test request (decision status reason) | statuses go-ftw received (markers and test) | result |"
echo "|---|---|---|---|"
for id in $($PY - "$RUN" <<'PYEOF'
import json, os, re, sys
d = json.load(open(os.path.join(sys.argv[1], "ftw.json")))
ids = set(d.get("failed") or [])
ab = os.path.join(sys.argv[1], "aborted.txt")
if os.path.exists(ab):
    ids.update(x.strip() for x in open(ab) if x.strip())
ids = [i for i in ids if not i.startswith("95")]
print(" ".join(sorted(ids, key=lambda t: tuple(int(x) for x in t.split("-")))))
PYEOF
); do
  : > "$OUT/events.jsonl"
  out/step25/bin210/go-ftw run --config "$OUT/.ftw.yaml" -d $TESTS -o json --debug -i "^$id\$" > "$OUT/one.json" 2> "$OUT/one.stderr"
  $PY - "$id" "$OUT" <<'PYEOF'
import json, re, sys
tid, out = sys.argv[1], sys.argv[2]
evs = []
for line in open(out + "/events.jsonl", encoding="utf-8").read().split("\n"):
    if line.strip():
        e = json.loads(line)
        evs.append(f"{e.get('decision')} {e.get('status')} {e.get('reason')}")
mid = evs[1:-1] if len(evs) >= 3 else evs
stderr = open(out + "/one.stderr", encoding="utf-8", errors="replace").read()
stderr = re.sub(r"\x1b\[[0-9;]*m", "", stderr)
statuses = re.findall(r'received data - "HTTP/1\.[01] (\d{3})', stderr)
try:
    d = json.load(open(out + "/one.json"))
    res = "failed" if tid in (d.get("failed") or []) else ("success" if tid in (d.get("success") or []) else "?")
except ValueError:
    res = "no result (runner stopped)"
print(f"| {tid} | {'; '.join(mid) or 'none'} ({len(evs)} events in all) | {' '.join(statuses) or 'none'} | {res} |")
PYEOF
done
