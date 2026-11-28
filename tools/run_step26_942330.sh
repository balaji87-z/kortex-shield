#!/bin/bash
# Step-26 DIAGNOSTIC (rule 34): the four attacks-v1 requests for which the
# engine logs CRS 942330 at PL2 and the Coraza connector image does not.
# Each of the four is sent 25 times (100 requests) to
#   a) the engine (patched coraza, step 23),
#   b) the engine built in a scratch copy against stock coraza v3.8.1,
#   d) the engine built in a scratch copy against coraza v3.7.0 (the version
#      inside the connector image),
#   e) the engine's own source built with -tags coraza.rule.no_regex_multiline
#      (the tag the connector image's libcoraza.so names),
#   c) the Coraza connector image,
# and the audit entries that carry 942330 are counted per request. Each case
# tests one explanation: the step-23 patch (a against b), randomness (25
# sends), the coraza version (d), the regex build tag (e).
# Usage: [STUB_PORT=13004] run_step26_942330.sh   (needs docker for c)
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
LOG=docs/logs/step26-DIAGNOSTIC-942330.txt
IDS="v1-command-injection-0a2a074b-login v1-command-injection-0a2a074b-q v1-command-injection-7dc8718c-login v1-command-injection-7dc8718c-q"
M=out/step26-942330-manifest.jsonl
mkdir -p out; : > $LOG
echo "# Step-26 DIAGNOSTIC: CRS 942330 on four attacks-v1 requests, 25 sends each, PL2" | tee -a $LOG
echo "== $(date -u +%FT%TZ), git $(git rev-parse HEAD), $(go version), load at start: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
$PY - data/attacks-v1/manifest.jsonl $M $IDS <<'PYEOF'
import json, sys
src, dst, ids = sys.argv[1], sys.argv[2], sys.argv[3:]
rows = {json.loads(l)["id"]: json.loads(l) for l in open(src)}
with open(dst, "w") as fh:
    for rep in range(1, 26):
        for i in ids:
            r = dict(rows[i]); r["id"] = f"{i}-r{rep:02d}"
            fh.write(json.dumps(r) + "\n")
PYEOF
echo "== manifest $M: $(wc -l < $M | tr -d ' ') requests (not committed: copies of 4 frozen samples)" | tee -a $LOG
count() { # <label> <audit.jsonl>
  $PY - "$1" "$2" $IDS <<'PYEOF' | tee -a $LOG
import collections, json, sys
label, path, ids = sys.argv[1], sys.argv[2], sys.argv[3:]
entries, with_rule = collections.Counter(), collections.Counter()
sets, scores = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
for line in open(path):
    if not line.strip():
        continue
    e = json.loads(line)
    sid = (e.get("sample_id") or "")
    base = sid.rsplit("-r", 1)[0]
    if base in ids:
        entries[base] += 1
        rule_ids = [str(r.get("id")) for r in (e.get("rules") or [])]
        with_rule[base] += "942330" in rule_ids
        sets[base][" ".join(sorted(set(rule_ids)))] += 1
        scores[base][str(e.get("inbound_score_from_949110"))] += 1
for i in ids:
    print(f"   {label}: {i}: audit entries {entries[i]} of 25 sends, with 942330 in {with_rule[i]}; "
          f"rule-id sets seen: {dict(sets[i])}; scores at 949110: {dict(scores[i])}")
print(f"== {label}: 942330 in {sum(with_rule.values())} of {sum(entries.values())} audit entries")
PYEOF
}
engine_case() { # <label> <tag>
  local run=out/s26-942330-$2
  rm -rf $run
  start_engine s26-942330-$2 inprocess 8097 2 2000 out/s26-942330-$2.engine.log || { echo "engine did not start ($1)" | tee -a $LOG; return 1; }
  config_proof "$1" 8097 $LOG
  echo "== $1 engine binary sha256 $(sha256_of $ENGINE_BIN)" | tee -a $LOG
  $PY -m kortex_eval.runner --manifest $M --base-url $BASE:8097 --out $run --timeout 15 --workers 1 \
    --block-status 403 --block-marker 'kortex-decision=block' --default-user-agent "$UA" > out/s26-942330-$2.runner.log 2>&1
  stop_engine
  $PY -m kortex_eval.crs_audit --logs $ENGINE_AUDIT --out $run/audit.jsonl >> $LOG 2>&1
  count "$1" $run/audit.jsonl
}
if curl -s -o /dev/null --max-time 2 http://127.0.0.1:$STUB_PORT/; then echo "port $STUB_PORT already answers" | tee -a $LOG; exit 1; fi
build_engine $LOG || exit 1
start_stub || exit 1
engine_case "engine (patched coraza)" patched
SCR=out/DIAGNOSTIC-engine-stock-coraza
rm -rf $SCR && mkdir -p $SCR && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $SCR && tar xf -)
rm -rf $SCR/third_party
(cd $SCR && go mod edit -dropreplace github.com/corazawaf/coraza/v3 \
  && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-stock-coraza .) || { echo "SCRATCH BUILD FAILED" | tee -a $LOG; exit 1; }
ENGINE_BIN=out/kortex-engine-DIAGNOSTIC-stock-coraza
echo "== DIAGNOSTIC scratch engine coraza module: $(cd $SCR && go list -m github.com/corazawaf/coraza/v3)" | tee -a $LOG
engine_case "DIAGNOSTIC engine on stock coraza v3.8.1" stock
# d) the engine against coraza v3.7.0, the version inside the connector image
#    (libcoraza.so of the image names corazawaf/coraza/v3@v3.7.0)
SCR=out/DIAGNOSTIC-engine-coraza370
rm -rf $SCR && mkdir -p $SCR && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $SCR && tar xf -)
rm -rf $SCR/third_party
(cd $SCR && go mod edit -dropreplace github.com/corazawaf/coraza/v3 \
  && go mod edit -require github.com/corazawaf/coraza/v3@v3.7.0 && go mod tidy >/dev/null 2>&1 \
  && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-coraza370 .) || { echo "SCRATCH BUILD FAILED (coraza 3.7.0)" | tee -a $LOG; exit 1; }
ENGINE_BIN=out/kortex-engine-DIAGNOSTIC-coraza370
echo "== DIAGNOSTIC scratch engine coraza module: $(cd $SCR && go list -m github.com/corazawaf/coraza/v3); files that differ from engine/ other than go.mod, go.sum and third_party: $(diff -rq --exclude=go.mod --exclude=go.sum --exclude=third_party --exclude=engine --exclude='*.log' engine $SCR | wc -l | tr -d ' ')" | tee -a $LOG
engine_case "DIAGNOSTIC engine on coraza v3.7.0" coraza370
# e) the engine's own source built with the Go build tag the connector image's
#    libcoraza.so was built with: coraza.rule.no_regex_multiline
(cd engine && go build -buildvcs=false -tags coraza.rule.no_regex_multiline -o ../out/kortex-engine-DIAGNOSTIC-no-regex-multiline .) || { echo "TAG BUILD FAILED" | tee -a $LOG; exit 1; }
ENGINE_BIN=out/kortex-engine-DIAGNOSTIC-no-regex-multiline
echo "== DIAGNOSTIC engine built from engine/ unchanged with -tags coraza.rule.no_regex_multiline" | tee -a $LOG
engine_case "DIAGNOSTIC engine with -tags coraza.rule.no_regex_multiline" tag
stop_stub
docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1 || true
MODSEC_RULE_ENGINE=On PARANOIA=2 BLOCKING_PARANOIA=2 DETECTION_PARANOIA=2 CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
  docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null 2>&1
for i in $(seq 1 30); do curl -s -o /dev/null --max-time 3 http://localhost:8082/ && break; sleep 1; done
c=deploy-coraza-crs-1
echo "== coraza version inside the connector image (grep in /usr/local/lib/libcoraza.so): $(docker exec $c sh -c 'grep -a -o "corazawaf/coraza/v3@v[0-9.a-z-]*" /usr/local/lib/libcoraza.so | sort | uniq -c | tr -s " "' | tr '\n' ';')" | tee -a $LOG
echo "== build tags named inside the connector image's libcoraza.so: $(docker exec $c sh -c 'grep -a -o "\-tags=[a-zA-Z_.,]*" /usr/local/lib/libcoraza.so | sort | uniq -c | tr -s " "' | tr '\n' ';')" | tee -a $LOG
echo "== connector image: $(docker inspect --format '{{.Config.Image}}' $c); $(docker exec $c sh -c 'echo "E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA D=$DETECTION_PARANOIA"; grep -m1 -o "ver:.OWASP_CRS/[0-9.]*" /opt/coraza/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf')" | tee -a $LOG
run=out/s26-942330-connector; rm -rf $run
$PY -m kortex_eval.runner --manifest $M --base-url http://localhost:8082 --out $run --timeout 15 --workers 1 \
  --default-user-agent "$UA" > out/s26-942330-connector.runner.log 2>&1
sleep 2
docker cp $c:/var/log/coraza/audit/audit.log $run/raw-audit.log >> $LOG 2>&1
$PY tools/coraza_audit.py --logs $run/raw-audit.log --out $run/audit.jsonl >> $LOG 2>&1
count "Coraza connector image" $run/audit.jsonl
docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1
echo "== load at end: $(uptime | sed 's/.*load/load/')" | tee -a $LOG
echo S26-942330-DONE | tee -a $LOG
