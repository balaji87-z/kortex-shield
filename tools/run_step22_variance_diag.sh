#!/bin/bash
# Step-22 DIAGNOSTIC C (rule 34): why does the set of matched rules (and, as
# this run shows, the status) of one unchanged request vary between replays?
# Never a baseline or parity number.
#
# Hypotheses, both about coraza v3.8.1 iterating its Go-map collections in a
# different order on every call (internal/collections/map.go FindAll):
#   H1 capture order: a rule with `capture` and a chained rule that reads
#      TX:1/TX:2 (CRS 942130) sees the captures of whichever variable was
#      evaluated last, so the chain outcome depends on the iteration order.
#   H2 transformation cache: the cache key is (pointer to the key string,
#      position in the value list, variable, transformation id)
#      (internal/corazawaf/rule.go transformArg). Values that share one key
#      share the pointer, the position changes with the iteration order, so a
#      rule can get the cached transformation of the other value.
# Discriminating builds (scratch copies under out/, never committed):
#   stock    engine/ as committed
#   nocache  coraza patched: transformArg never uses the cache
#   sorted   coraza patched: collections iterate in sorted key order
#   upstream coraza main at commit $UPSTREAM_COMMIT (has the cache-key fix of PR #1682)
# H1 predicts: syn-chain varies on stock AND nocache, constant on sorted.
# H2 predicts: syn-dup varies on stock, constant on nocache.
# If PR #1682 fixes H2 and not H1: on upstream syn-dup is constant, syn-chain still varies.
#
# Usage: run_step22_variance_diag.sh engine       three builds, PL2, in-process
#        run_step22_variance_diag.sh containers   ModSecurity and Coraza connector images, PL2
# Log: docs/logs/step22-variance-<part>-DIAGNOSTIC.txt; counts in docs/logs/runs/s22-variance-DIAGNOSTIC/
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
STUB_PORT=13001   # own stub: other step-22 scripts stop the one on 13000
PART=${1:?engine or containers}
REPS=${REPS:-200}
UPSTREAM_COMMIT=${UPSTREAM_COMMIT:-4cc95a33a6a2}
DUR=docs/logs/runs/s22-variance-DIAGNOSTIC
LOG=docs/logs/step22-variance-$PART-DIAGNOSTIC.txt
mkdir -p out $DUR
: > $LOG
echo "# Step-22 DIAGNOSTIC C, $PART: status and matched-rule variance of unchanged requests, $REPS replays each (never a baseline or parity number)" >> $LOG

# two benign-wcp-v0 ids from DIAGNOSTIC B, when the local (uncommitted) manifest is present
WCP=out/s22-variance-two.jsonl
WCPARG=""
if [ -f data/benign-wcp-v0/manifest.jsonl ]; then
  $PY - > $WCP <<'PYEOF'
import json
want = {"wcp-35f82c1417df", "wcp-7b0bdeda7bc7"}
for line in open("data/benign-wcp-v0/manifest.jsonl"):
    if json.loads(line)["id"] in want:
        print(line, end="")
PYEOF
  WCPARG="--manifest $WCP"
else
  echo "== data/benign-wcp-v0/manifest.jsonl absent: the two wcp ids are NOT MEASURED, synthetic requests only" >> $LOG
fi

if [ "$PART" = engine ]; then
  echo "== host: $(uname -srm); $(go version); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG
  CORAZA=$(cd engine && go list -m -f '{{.Dir}}' github.com/corazawaf/coraza/v3)
  echo "== coraza module: $(cd engine && go list -m github.com/corazawaf/coraza/v3)" >> $LOG
  build_engine $LOG || exit 1
  cp $ENGINE_BIN out/kortex-engine-DIAGNOSTIC-stock
  for V in nocache sorted; do
    SCR=out/DIAGNOSTIC-engine-$V
    rm -rf $SCR out/DIAGNOSTIC-coraza-$V
    mkdir -p $SCR && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $SCR && tar xf -)
    cp -R "$CORAZA" out/DIAGNOSTIC-coraza-$V && chmod -R u+w out/DIAGNOSTIC-coraza-$V
    $PY - out/DIAGNOSTIC-coraza-$V $V >> $LOG <<'PYEOF' || { echo "PATCH FAILED for $V" | tee -a $LOG; exit 1; }
import pathlib, sys
root, variant = pathlib.Path(sys.argv[1]), sys.argv[2]
def patch(rel, old, new, count):
    p = root / rel
    s = p.read_text()
    assert s.count(old) == count, f"{rel}: expected {count} occurrence(s) of the patch anchor, found {s.count(old)}"
    p.write_text(s.replace(old, new))
    print(f"   patch {variant}: {rel}: {count} replacement(s)")
if variant == "nocache":
    patch("internal/corazawaf/rule.go",
          'case arg.Variable().Name() == "TX":',
          'case true: // DIAGNOSTIC: never use the transformation cache', 1)
else:
    (root / "internal/collections/diag_sorted.go").write_text(
        "package collections\n\nimport \"sort\"\n\n// DIAGNOSTIC: deterministic iteration order\n"
        "func sortedKeys(m map[string][]keyValue) []string {\n\tkeys := make([]string, 0, len(m))\n"
        "\tfor k := range m {\n\t\tkeys = append(keys, k)\n\t}\n\tsort.Strings(keys)\n\treturn keys\n}\n")
    # named.go: FindAll and String() share the anchor, both are made ordered
    for rel, data, n in (("internal/collections/map.go", "c.data", 1), ("internal/collections/named.go", "c.collection.data", 2)):
        patch(rel, f"\tfor _, data := range {data} {{\n\t\tfor _, d := range data {{",
              f"\tfor _, k := range sortedKeys({data}) {{\n\t\tdata := {data}[k]\n\t\tfor _, d := range data {{", n)
        patch(rel, f"\tfor k, data := range {data} {{\n\t\tif key.MatchString(k) {{",
              f"\tfor _, k := range sortedKeys({data}) {{\n\t\tdata := {data}[k]\n\t\tif key.MatchString(k) {{", 1)
PYEOF
    (cd $SCR && go mod edit -replace github.com/corazawaf/coraza/v3=../DIAGNOSTIC-coraza-$V \
      && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-$V .) >> $LOG 2>&1 || { echo "SCRATCH BUILD FAILED for $V" | tee -a $LOG; exit 1; }
    echo "== build $V: sha256 $(sha256_of out/kortex-engine-DIAGNOSTIC-$V); .go files of engine/ that differ in the scratch copy: $(diff -rq --exclude=go.mod --exclude=go.sum --exclude=engine --exclude='*.log' engine $SCR | wc -l | tr -d ' '); coraza files that differ from the module: $(diff -rq "$CORAZA" out/DIAGNOSTIC-coraza-$V | wc -l | tr -d ' ')" >> $LOG
    diff -rq "$CORAZA" out/DIAGNOSTIC-coraza-$V | sed "s|$CORAZA|<coraza>|; s|^|      |" >> $LOG
  done
  # upstream: coraza main at a pinned commit, which contains PR #1682
  # "key the transformation cache by value identity" (issue #1681). Needs the
  # network once; other modules move with it (see the go.mod diff in the log).
  SCR=out/DIAGNOSTIC-engine-upstream
  rm -rf $SCR && mkdir -p $SCR && (cd engine && tar cf - --exclude engine --exclude '*.log' .) | (cd $SCR && tar xf -)
  if (cd $SCR && go get github.com/corazawaf/coraza/v3@$UPSTREAM_COMMIT > /dev/null 2>&1 && go mod tidy > /dev/null 2>&1 \
      && go build -buildvcs=false -o ../kortex-engine-DIAGNOSTIC-upstream .) >> $LOG 2>&1; then
    VARIANTS="stock nocache sorted upstream"
    echo "== build upstream: sha256 $(sha256_of out/kortex-engine-DIAGNOSTIC-upstream); go.mod against engine/go.mod:" >> $LOG
    diff engine/go.mod $SCR/go.mod | sed 's/^/      /' >> $LOG
  else
    VARIANTS="stock nocache sorted"
    echo "== build upstream: FAILED (network or API change); variant NOT MEASURED" >> $LOG
  fi
  start_stub || exit 1
  for V in $VARIANTS; do
    ENGINE_BIN=out/kortex-engine-DIAGNOSTIC-$V
    NAME=DIAGNOSTIC-variance-$V-pl2
    start_engine var-$V inprocess 8095 2 2000 $DUR/engine-$NAME.log || { echo "== $NAME: engine did not start" >> $LOG; continue; }
    config_proof "$NAME" 8095 $LOG
    $PY tools/run_step22_variance_diag.py --base-url $BASE:8095 --reps $REPS $WCPARG \
      --block-marker 'kortex-decision=block' --out $DUR/$NAME.status.json >> $LOG 2>&1
    stop_engine
    $PY -m kortex_eval.crs_audit --logs $ENGINE_AUDIT --out out/s22-$NAME.audit.jsonl >> $LOG 2>&1
    $PY tools/step22_variance_summary.py out/s22-$NAME.audit.jsonl $V >> $LOG
  done
  stop_stub
else
  echo "== host: $(uname -srm); docker server $(docker version --format '{{.Server.Version}} {{.Server.Os}}/{{.Server.Arch}}'); load at start: $(uptime | sed 's/.*load/load/')" >> $LOG
  for ENG in modsec coraza; do
    NAME=DIAGNOSTIC-variance-$ENG-pl2
    up=0
    docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1 || true
    if [ $ENG = modsec ]; then PORT=8081; C=deploy-baseline-crs-1; else PORT=8082; C=deploy-coraza-crs-1; fi
    for try in 1 2 3; do
      if [ $ENG = modsec ]; then
        MODSEC_RULE_ENGINE=On PARANOIA=2 BLOCKING_PARANOIA=2 DETECTION_PARANOIA=2 BACKEND=http://stub-backend:3000 \
          docker compose -f deploy/compose.yml up -d --force-recreate stub-backend baseline-crs > /dev/null 2>&1
      else
        MODSEC_RULE_ENGINE=On PARANOIA=2 BLOCKING_PARANOIA=2 DETECTION_PARANOIA=2 \
          CORAZA_RULE_ENGINE=On CORAZA_BACKEND=stub-backend:3000 \
          docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate stub-backend coraza-crs > /dev/null 2>&1
      fi
      for i in $(seq 1 30); do curl -s -o /dev/null --max-time 3 http://localhost:$PORT/ && { up=1; break; }; sleep 1; done
      [ $up = 1 ] && break
    done
    [ $up = 1 ] || { echo "== $NAME: CONTAINER DID NOT START, run skipped" | tee -a $LOG; continue; }
    {
      echo "== $NAME rule29/28 $(date -u +%FT%TZ)"
      echo "   image: $(docker inspect --format '{{.Config.Image}} id {{.Image}}' $C) platform $(docker image inspect --format '{{.Os}}/{{.Architecture}}' $(docker inspect --format '{{.Image}}' $C))"
      if [ $ENG = modsec ]; then
        docker exec $C bash -c 'echo "   env: E=$MODSEC_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA"; echo "   ruleset: $(grep -m1 -o "ver:.OWASP_CRS/[0-9.]*" /etc/modsecurity.d/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf); engine: $(strings /usr/local/lib/libmodsecurity.so* 2>/dev/null | grep -m1 -o "ModSecurity v[0-9.]*" || echo "libmodsecurity version: see nginx start-up line")"'
        docker exec $C sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/modsecurity/audit/audit.log|' /etc/modsecurity.d/modsecurity.conf
        docker exec $C nginx -s reload 2>&1 | grep -o "libmodsecurity3 version [0-9.]*" | sed 's/^/   /'
        for i in $(seq 1 15); do
          sleep 1
          curl -s -o /dev/null "http://localhost:$PORT/?audit-warmup-blocked=%27%20OR%201%3d1--"
          docker exec $C sh -c '[ -s /var/log/modsecurity/audit/audit.log ]' && break
        done
        sleep 3
      else
        docker exec $C sh -c 'echo "   env: E=$CORAZA_RULE_ENGINE B=$BLOCKING_PARANOIA P=$PARANOIA D=$DETECTION_PARANOIA"; echo "   ruleset: $(grep -m1 -o "ver:.OWASP_CRS/[0-9.]*" /opt/coraza/owasp-crs/rules/REQUEST-901-INITIALIZATION.conf); engine: $(strings /usr/local/lib/libcoraza.so 2>/dev/null | grep -m1 -o "corazawaf/coraza/v3@v[0-9.]*" || echo "coraza version not readable")"'
      fi
    } >> $LOG 2>&1
    $PY tools/run_step22_variance_diag.py --base-url http://localhost:$PORT --reps $REPS $WCPARG \
      --block-marker '<center>nginx</center>' --out $DUR/$NAME.status.json >> $LOG 2>&1
    sleep 2
    if [ $ENG = modsec ]; then
      docker cp $C:/var/log/modsecurity/audit/audit.log out/s22-$NAME.raw-audit.log >> $LOG 2>&1
      $PY -m kortex_eval.crs_audit --logs out/s22-$NAME.raw-audit.log --out out/s22-$NAME.audit.jsonl >> $LOG 2>&1
    else
      docker cp $C:/var/log/coraza/audit/audit.log out/s22-$NAME.raw-audit.log >> $LOG 2>&1
      $PY tools/coraza_audit.py --logs out/s22-$NAME.raw-audit.log --out out/s22-$NAME.audit.jsonl >> $LOG 2>&1
    fi
    $PY tools/step22_variance_summary.py out/s22-$NAME.audit.jsonl $ENG >> $LOG
  done
  docker compose -f deploy/compose.yml --profile coraza down > /dev/null 2>&1
fi
echo "== load at end: $(uptime | sed 's/.*load/load/')" >> $LOG
echo S22-VARIANCE-DIAG-DONE
