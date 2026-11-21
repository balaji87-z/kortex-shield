#!/bin/bash
# Step-20 T1: does the coraza connector (pinned image, coraza v3.7.0 inside)
# share the duplicate-arg flip defect? flip_repro 5x500 at PL2 against
# deploy-coraza-crs-1 (rule 13: force-recreate, one capture, sequential).
# The dup-args measurement (20 repeats) cannot see a ~2% per-transaction
# defect; this high-repeat run is the discriminating test (rule 44).
set -u
cd "$(dirname "$0")/.."
RUNDIR=docs/logs/runs/s20-t1-flip-connector
mkdir -p "$RUNDIR"
export PARANOIA=2 BLOCKING_PARANOIA=2 DETECTION_PARANOIA=2
export CORAZA_RULE_ENGINE=On CORAZA_BACKEND=http://stub-backend:3000
echo "== connector flip run $(date -u +%FT%TZ) load=[$(uptime | grep -o 'load average.*')]"
# stub-backend FIRST and running before coraza-crs: nginx resolves the
# upstream host at config load; a parallel start races Docker DNS and nginx
# exits 1 "invalid host in upstream" (attempt 1, 2026-11-21 13:09, INVALID).
docker compose -f deploy/compose.yml up -d stub-backend 2>&1 | tail -1
for i in $(seq 1 30); do
  [ "$(docker inspect deploy-stub-backend-1 --format '{{.State.Status}}' 2>/dev/null)" = "running" ] && break
  sleep 1
done
sleep 2
docker compose -f deploy/compose.yml --profile coraza up -d --force-recreate --no-deps coraza-crs 2>&1 | tail -2
code=000
for attempt in 1 2 3; do
  for i in $(seq 1 45); do
    code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8082/ || true)
    [ "$code" != "000" ] && break
    if [ "$(docker inspect deploy-coraza-crs-1 --format '{{.State.Status}}' 2>/dev/null)" = "exited" ]; then
      echo "coraza-crs exited during startup (attempt $attempt); restarting"; docker start deploy-coraza-crs-1 >/dev/null
    fi
    sleep 1
  done
  [ "$code" != "000" ] && break
done
echo "readiness probe status=$code"
if [ "$code" = "000" ]; then echo "CORAZA NOT UP - run INVALID"; docker logs deploy-coraza-crs-1 2>&1 | tail -3; exit 1; fi
# rule-29 effective config proof from inside the running container
{
  echo "== rule29 connector effective config $(date -u +%FT%TZ)"
  docker exec deploy-coraza-crs-1 sh -c 'grep -E "^SecRuleEngine|^SecRequestBodyLimit|^SecRequestBodyNoFilesLimit" /opt/coraza/config/coraza.conf'
  docker exec deploy-coraza-crs-1 sh -c 'grep -E "blocking_paranoia_level|detection_paranoia_level|crs_setup_version" /opt/coraza/config/crs-setup.conf | grep -v "^#" | head -6'
  echo -n "coraza build info: "
  docker exec deploy-coraza-crs-1 sh -c 'grep -a -o "github.com/corazawaf/coraza/v3@v[0-9.]*" /usr/local/lib/libcoraza.so | head -1'
  echo -n "CRS version: "
  docker exec deploy-coraza-crs-1 sh -c 'grep -a -o "coreruleSet.*ver.*" /opt/coraza/config/crs-setup.conf 2>/dev/null | head -1; cat /opt/coraza/CRS_VERSION 2>/dev/null || true'
  docker image inspect ghcr.io/coreruleset/coraza-crs@sha256:bfbfe70b4445c1ef1dc389c2de12cfdb194c9616746c33dc8a7131461c28f4a6 --format 'image id: {{.Id}} repoDigests={{.RepoDigests}}'
} 2>&1 | tee "$RUNDIR/config-proof.txt"
# canary probe: both samples must block (403) at PL2 or the flip metric is void
.venv/bin/python - <<'EOF' | tee "$RUNDIR/probe.txt"
import sys; sys.path.insert(0, "tools")
from flip_repro import load_samples, send
for s in load_samples("data/benign-wcp-v0/manifest.jsonl"):
    st, ms = send(s, "127.0.0.1", 8082, 30)
    print(f"probe {s['id']}: status={st} ms={ms:.1f}")
EOF
for R in 1 2 3 4 5; do
  .venv/bin/python tools/flip_repro.py --base-url http://127.0.0.1:8082 --rounds 500 \
    --out "$RUNDIR/rounds-pl2-r$R.jsonl" 2>/dev/null | tail -1
done
echo "load_end=[$(uptime | grep -o 'load average.*')]"
# capture the connector audit log for this run (rule 42)
docker exec deploy-coraza-crs-1 sh -c 'cat /var/log/coraza/audit/audit.log' > "$RUNDIR/audit-connector.log" 2>/dev/null
wc -l "$RUNDIR/audit-connector.log"
echo "CONNECTOR-FLIP-DONE"
