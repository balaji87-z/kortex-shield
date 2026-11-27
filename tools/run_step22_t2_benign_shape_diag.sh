#!/bin/bash
# Step-22 T2 DIAGNOSTIC (rule 34): what does the benign probe of the T2 attack
# cells get from an IDLE engine? tools/run_step22_t2_attack.py counts a benign
# request as served only on status 200. This sends the two requests the first
# recorded cells sent (numeric-IP Host, no User-Agent) and the corrected ones
# (Host localhost, browser User-Agent) to an engine with no attack running,
# at PL1 and PL2, and prints status and scoring rule ids.
# It then re-reads the recorded recovery samples of the committed cells.
# Never a baseline number. Log: docs/logs/step22-t2-benign-shape-DIAGNOSTIC.txt
set -u
cd "$(dirname "$0")/.."
. tools/step22_lib.sh
LOG=docs/logs/step22-t2-benign-shape-DIAGNOSTIC.txt
mkdir -p out
: > $LOG
echo "# Step-22 T2 DIAGNOSTIC: the T2 benign probe against an idle engine (no attack)" >> $LOG
echo "== host: $(uname -srm); load: $(uptime | sed 's/.*load/load/')" >> $LOG
build_engine $LOG || exit 1
start_stub || exit 1
for PL in 1 2; do
  start_engine DIAGNOSTIC-t2-benign-pl$PL worker 8096 $PL 2000 out/s22-DIAGNOSTIC-t2-benign-pl$PL.engine.log || continue
  config_proof "DIAGNOSTIC idle PL$PL" 8096 $LOG
  $PY - $ENGINE_EVENTS >> $LOG <<'PYEOF'
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("t2", "tools/run_step22_t2_attack.py")
t2 = importlib.util.module_from_spec(spec); spec.loader.exec_module(t2)
url = "http://127.0.0.1:8096/"
body = json.dumps({"k": "v", "n": 1}).encode()
hdrs = {"Content-Type": "application/json", "X-Kortex-Sample-Id": "DIAGNOSTIC-s22-t2-benign"}
for i in range(3):
    # the shape the first recorded cells sent: numeric-IP Host, no User-Agent
    print("   old probe  POST status:", t2.raw_post(url, body, hdrs, "127.0.0.1")[0],
          " GET status:", t2.http(url + "/?q=benign", src="127.0.0.1", method="GET")[0])
new_url = "http://localhost:8096/"
new_hdrs = {**hdrs, "User-Agent": t2.BENIGN_UA}
for i in range(3):
    # the corrected shape: Host localhost, browser User-Agent
    print("   new probe  POST status:", t2.raw_post(new_url, body, new_hdrs, "127.0.0.1")[0],
          " GET status:", t2.raw_get(new_url + "/?q=benign", "127.0.0.1")[0])
seen = set()
for line in open(sys.argv[1]):
    e = json.loads(line)
    ids = [r for r in e.get("reason", "").replace("rules=", "").split(",")
           if r[:2] == "92" and r[3:].isdigit() and int(r[3:]) >= 100]
    key = (e.get("decision"), e.get("status"), tuple(ids))
    if key not in seen:
        seen.add(key)
        print(f"   event decision={key[0]} status={key[1]} 92x check rules matched={list(key[2])}")
PYEOF
  stop_engine
done
stop_stub
$PY - >> $LOG <<'PYEOF'
import json
print("== recorded recovery samples of the committed cells (docs/logs/runs/s22-t2-cells)")
for c in ("large-one", "large-eight", "small-one", "small-eight"):
    d = json.load(open(f"docs/logs/runs/s22-t2-cells/cell-{c}.json"))
    rs = d.get("recovery_samples") or []
    first = next((s["t"] for s in rs if s["workers"]["pool"] >= 4 and s["penalised_clients"] == 0
                  and s["inflight_small"] == 0 and s["inflight_large"] == 0), None)
    print(f"   {c}: pl={d['pl']} benign_post_ok={d['benign_post_ok']}/{d['benign_post_n']} "
          f"benign_get_ok={d['benign_get_ok']}/{d['benign_get_n']} recovery_s={d['recovery_s']} "
          f"benign POST ms p50={d['benign_post_ms'][len(d['benign_post_ms'])//2]} "
          f"first recovery sample with pool>=4, penalised=0, inflight=0: t={first} s of {len(rs)} samples")
PYEOF
echo S22-T2-DIAG-DONE
