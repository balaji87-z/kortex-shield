#!/bin/bash
# step-17 T1 DIAGNOSTIC (rule 34): engine built with SecAuditEngine On to capture
# audit entries for PASSED samples (the s16-t2 runs audit RelevantOnly, so passes
# are not audited). Never produces a baseline or parity number.
# Evidence: which variables (ARGS/ARGS_NAMES/REQUEST_BODY) the transaction
# populates for text/plain, octet-stream, unknown-ct raw bodies.
set -u
cd /home/Kavinharish/kortexshield
RUN=docs/logs/step17-t1-audit-passed.txt
: > $RUN
echo "# DIAGNOSTIC run (rule 34): engine built with SecAuditEngine On (temporary" >> $RUN
echo "# build in /tmp/kortex-diag; the committed engine keeps RelevantOnly)." >> $RUN
echo "== load average at start:" >> $RUN
uptime >> $RUN

rm -rf /tmp/kortex-diag
rm -f /tmp/kx17diag-audit.log /tmp/kx17diag-events.jsonl
cp -r engine /tmp/kortex-diag
sed -i 's/^SecAuditEngine RelevantOnly$/SecAuditEngine On/' /tmp/kortex-diag/config.go
grep -n "SecAuditEngine" /tmp/kortex-diag/config.go >> $RUN
# diagnostic variable-dump rules (id 9999xx, DIAGNOSTIC ONLY, never committed):
# prove which of ARGS_NAMES / ARGS / REQUEST_BODY the transaction populates
cat > /tmp/kx17dump.py <<'PYEOF'
s = open('/tmp/kortex-diag/config.go').read()
dump = (
    "SecRule &ARGS_POST \"@eq 0\" \"id:999903,phase:2,log,pass,t:none,msg:'DIAG ARGS_POST EMPTY'\"\n"
    "SecRule REQBODY_PROCESSOR \"@streq URLENCODED\" \"id:999908,phase:2,log,pass,t:none,msg:'DIAG RBP=URLENCODED'\"\n"
    "SecRule REQBODY_PROCESSOR \"@streq JSON\" \"id:999909,phase:2,log,pass,t:none,msg:'DIAG RBP=JSON'\"\n"
    "SecRule REQBODY_PROCESSOR \"!@rx ^(URLENCODED|JSON|XML|MULTIPART)$\" \"id:999910,phase:2,log,pass,t:none,msg:'DIAG RBP=OTHER-OR-EMPTY'\"\n"
    "SecRule &ARGS_POST \"@gt 0\" \"id:999905,phase:2,log,pass,t:none,msg:'DIAG ARGS_POST POPULATED'\"\n"
)
s = s.replace('Include %s/owasp-crs/rules/*.conf', dump + 'Include %s/owasp-crs/rules/*.conf')
open('/tmp/kortex-diag/config.go', 'w').write(s)
PYEOF
python3 /tmp/kx17dump.py
grep -n "99990" /tmp/kortex-diag/config.go >> $RUN
export PATH=$PATH:/usr/local/go/bin GOTOOLCHAIN=auto
( cd /tmp/kortex-diag && go build -o /tmp/kortex-diag-engine . ) >> $RUN 2>&1 || { echo BUILD-FAILED >> $RUN; exit 1; }

KORTEX_LISTEN_ADDR=127.0.0.1:8103 \
KORTEX_BACKEND_URL=http://127.0.0.1:13001 \
KORTEX_RULES_DIR=/home/Kavinharish/kortexshield/engine/crs \
KORTEX_EVENTS_FILE=/tmp/kx17diag-events.jsonl \
KORTEX_AUDIT_LOG=/tmp/kx17diag-audit.log \
/tmp/kortex-diag-engine >> /tmp/kx17diag-engine.log 2>&1 &
EPID=$!
# stub backend on 13001 if it is down (compose stack was lost in the redeploy)
curl -s -o /dev/null http://127.0.0.1:13001/ || (cd /tmp && nohup python3 -m http.server 13001 >/tmp/kx17stub.log 2>&1 &)
sleep 1.5
curl -s http://127.0.0.1:8103/__kortex/config >> $RUN

# the payloads the engine passed under the raw-body carriers (T1 analysis):
# sqli-6e47f23b and command-injection-dc2932d5 (PL1), command-injection-ecb32a80 (PL2)
for pid in sqli-0933fb66 sqli-6e47f23b command-injection-dc2932d5 command-injection-ecb32a80; do
  for car in text-plain octet-stream unknown-ct urlencoded; do
    sid="diag-$car-$pid"
    python3 - "$sid" "$car" "$pid" <<'PYEOF' > /tmp/kx17diag-body.bin
import json, sys
sid, car, pid = sys.argv[1], sys.argv[2], sys.argv[3]
man=[json.loads(l) for l in open('data/attacks-ct-v0/manifest.jsonl')]
s=[x for x in man if x['id']==f'actv0-{car}-{pid}'][0]
sys.stdout.buffer.write(s['body'].encode())
open('/tmp/kx17diag-ct.txt','w').write(s['content_type'])
PYEOF
    CT=$(cat /tmp/kx17diag-ct.txt)
    curl -s -o /dev/null -w "replay $sid status=%{http_code}\n" \
      -H "X-Kortex-Sample-Id: $sid" -H "Content-Type: $CT" \
      --data-binary @/tmp/kx17diag-body.bin http://127.0.0.1:8103/ >> $RUN
  done
done
sleep 1
echo "== audit entries for the diag samples (from /tmp/kx17diag-audit.log):" >> $RUN
python3 - >> $RUN <<'PYEOF'
import json, re
for line in open('/tmp/kx17diag-audit.log'):
    if '"transaction"' not in line: continue
    e=json.loads(line)
    t=e['transaction']
    sid=(t['request']['headers'].get('x-kortex-sample-id') or [''])[0]
    if not sid.startswith('diag-'): continue
    print("== sample", sid)
    print("  content-type:", t['request']['headers'].get('content-type'))
    print("  audit request.body:", repr(t['request'].get('body'))[:150])
    for m in e.get('messages',[]):
        em=m.get('error_message','')
        rid=re.search(r'\[id "(\d+)"\]',em)
        data=re.search(r'\[data "([^"]*)"\]',em)
        print(f"  rule {rid.group(1) if rid else '?'}: {data.group(1) if data else '-'}")
PYEOF
kill $EPID 2>/dev/null
echo "ALL-DONE" >> $RUN
