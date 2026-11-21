#!/usr/bin/env python3
"""Step-20 T1: duplicate-argument bypass measurement (docs/plan-dup-args.md).
Sends the preregistered 40 payloads x 8 shapes x 20 repeats against one
endpoint and reports passes-out-of-20 per shape class, per PL handled by the
caller (the engine is started by the caller with the right PL)."""
import json, random, sys, time
import http.client
from urllib.parse import quote

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36")
REPEATS = 20


def load_payloads():
    # preregistered seed-0 pick, committed with the results (rule 23)
    pick = json.load(open("docs/logs/runs/s20-t1-dupargs/pick.json"))
    byid = {}
    for l in open("data/attacks-v0/manifest.jsonl"):
        e = json.loads(l)
        if e["id"] in {i for v in pick.values() for i in v}:
            byid[e["id"]] = e
    out = []
    for fam in sorted(pick):
        for sid in pick[fam]:
            out.append(byid[sid])
    return out


def variants(s):
    Q = s["query"]
    E = quote(Q, safe="")
    path = s["path"]
    q = [
        ("Q1", "GET", path, Q, None),
        ("Q2", "GET", path, Q + "&" + Q, None),
        ("Q3", "GET", path, "q=benign&" + Q, None),
        ("Q4", "GET", path, Q + "&q=benign", None),
    ]
    b = [
        ("B1", "POST", path, None, "p=" + E),
        ("B2", "POST", path, None, "p=" + E + "&p=" + E),
        ("B3", "POST", path, None, "p=benign&p=" + E),
        ("B4", "POST", path, None, "p=" + E + "&p=benign"),
    ]
    return q + b


def send(host, port, method, target, body, sid, timeout=30):
    h = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {"Accept-Encoding": "identity", "User-Agent": UA,
               "X-Kortex-Sample-Id": sid}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Content-Length"] = str(len(body))
    h.request(method, target, body=body, headers=headers)
    r = h.getresponse()
    data = r.read()
    h.close()
    return r.status, data


def main():
    host, port, block_status, marker, out_path = sys.argv[1:6]
    block_status = int(block_status)
    payloads = load_payloads()
    rows = []
    t0 = time.monotonic()
    for s in payloads:
        for shape, method, path, query, body in variants(s):
            target = path + ("?" + query if query else "")
            passes = 0
            errors = 0
            statuses = {}
            for n in range(REPEATS):
                sid = f"{s['id']}-{shape}-{n}"
                try:
                    st, data = send(host, int(port), method, target, body, sid)
                except Exception as ex:
                    st = -1
                statuses[st] = statuses.get(st, 0) + 1
                if st == -1:
                    errors += 1
                elif st != block_status:
                    passes += 1
            rows.append({"id": s["id"], "family": s["family"], "shape": shape,
                         "passes": passes, "errors": errors, "repeats": REPEATS,
                         "statuses": statuses})
    dur = time.monotonic() - t0
    json.dump(rows, open(out_path, "w"), indent=1)
    # summary per shape
    agg = {}
    for r in rows:
        a = agg.setdefault(r["shape"], {"passes": 0, "reps": 0, "ids": 0, "errors": 0})
        a["passes"] += r["passes"]; a["reps"] += r["repeats"]; a["ids"] += 1
        a["errors"] += r.get("errors", 0)
    print(f"duration {dur:.0f}s, {len(rows)} variants x {REPEATS}")
    for shp in ("Q1", "Q2", "Q3", "Q4", "B1", "B2", "B3", "B4"):
        a = agg[shp]
        print(f"{shp}: passes {a['passes']}/{a['reps']} errors {a['errors']} "
              f"(variants with >=1 pass: {sum(1 for r in rows if r['shape']==shp and r['passes']>0)}/{a['ids']})")


if __name__ == "__main__":
    main()
