#!/usr/bin/env python3
"""Step-22 T5a: padding matrix extension (k=8, 32, 120000 bytes).

Same design as step-21 T1a (XSS + SQLi canaries, payload before/after
padding, 3 content types, 3 reps) but with the new k values. 120000 B of
padding keeps the total below KORTEX_MAX_INSPECTED_BYTES (131072).

Usage: run_step22_t5_padding.py --engine URL --out FILE
Writes one JSON line per request: {cell..., status, rule_ids}.
"""
import argparse, json, random, sys, time, urllib.parse, urllib.request

XSS = '"><script>alert(1)</script>'
SQLI = 'admin" or "1"="1"#'

def padding_text(n, seed=7):
    rnd = random.Random(seed)
    words = ("order shipping invoice customer basket checkout catalogue nature "
             "meadow river stone forest harvest weather morning library window "
             "garden market recipe journey blanket compass lantern).split")
    words = words.replace(").split", "").split()
    out = []
    while sum(len(w) + 1 for w in out) < n:
        out.append(rnd.choice(words))
    s = " ".join(out)
    return s[:n]

def make_body(payload, k, pos, ct):
    pad = padding_text(k)
    if ct == "text/plain":
        return (pad + payload) if pos == "before" else (payload + pad)
    if ct == "urlencoded":
        if pos == "before":
            q = "q=" + urllib.parse.quote(pad + payload, safe="")
        else:
            q = "q=" + urllib.parse.quote(payload + pad, safe="")
        return q
    if ct == "json":
        val = (pad + payload) if pos == "before" else (payload + pad)
        return json.dumps({"note": val})
    raise ValueError(ct)

def send(url, body, ct, sample_id, pl, timeout=60):
    req = urllib.request.Request(url + "/", data=body.encode(), method="POST")
    req.add_header("Content-Type", ct)
    req.add_header("X-Kortex-Sample-Id", sample_id)
    t0 = time.time()
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        status, text = r.status, r.read(200).decode(errors="replace")
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read(200).decode(errors="replace")
    except Exception as e:
        return {"status": None, "error": str(e)[:120], "elapsed_ms": int((time.time()-t0)*1000)}
    return {"status": status, "elapsed_ms": int((time.time()-t0)*1000),
            "resp_head": text[:120]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--reps", type=int, default=3)
    args = ap.parse_args()
    rows = []
    for pl in (1, 2):
        # paranoia via headers is not possible; PL is engine-side config.
        # The caller runs the script once per PL against a PL-configured engine.
        for k in (8192, 32768, 120000):
            for payload_name, payload in (("xss", XSS), ("sqli", SQLI)):
                for pos in ("before", "after"):
                    for ct in ("text/plain", "application/x-www-form-urlencoded", "application/json"):
                        body = make_body(payload, k, pos, ct)
                        assert len(body) < 131072, (k, len(body))
                        for rep in range(1, args.reps + 1):
                            sid = f"t5a-pl{pl}-k{k}-{payload_name}-{pos}-{ct.split('/')[0].replace('x-www-form-urlencoded','url')}-r{rep}"
                            r = send(args.engine, body, ct, sid, pl)
                            r.update({"id": sid, "k": k, "payload": payload_name,
                                      "pos": pos, "ct": ct, "pl": pl, "rep": rep})
                            rows.append(r)
                            print(json.dumps(r), flush=True)
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    n = len(rows)
    blocked = sum(1 for r in rows if r["status"] == 403)
    passed = sum(1 for r in rows if r["status"] == 200)
    failclosed = sum(1 for r in rows if r["status"] in (400, 413, 503))
    other = n - blocked - passed - failclosed
    print(f"TOTAL {n} blocked403={blocked} passed200={passed} failclosed(400/413/503)={failclosed} other={other}", file=sys.stderr)

if __name__ == "__main__":
    main()
