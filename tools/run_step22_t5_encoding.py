#!/usr/bin/env python3
"""Step-22 T5b: Content-Encoding and Transfer-Encoding evasion probes.

Cells (per payload XSS/SQLi):
  A. body gzipped, Content-Encoding: gzip present, 3 CTs
  B. body zlib-deflated, Content-Encoding: deflate present, 3 CTs
  C. body gzipped, NO Content-Encoding header (control: engine should see
     gzip bytes and the backend too)
  D. raw body, no CE (control: detection must fire)
  E. Transfer-Encoding: chunked, raw body with the payload split across a
     chunk boundary (two split offsets)
Engine + connector, PL1. Status and rule ids per cell.

Usage: run_step22_t5_encoding.py --engine URL --out FILE
"""
import argparse, gzip, json, sys, time, urllib.parse, urllib.request, zlib, http.client
from urllib.parse import urlsplit

XSS = '"><script>alert(1)</script>'
SQLI = 'admin" or "1"="1"#'

def make_raw(payload, ct):
    if ct == "text/plain":
        return "note " + payload
    if ct in ("urlencoded", "application/x-www-form-urlencoded"):
        return "q=" + urllib.parse.quote(payload, safe="")
    if ct in ("json", "application/json"):
        return json.dumps({"note": payload})
    raise ValueError(ct)

def chunked_send(host_port, path, body_bytes, headers, sample_id, chunk_size=7, timeout=30):
    """Send a request with a hand-rolled chunked body."""
    c = http.client.HTTPConnection(host_port, timeout=timeout)
    try:
        # skip_host: http.client adds its own Host header; a second one makes
        # the Go server answer 400 and close, which the client sees as a reset.
        c.putrequest("POST", path, skip_host=True, skip_accept_encoding=True)
        c.putheader("Host", host_port)
        c.putheader("Content-Type", headers.get("Content-Type", "text/plain"))
        c.putheader("Transfer-Encoding", "chunked")
        c.putheader("X-Kortex-Sample-Id", sample_id)
        c.endheaders()
        for i in range(0, len(body_bytes), chunk_size):
            chunk = body_bytes[i:i+chunk_size]
            c.send(("%x\r\n" % len(chunk)).encode() + chunk + b"\r\n")
        c.send(b"0\r\n\r\n")
        r = c.getresponse()
        status, text = r.status, r.read(200).decode(errors="replace")
        return {"status": status, "resp_head": text[:120]}
    except Exception as e:
        return {"status": None, "error": str(e)[:120]}
    finally:
        c.close()

def normal_send(url, body_bytes, headers, sample_id, timeout=30):
    req = urllib.request.Request(url + "/", data=body_bytes, method="POST")
    for k, v in headers.items():
        req.add_header(k, v)
    req.add_header("X-Kortex-Sample-Id", sample_id)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return {"status": r.status, "resp_head": r.read(200).decode(errors="replace")[:120]}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "resp_head": e.read(200).decode(errors="replace")[:120]}
    except Exception as e:
        return {"status": None, "error": str(e)[:120]}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--engine", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    u = urlsplit(args.engine)
    base = u.netloc
    rows = []
    def rec(cell, payload_name, ct, variant, r, sample_id, note=""):
        r.update({"id": sample_id, "cell": cell, "payload": payload_name, "ct": ct,
                  "variant": variant, "note": note})
        rows.append(r)
        print(json.dumps(r), flush=True)
    for pname, payload in (("xss", XSS), ("sqli", SQLI)):
        for ct in ("text/plain", "application/x-www-form-urlencoded", "application/json"):
            raw = make_raw(payload, ct).encode()
            gz = gzip.compress(raw)
            df = zlib.compress(raw)
            short = {"text/plain": "plain", "application/x-www-form-urlencoded": "url", "application/json": "json"}[ct]
            sid = f"t5b-{pname}-{short}"
            # A: gzip + header
            rec("A", pname, ct, "gzip+header",
                normal_send(args.engine, gz, {"Content-Type": ct, "Content-Encoding": "gzip"}, sid + "-A"), sid + "-A")
            # B: deflate + header
            rec("B", pname, ct, "deflate+header",
                normal_send(args.engine, df, {"Content-Type": ct, "Content-Encoding": "deflate"}, sid + "-B"), sid + "-B")
            # C: gzip, no header
            rec("C", pname, ct, "gzip-noheader",
                normal_send(args.engine, gz, {"Content-Type": ct}, sid + "-C"), sid + "-C")
            # D: raw control
            rec("D", pname, ct, "raw",
                normal_send(args.engine, raw, {"Content-Type": ct}, sid + "-D"), sid + "-D")
            # E: chunked, payload split across chunk boundary (2 offsets)
            for off in (4, 9):
                # split point inside the payload string
                s = make_raw(payload, ct)
                idx = s.find(payload) + off
                b = s.encode()
                # rebuild body so the chunk boundary falls at idx
                first, second = b[:idx], b[idx:]
                chunked_body = first + second  # boundary handled by chunking below
                r = chunked_send(base, "/", chunked_body, {"Content-Type": ct},
                                 sid + f"-E{off}", chunk_size=max(1, idx))
                rec("E", pname, ct, f"chunked-split@{off}", r, sid + f"-E{off}")
    with open(args.out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    from collections import Counter
    print("STATUS COUNTS:", Counter(r["status"] for r in rows), file=sys.stderr)

if __name__ == "__main__":
    main()
