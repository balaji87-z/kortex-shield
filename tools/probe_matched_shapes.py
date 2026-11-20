#!/usr/bin/env python3
"""Step-12 T3: differential probes built from the only-Coraza match shapes.

PROBE TABLE (fixed before any send; 20 probes as instructed). All probes are
synthetic; none reuse recorded sample values (rule 25). Shapes come from the
step-12 T3 match-shape analysis: the only-Coraza matches sit on ARGS_NAMES /
ARGS whose names or values contain raw high bytes / binary, matched by short
binary or shell-meta sequences. Each probe sends EXACT raw bytes over a raw
socket so no client library re-encodes anything. Every probe carries a unique
path marker /probe-pNN so its audit entry (if any) can be attributed by URI.

 id  method target            request shape                                   family probed
 --  ------ ------            -----------------------------------------------  --------------------
 P01 GET  /probe-p01?a%00b=c  NUL (pct) in arg NAME                          ARGS_NAMES handling
 P02 GET  /probe-p02?%86ab=c  high byte (pct) in NAME                        ARGS_NAMES handling
 P03 GET  /probe-p03?a=%86bc  high byte in VALUE                             ARGS value
 P04 GET  /probe-p04?a=%c0%80 overlong NUL encoding                          UTF-8 validation
 P05 GET  /probe-p05?a=%ed%a0%80 UTF-16 surrogate (CESU-8)                   UTF-8 validation
 P06 GET  /probe-p06?a=%fe%fe invalid UTF-8 pair                             UTF-8 validation
 P07 GET  /probe-p07?a=<0xFF> raw 0xFF byte in line                          line/arg handling
 P08 GET  /probe-p08?a%60b=c  backtick (pct) in NAME                         932370 shape
 P09 GET  /probe-p09?a=%7B%20url=b "{ url" shape in value                    932370 shape
 P10 GET  /probe-p10?a=b%00c  NUL inside value                               ARGS value
 P11 GET  /probe-p11?%00=x    NUL as full NAME                               ARGS_NAMES handling
 P12 GET  /probe-p12?a=%uFFFD %u escape                                      920 decoding
 P13 GET  /probe-p13?a=%c8%a9 valid 2-byte UTF-8                             control probe
 P14 GET  /probe-p14?a=b c    raw space in request line                      line handling
 P15 POST /probe-p15          JSON, KEY has lone-surrogate escape \ud800     ARGS_NAMES from JSON
 P16 POST /probe-p16          JSON, VALUE has lone-surrogate \udc80          ARGS from JSON
 P17 POST /probe-p17          JSON, KEY has \ufffd (valid UTF-8)             ARGS_NAMES from JSON
 P18 POST /probe-p18          form-urlencoded name=%86abc value=%fedc        ARGS from URLENCODED
 P19 POST /probe-p19          JSON, 1200 members (valid; 200007 @ge 1000)    200007 argument limit
 P20 GET  /probe-p20?a=b      plain control probe                            (no match expected)

For each probe both engines answer the SAME bytes; we record HTTP status.
Rule IDs per probe are extracted afterwards from each engine's audit log by
the probe-pNN marker (tools/probe_rule_extract.py). Neither engine is called
correct or incorrect (AGENTS rule 4): disagreements are listed, not judged.

Usage: probe_matched_shapes.py <host> <port> <engine-label> <out-prefix>
"""
import json
import socket
import sys
import time

HOST_HEADER = "localhost"

JSON_LONE_KEY = '{"a\\ud800b": "x"}'
JSON_LONE_VAL = '{"k": "v\\udc80w"}'
JSON_REPL_KEY = '{"a\ufffdb": "x"}'


def P(n):
    return f"/probe-p{n}".encode()


PROBES = [
    ("P01", "GET", P(1) + b"?a%00b=c", None, None),
    ("P02", "GET", P(2) + b"?%86ab=c", None, None),
    ("P03", "GET", P(3) + b"?a=%86bc", None, None),
    ("P04", "GET", P(4) + b"?a=%c0%80", None, None),
    ("P05", "GET", P(5) + b"?a=%ed%a0%80", None, None),
    ("P06", "GET", P(6) + b"?a=%fe%fe", None, None),
    ("P07", "GET", P(7) + b"?a=\xff", None, None),
    ("P08", "GET", P(8) + b"?a%60b=c", None, None),
    ("P09", "GET", P(9) + b"?a=%7B%20url=b", None, None),
    ("P10", "GET", P(10) + b"?a=b%00c", None, None),
    ("P11", "GET", P(11) + b"?%00=x", None, None),
    ("P12", "GET", P(12) + b"?a=%uFFFD", None, None),
    ("P13", "GET", P(13) + b"?a=%c8%a9", None, None),
    ("P14", "GET", P(14) + b"?a=b c", None, None),
    ("P15", "POST", P(15), JSON_LONE_KEY.encode("utf-8", "surrogatepass"), b"application/json"),
    ("P16", "POST", P(16), JSON_LONE_VAL.encode("utf-8", "surrogatepass"), b"application/json"),
    ("P17", "POST", P(17), JSON_REPL_KEY.encode("utf-8"), b"application/json"),
    ("P18", "POST", P(18), b"%86abc=%fedc", b"application/x-www-form-urlencoded"),
    ("P19", "POST", P(19), json.dumps({f"k{i}": 0 for i in range(1200)}).encode(), b"application/json"),
    ("P20", "GET", P(20) + b"?a=b", None, None),
]


def build_request(method, target, body, ct):
    if method == "GET":
        return (b"GET " + target + b" HTTP/1.1\r\nHost: " + HOST_HEADER.encode() +
                b"\r\nUser-Agent: probe\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
    return (b"POST " + target + b" HTTP/1.1\r\nHost: " + HOST_HEADER.encode() +
            b"\r\nContent-Type: " + ct +
            b"\r\nContent-Length: " + str(len(body)).encode() +
            b"\r\nUser-Agent: probe\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n" + body)


def send(host, port, req, timeout=15):
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(req)
    data = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    s.close()
    head = data.split(b"\r\n\r\n", 1)[0]
    return int(head.split(b" ")[1]) if b" " in head else None


def main():
    host, port, label, out_prefix = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    rows = []
    for pid, method, target, body, ct in PROBES:
        req = build_request(method, target, body, ct)
        t0 = time.monotonic()
        try:
            status = send(host, port, req)
            err = None
        except Exception as e:
            status, err = None, f"{type(e).__name__}: {e}"
        elapsed = round((time.monotonic() - t0) * 1000, 1)
        rows.append({"probe": pid, "engine": label, "status": status, "error": err,
                     "elapsed_ms": elapsed})
        print(f"{pid} {label} status={status} err={err}")
    with open(out_prefix + f"-{label}.jsonl", "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()
