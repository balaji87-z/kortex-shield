#!/usr/bin/env python3
"""Step-27 DIAGNOSTIC: a few hand-written requests of the parsing differential,
sent as raw bytes to one WAF on localhost (rule 6), status per request.

The requests are those of tools/step27_parsing_diff.py: the XML control and
the XML attribute case (plus the same pair with an SQL injection payload),
and the overlong path traversal as raw bytes and percent-encoded.

Usage: step27_reference_probe.py PORT LABEL
       step27_reference_probe.py --audit-ids < AUDIT_LOG   (rule ids per case)
"""
import socket
import sys

CANARY_XML = "&lt;script&gt;alert(1)&lt;/script&gt;"
SQLI = "1' UNION SELECT password FROM users-- "


def post(cid, body):
    b = body.encode()
    return (f"POST /body HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: {cid}\r\n"
            f"Content-Type: application/xml\r\nContent-Length: {len(b)}\r\nConnection: close\r\n\r\n").encode() + b


def get(cid, target):
    return b"GET " + target + f" HTTP/1.1\r\nHost: localhost\r\nX-Kortex-Sample-Id: {cid}\r\nConnection: close\r\n\r\n".encode()


CASES = [
    ("xml-control", "the canary as element text", post("xml-control", f"<r><q>{CANARY_XML}</q></r>")),
    ("xml-attr", "the canary as an attribute value", post("xml-attr", f'<r q="{CANARY_XML}"/>')),
    ("xml-sqli-control", "an SQL injection payload as element text", post("xml-sqli-control", f"<r><q>{SQLI}</q></r>")),
    ("xml-sqli-attr", "the same payload as an attribute value", post("xml-sqli-attr", f'<r q="{SQLI}"/>')),
    ("ovl-path-pct", "path traversal with %C0%AF", get("ovl-path-pct", b"/static/..%C0%AF..%C0%AFetc/passwd")),
    ("ovl-path-raw", "path traversal with raw bytes C0 AF", get("ovl-path-raw", b"/static/..\xc0\xaf..\xc0\xafetc/passwd")),
]


def send(port, raw):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(raw)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    line = data.split(b"\r\n", 1)[0].decode("latin-1")
    parts = line.split(" ")
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None


def audit_ids(stream):
    """Rule ids per sample id from JSON audit lines (ModSecurity or coraza form)."""
    import json
    import re
    out = {}
    for line in stream:
        line = line.strip()
        if not line.startswith('{"transaction"'):
            continue
        try:
            tx = json.loads(line)
        except ValueError:
            continue
        t = tx["transaction"]
        headers = {k.lower(): v for k, v in (t.get("request", {}).get("headers") or {}).items()}
        sid = headers.get("x-kortex-sample-id")
        sid = sid[0] if isinstance(sid, list) else sid
        if not sid:
            continue
        ids = set()
        for m in (t.get("messages") or []) + (tx.get("messages") or []):
            rid = (m.get("details") or {}).get("ruleId")
            if rid:
                ids.add(int(rid))
            ids.update(int(i) for i in re.findall(r'\[id "(\d+)"\]', m.get("error_message") or ""))
        out.setdefault(sid, set()).update(i for i in ids if i >= 900000 and i % 1000 > 20 and i // 1000 not in (900, 901, 949, 980))
    return out


def main(argv):
    if argv[1] == "--audit-ids":
        got = audit_ids(sys.stdin)
        for cid, _, _ in CASES:
            ids = got.get(cid)
            print(f"      {cid}: " + ("no audit entry" if ids is None else ", ".join(map(str, sorted(ids))) or "none"))
        return 0
    port, label = int(argv[1]), argv[2]
    for cid, note, raw in CASES:
        try:
            status = send(port, raw)
        except OSError as e:
            status = f"error {type(e).__name__}"
        print(f"   {label} {cid}: {status}   ({note})")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
