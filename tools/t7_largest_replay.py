#!/usr/bin/env python3
"""Step-13 T7 (DIAGNOSTIC): replay the 20 largest-body WCP samples once each
(60 s timeout), print id, encoded size, elapsed, status. No request values."""
import http.client
import sys
import time

sys.path.insert(0, ".")
from kortex_eval.manifest import load as load_samples  # noqa: E402

port, label = int(sys.argv[1]), sys.argv[2]
samples = sorted(load_samples("data/benign-wcp-v0/manifest.jsonl"),
                 key=lambda s: len(s.body.encode("utf-8", "surrogatepass")) if s.body else 0,
                 reverse=True)[:20]
for s in samples:
    body = s.body.encode("utf-8", "surrogatepass") if s.body else None
    c = http.client.HTTPConnection("localhost", port, timeout=60)
    t0 = time.monotonic()
    try:
        h = dict(s.headers)
        h.pop("Host", None)
        h.pop("host", None)
        if s.content_type:
            h.setdefault("Content-Type", s.content_type)
        c.request(s.method, s.path + (f"?{s.query}" if s.query else "/"), body=body, headers=h)
        r = c.getresponse()
        r.read()
        print(f"{label} {s.id} bytes={len(body) if body else 0} {round((time.monotonic()-t0)*1000)}ms {r.status}")
    except Exception as e:
        print(f"{label} {s.id} bytes={len(body) if body else 0} {round((time.monotonic()-t0)*1000)}ms {e.__class__.__name__}")
    c.close()
