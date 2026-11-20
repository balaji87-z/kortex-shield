#!/usr/bin/env python3
"""Step-13 T7 (DIAGNOSTIC): replay wcp-80a49c991b2d with the body truncated to
each size in SIZES (prefix of the recorded body), 3 replays each, 60 s timeout.
Prints: size, per-replay (elapsed_ms, status). No request values."""
import http.client
import sys
import time

sys.path.insert(0, ".")
from kortex_eval.manifest import load as load_samples  # noqa: E402

TARGET = "wcp-80a49c991b2d"
port, label, sizes_path = int(sys.argv[1]), sys.argv[2], sys.argv[3]
sample = next(s for s in load_samples("data/benign-wcp-v0/manifest.jsonl") if s.id == TARGET)
full = sample.body.encode("utf-8", "surrogatepass")
print(f"target {TARGET} method={sample.method} ct_len={len(sample.content_type)} full_body_bytes={len(full)}")

for line in open(sizes_path):
    n = int(line.strip())
    body = full[:n]
    times = []
    for _ in range(3):
        c = http.client.HTTPConnection("localhost", port, timeout=60)
        t0 = time.monotonic()
        try:
            c.request(sample.method, sample.path + (f"?{sample.query}" if sample.query else "/"),
                      body=body, headers={"Content-Type": sample.content_type})
            r = c.getresponse()
            r.read()
            times.append(f"{round((time.monotonic()-t0)*1000)}ms/{r.status}")
        except Exception as e:
            times.append(f"{round((time.monotonic()-t0)*1000)}ms/{e.__class__.__name__}")
        c.close()
    print(f"{label} bytes={n}: {' '.join(times)}")
