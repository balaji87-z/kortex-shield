#!/usr/bin/env python3
"""Step-14 T1b (DIAGNOSTIC): replay the step-13 Coraza timeout/error samples
3 times on each engine with a 60 s timeout, using the runner's own send_one
so header handling matches the full runs. Prints id, elapsed, status only."""
import re
import sys

sys.path.insert(0, ".")
from kortex_eval.manifest import load as load_samples  # noqa: E402
from kortex_eval.runner import send_one, DEFAULT_BLOCK_MARKER  # noqa: E402

BLOCK_MARKER = re.compile(DEFAULT_BLOCK_MARKER)

IDS = [
    "wcp-00f2f589e97a", "wcp-96bd5332ae15", "wcp-50071536f159",
    "wcp-ab265f963540", "wcp-7df6cb91aaf0", "wcp-80a49c991b2d",
    "wcp-0bdd37cedc4b", "wcp-eeeb13d052ce", "wcp-6b0bf5e43122",
]
PORTS = {"modsec": 8081, "coraza": 8082}
samples = {s.id: s for s in load_samples("data/benign-wcp-v0/manifest.jsonl")}
engine = sys.argv[1] if len(sys.argv) > 1 else None
for sid in IDS:
    s = samples[sid]
    body = s.body or ""
    b = body.encode("utf-8", "surrogatepass")
    ct = (s.content_type or "<none>").split(";")[0]
    for eng, port in PORTS.items():
        if engine and eng != engine:
            continue
        res = []
        for _ in range(3):
            try:
                r = send_one(s, "localhost", port, timeout=60,
                             block_status=403, block_marker=BLOCK_MARKER)
                res.append((r["elapsed_ms"], r["status"]))
            except Exception as e:  # noqa: BLE001
                res.append(("ERR", e.__class__.__name__))
        print(f"{sid} ct={ct} bytes={len(b)} {eng}: {res}")
