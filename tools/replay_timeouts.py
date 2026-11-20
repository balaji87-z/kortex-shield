#!/usr/bin/env python3
"""Step-12 T6: replay the 8 Coraza PL1 timeout samples + the 1 ModSecurity
encoding-error sample, 5x each, against BOTH engines, 60s per-request timeout.
Uses kortex_eval.runner.send_one verbatim (same request-building code as the
recorded runs). Usage: replay_timeouts.py <host> <port> <label> <out-jsonl>
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from kortex_eval.manifest import load as load_samples
from kortex_eval.runner import send_one

IDS = [
    "wcp-00f2f589e97a", "wcp-a5a302eda586", "wcp-86904cff10c3", "wcp-96bd5332ae15",
    "wcp-ffd61414ef24", "wcp-7df6cb91aaf0", "wcp-eeeb13d052ce", "wcp-80a49c991b2d",
    "wcp-6b0bf5e43122",
]
REPEATS = 5


def main():
    host, port, label, out = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]
    samples = {s.id: s for s in load_samples("data/benign-wcp-v0/manifest.jsonl")}
    rows = []
    for sid in IDS:
        s = samples[sid]
        for i in range(REPEATS):
            row = send_one(s, host, port, timeout=60.0, block_status=403,
                           block_marker=None, default_user_agent=None)
            row.update({"engine": label, "repeat": i + 1})
            rows.append(row)
            print(f"{sid} {label} #{i+1}: {row['error'] or row['status']} "
                  f"{row['elapsed_ms']}ms")
    with open(out, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


if __name__ == "__main__":
    main()
