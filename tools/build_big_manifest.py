#!/usr/bin/env python3
"""Step-21 T4: build the derived >16 KB manifest from the frozen datasets
(benign-wcp-v0, benign-wcp-v1; benign-browse-v1 has none). Derived input:
a pure filter of frozen manifests - no sample is edited (rule 10/12).
Usage: build_big_manifest.py <out_manifest.jsonl>
"""
from __future__ import annotations

import json
import sys

DATASETS = ["benign-wcp-v0", "benign-wcp-v1"]
THRESH = 16384


def main() -> int:
    out = sys.argv[1]
    n = 0
    with open(out, "w") as f:
        for ds in DATASETS:
            for line in open(f"data/{ds}/manifest.jsonl"):
                e = json.loads(line)
                b = e.get("body", "")
                size = len(b.encode() if isinstance(b, str) else b)
                if size > THRESH:
                    f.write(json.dumps(e) + "\n")
                    n += 1
    print(f"derived manifest: {n} samples > {THRESH} B")
    return 0


if __name__ == "__main__":
    sys.exit(main())
