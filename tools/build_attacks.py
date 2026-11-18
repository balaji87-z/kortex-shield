"""Build the attack-corpus candidates from the cloned public payload lists.

For each family, read the chosen plain-list file, remove blank lines, comment
lines (#) and exact duplicates, then take at most --max-per-family payloads by
deterministic sampling (random.Random(0)). Each payload yields two requests:

  (a) GET  /rest/products/search?q=<urllib.parse.quote(payload, safe='')>
  (b) POST /rest/user/login  body=json.dumps({"email": payload, "password": "x"})
      Content-Type: application/json

Sample fields follow the raw-wire convention (README): path/query/body are
sent exactly as stored. id = "<family>-<sha8(payload)>-<q|login>", label
"attack", source "<repo>@<commit>:<file path>:<line number>".

Output: data/attacks-v0/candidates.jsonl (never filtered by reach here).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
import urllib.parse
from pathlib import Path

# family -> (repo name, commit sha, file path relative to the clone)
SOURCES = {
    "sqli": (
        "SecLists",
        "6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9",
        "Fuzzing/Databases/SQLi/quick-SQLi.txt",
    ),
    "xss": (
        "SecLists",
        "6b19c2f5088c45b5dadb4d8918d2ab4f7efb03a9",
        "Fuzzing/XSS/human-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
    ),
    "path-traversal": (
        "PayloadsAllTheThings",
        "08ea40e77db3f42ef8f20c65196f3936a19b6c86",
        "File Inclusion/Intruders/Traversal.txt",
    ),
    "command-injection": (
        "PayloadsAllTheThings",
        "08ea40e77db3f42ef8f20c65196f3936a19b6c86",
        "Command Injection/Intruder/command_exec.txt",
    ),
}
EXTERNAL = Path("data/external")


def load_payloads(path: Path) -> tuple[list[str], dict]:
    """Read one payload per line; drop blanks and #-comments; dedupe exactly.

    Returns (payloads, filter_counts). Line numbers refer to the source file.
    """
    seen: dict[str, int] = {}
    payloads: list[str] = []
    counts = {"raw_lines": 0, "blank_removed": 0, "comment_removed": 0, "duplicates_removed": 0}
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            counts["raw_lines"] += 1
            line = raw.rstrip("\n")
            if not line.strip():
                counts["blank_removed"] += 1
                continue
            if line.lstrip().startswith("#"):
                counts["comment_removed"] += 1
                continue
            if line in seen:
                counts["duplicates_removed"] += 1
                continue
            seen[line] = lineno
            payloads.append(line)
    return payloads, counts


def first_line_number(path: Path, payload: str) -> int:
    with open(path, encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            if raw.rstrip("\n") == payload:
                return lineno
    raise ValueError(f"payload not found in source: {payload!r}")


def build(external_dir: Path, max_per_family: int, seed: int) -> list[dict]:
    samples: list[dict] = []
    stats: dict[str, dict] = {}
    rng = random.Random(seed)
    for family, (repo, commit, relpath) in SOURCES.items():
        src = external_dir / repo / relpath
        payloads, counts = load_payloads(src)
        after_filters = len(payloads)
        if after_filters > max_per_family:
            chosen = sorted(rng.sample(payloads, max_per_family))
        else:
            chosen = payloads
        stats[family] = {
            "source": f"{repo}@{commit}:{relpath}",
            **counts,
            "after_filters": after_filters,
            "sampled": len(chosen),
        }
        print(f"{family}: raw={counts['raw_lines']} blank={counts['blank_removed']} "
              f"comment={counts['comment_removed']} dup={counts['duplicates_removed']} "
              f"-> {after_filters} -> sampled {len(chosen)}", file=sys.stderr)
        for payload in chosen:
            lineno = first_line_number(src, payload)
            sha8 = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]
            source = f"{repo}@{commit}:{relpath}:{lineno}"
            # (a) GET search, query percent-encoded with safe='' (every special char encoded)
            samples.append({
                "id": f"{family}-{sha8}-q",
                "label": "attack",
                "family": family,
                "source": source,
                "method": "GET",
                "path": "/rest/products/search",
                "query": "q=" + urllib.parse.quote(payload, safe=""),
                "body": "",
                "content_type": "",
            })
            # (b) POST login with JSON body built by json.dumps
            samples.append({
                "id": f"{family}-{sha8}-login",
                "label": "attack",
                "family": family,
                "source": source,
                "method": "POST",
                "path": "/rest/user/login",
                "query": "",
                "body": json.dumps({"email": payload, "password": "x"}),
                "content_type": "application/json",
            })
    build.stats = stats  # type: ignore[attr-defined]
    return samples


def main() -> int:
    ap = argparse.ArgumentParser(description="Build attack-corpus candidates from public payload lists.")
    ap.add_argument("--out", default="data/attacks-v0/candidates.jsonl")
    ap.add_argument("--max-per-family", type=int, default=150)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--external-dir", default=str(EXTERNAL))
    args = ap.parse_args()

    samples = build(Path(args.external_dir), args.max_per_family, args.seed)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        for s in samples:
            fh.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"wrote {len(samples)} candidate samples -> {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
