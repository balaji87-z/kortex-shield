"""Cluster-aware benign reporting (step-05 T5).

Endpoint classes are DEFINED HERE, BEFORE any analysis is run on the data:

- static:   path starts with "/assets/" OR the path's last segment has one of
            the fixed extensions: .js .css .map .woff .woff2 .ttf .png .jpg
            .jpeg .gif .svg .ico .avif .webp .txt .md
- socket.io: path starts with "/socket.io"
- API:      path starts with "/api/" or "/rest/"
- other:    everything else (checked in this order: static, socket.io, API,
            other)

Reports, per class: sample count, distinct endpoint count, blocked count and
FP rate with 95% Wilson interval; then per-endpoint rates for classes with
blocks; then (for hard benign) distinct injection VALUES and how many were
blocked, in addition to the request count.

Known limitation (recorded in step-05): the browse samples' `source` field
does NOT contain a session number (the recorder wrote one source string for
all samples), so the fraction of sessions with >=1 blocked request cannot be
computed from the frozen data. The tool prints n/a for it on browse data.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

STATIC_PREFIX = "/assets/"
STATIC_EXTENSIONS = (".js", ".css", ".map", ".woff", ".woff2", ".ttf", ".png",
                     ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".avif", ".webp",
                     ".txt", ".md")


def classify(path: str) -> str:
    last = path.rsplit("/", 1)[-1].lower()
    if path.startswith(STATIC_PREFIX) or last.endswith(STATIC_EXTENSIONS):
        return "static"
    if path.startswith("/socket.io"):
        return "socket.io"
    if path.startswith("/api/") or path.startswith("/rest/"):
        return "API"
    return "other"


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple:
    if n == 0:
        return (None, None, None)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5
    return (p, (c - a) / d, (c + a) / d)


def pct(x) -> str:
    return "n/a" if x is None else f"{100 * x:.2f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description="Cluster-aware benign FP report.")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--annotations", required=True)
    ap.add_argument("--outcomes", required=True)
    ap.add_argument("--dataset", choices=("browse", "hard"), default="browse")
    args = ap.parse_args()

    manifest = {json.loads(l)["id"]: json.loads(l)
                for l in open(args.manifest, encoding="utf-8") if l.strip()}
    annotations = {json.loads(l)["id"]: json.loads(l)["endpoint"]
                   for l in open(args.annotations, encoding="utf-8") if l.strip()}
    outcomes = {json.loads(l)["id"]: json.loads(l)
                for l in open(args.outcomes, encoding="utf-8") if l.strip()}

    cls_of = {sid: classify(s["path"]) for sid, s in manifest.items()}
    total = collections.Counter(cls_of.values())
    blocked = {sid for sid, r in outcomes.items() if r["outcome"] == "waf_block"}
    blocked_cls = collections.Counter(cls_of[sid] for sid in blocked)

    # composition
    ep_by_cls = collections.defaultdict(set)
    for sid, ep in annotations.items():
        ep_by_cls[cls_of[sid]].add(ep)
    print("## Composition (class defined in tools/benign_clusters.py before analysis)\n")
    print("| class | samples | distinct endpoints | blocked | FP rate | 95% Wilson |")
    print("|---|---|---|---|---|---|")
    for cls in ("static", "socket.io", "API", "other"):
        n = total[cls]
        k = blocked_cls.get(cls, 0)
        p, lo, hi = wilson(k, n)
        print(f"| {cls} | {n} | {len(ep_by_cls[cls])} | {k} | {pct(p)} | {pct(lo)}–{pct(hi)} |")
    n_all = len(manifest)
    p, lo, hi = wilson(len(blocked), n_all)
    print(f"| **all** | {n_all} | {len(set(annotations.values()))} | {len(blocked)} | {pct(p)} | {pct(lo)}–{pct(hi)} |")

    # per-endpoint rate inside classes with blocks
    print("\n## Per-endpoint FP rate (classes with at least one block)\n")
    ep_total = collections.Counter(annotations.values())
    ep_blocked = collections.Counter(annotations[sid] for sid in blocked)
    for cls in ("static", "socket.io", "API", "other"):
        eps = [e for e in ep_by_cls[cls] if ep_blocked.get(e, 0) > 0]
        if not eps:
            continue
        print(f"### {cls}\n")
        print("| endpoint | blocked/samples | FP rate | 95% Wilson |")
        print("|---|---|---|---|")
        for e in sorted(eps, key=lambda e: (-ep_blocked[e], e)):
            k = ep_blocked[e]
            p, lo, hi = wilson(k, ep_total[e])
            print(f"| {e} | {k}/{ep_total[e]} | {pct(p)} | {pct(lo)}–{pct(hi)} |")
        print()

    # session fraction (browse only; unverifiable, see module docstring)
    if args.dataset == "browse":
        src = next(iter(manifest.values())).get("source", "")
        has_session = "session-" in src
        print("## Fraction of sessions with >=1 blocked request\n")
        if has_session:
            sess = collections.defaultdict(list)
            for sid, s in manifest.items():
                tag = s["source"].split("session-")[-1]
                sess[tag].append(sid)
            with_block = sum(1 for v in sess.values() if any(sid in blocked for sid in v))
            print(f"{with_block}/{len(sess)} sessions had at least one blocked request")
        else:
            print("n/a — the frozen samples' `source` field does not contain a "
                  "session number (recorder wrote one source string for all "
                  "samples); cannot be computed from the frozen data. Recorded "
                  "as a step-05 deviation.")

    # hard benign: distinct injection values
    if args.dataset == "hard":
        values = collections.defaultdict(list)
        for sid, s in manifest.items():
            # id format: hardben-<sha8>-q | hardben-<sha8>-login
            sha = sid.split("-")[1]
            values[sha].append(sid)
        blocked_vals = [sha for sha, sids in values.items()
                        if any(sid in blocked for sid in sids)]
        print("\n## Distinct injection values (hard benign)\n")
        print(f"- distinct values: {len(values)}")
        print(f"- values with at least one blocked request: {len(blocked_vals)} "
              f"({pct(wilson(len(blocked_vals), len(values))[0])})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
