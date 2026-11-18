"""Breakdown of benign-corpus baseline results: false positive rates.

Per-request FP rate, per-distinct-endpoint FP rate, and the list of blocked
endpoints with the CRS rule IDs that fired, with 95% Wilson intervals.

Inputs: frozen manifest, annotations file (endpoint per sample), audit.jsonl
from the run, and the run's outcomes.jsonl (engine-mode blocking).
Rule 14: never merge natural (benign-browse) and hard (benign-hard) rates —
run this tool once per dataset and report the numbers separately.
"""
from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float, float]:
    if n == 0:
        return (None, None, None)
    p = k / n
    denom = 1 + z * z / n
    centre = p + z * z / (2 * n)
    adj = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5
    return (p, (centre - adj) / denom, (centre + adj) / denom)


def pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.2f}%"


def row(name: str, k: int, n: int) -> str:
    p, lo, hi = wilson(k, n)
    return f"| {name} | {k}/{n} | {pct(p)} | {pct(lo)} – {pct(hi)} |"


def main() -> int:
    ap = argparse.ArgumentParser(description="Break down benign-corpus baseline results.")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--annotations", required=True)
    ap.add_argument("--audit", required=True)
    ap.add_argument("--outcomes", required=True)
    args = ap.parse_args()

    manifest = {json.loads(l)["id"]: json.loads(l)
                for l in open(args.manifest, encoding="utf-8") if l.strip()}
    annotations = {json.loads(l)["id"]: json.loads(l)["endpoint"]
                   for l in open(args.annotations, encoding="utf-8") if l.strip()}
    audit = {}
    for line in open(args.audit, encoding="utf-8"):
        if not line.strip():
            continue
        e = json.loads(line)
        sid = e.get("sample_id")
        if sid:
            audit.setdefault(sid, []).append(e)
    outcomes = {json.loads(l)["id"]: json.loads(l)
                for l in open(args.outcomes, encoding="utf-8") if l.strip()}

    # ---- per-request FP rate (unstratified, first) ----
    blocked = [sid for sid in manifest if outcomes[sid]["outcome"] == "waf_block"]
    n = len(manifest)
    print(f"## Per-request false positive rate\n")
    print(row("blocked (FP)", len(blocked), n))
    print()

    # ---- per-distinct-endpoint rate ----
    print("## Per-endpoint false positive rate (distinct endpoints)\n")
    ep_total: dict[str, int] = collections.Counter(annotations.values())
    ep_blocked: dict[str, int] = collections.Counter(
        annotations[sid] for sid in blocked)
    print("| endpoint | blocked/samples | FP rate | 95% Wilson |")
    print("|---|---|---|---|")
    for ep in sorted(ep_total, key=lambda e: (-ep_blocked.get(e, 0), e)):
        k = ep_blocked.get(ep, 0)
        if k == 0:
            continue
        print(row(ep, k, ep_total[ep]))
    clean = [ep for ep in ep_total if ep_blocked.get(ep, 0) == 0]
    print(f"\n{len(clean)} of {len(ep_total)} distinct endpoints with zero blocks")
    print()

    # ---- blocked endpoints with rule IDs ----
    print("## Blocked endpoints with firing rule IDs\n")
    rule_by_ep: dict[str, set] = collections.defaultdict(set)
    for sid in blocked:
        for e in audit.get(sid, []):
            for r in e.get("rules", []):
                rule_by_ep[annotations[sid]].add(str(r.get("id")))
    for ep in sorted(rule_by_ep):
        ids = sorted(rule_by_ep[ep], key=lambda r: int(r) if r.isdigit() else 0)
        print(f"- `{ep}`: {', '.join(ids)}")
    print()

    # ---- distinct requests AND distinct payloads (rule 15) ----
    print("## Distinct counts (rule 15)\n")
    seen_payload: set = set()
    for s in manifest.values():
        seen_payload.add((s["method"], s["path"], s["query"], s["body"]))
    print(f"- distinct requests (samples): {n}")
    print(f"- distinct (path, query, body) triples: {len(seen_payload)}")
    blocked_triples = {json.dumps([manifest[s]["method"], manifest[s]["path"],
                                   manifest[s]["query"], manifest[s]["body"]])
                       for s in blocked}
    print(f"- distinct blocked triples: {len(blocked_triples)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
