"""Breakdown of attack-corpus results: family x injection_point, family x
fragment/complete, with counts, 95% Wilson intervals and distinct-payload counts.

Inputs: frozen manifest, annotations file, and a predictions.jsonl from a run.
Prints unstratified per-family recall FIRST, then the stratified views
(rule: stratified numbers are shown alongside, never instead of, unstratified).
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import sys
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.959963984540054) -> tuple[float, float, float]:
    """Wilson score interval; returns (rate, low, high) or (None, None, None) for n=0."""
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
    ap = argparse.ArgumentParser(description="Break down attack-corpus predictions.")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--annotations", required=True)
    ap.add_argument("--predictions", required=True)
    args = ap.parse_args()

    manifest = [json.loads(l) for l in open(args.manifest, encoding="utf-8") if l.strip()]
    annotations = {a["id"]: a for a in
                   (json.loads(l) for l in open(args.annotations, encoding="utf-8") if l.strip())}
    flagged: dict[str, bool] = {}
    for line in open(args.predictions, encoding="utf-8"):
        if line.strip():
            obj = json.loads(line)
            flagged[obj["id"]] = bool(obj["flagged"])

    missing = [s["id"] for s in manifest if s["id"] not in flagged]
    if missing:
        print(f"attack_breakdown: {len(missing)} samples without a prediction, "
              f"e.g. {missing[:5]}", file=sys.stderr)
        return 2

    def recall_table(title: str, keyfn) -> list[str]:
        groups: dict[tuple, list[dict]] = collections.defaultdict(list)
        for s in manifest:
            groups[keyfn(s)].append(s)
        lines = [f"### {title}", "", "| Group | Recall | Rate | 95% interval |", "|---|---|---|---|"]
        for key in sorted(groups, key=str):
            ss = groups[key]
            k = sum(1 for s in ss if flagged[s["id"]])
            lines.append(row(str(key), k, len(ss)))
        return lines

    out: list[str] = []

    # unstratified first
    out += recall_table("Recall per family (unstratified)", lambda s: s["family"])

    # distinct payloads per family
    out += ["", "### Distinct payloads per family (rule 15)", "",
            "| Family | Requests | Distinct payloads |", "|---|---|---|"]
    for fam in sorted({s["family"] for s in manifest}):
        ss = [s for s in manifest if s["family"] == fam]
        payloads = {annotations[s["id"]]["payload"] for s in ss if s["id"] in annotations}
        out.append(f"| {fam} | {len(ss)} | {len(payloads)} |")

    # stratified views
    out += ["", "(Stratified views — the fragment rule was defined after seeing v0",
            "results; these numbers are exploratory and never replace the",
            "unstratified ones above.)", ""]
    out += recall_table("Recall: family x injection_point",
                        lambda s: (s["family"], annotations[s["id"]]["injection_point"]))
    out += [""]
    out += recall_table("Recall: family x fragment/complete",
                        lambda s: (s["family"], "fragment" if annotations[s["id"]]["fragment"] else "complete"))

    print("\n".join(out) + "\n")

    # diversity report
    print("### Payload diversity", "")
    for fam in sorted({s["family"] for s in manifest}):
        payloads = sorted({annotations[s["id"]]["payload"] for s in manifest
                           if s["family"] == fam and s["id"] in annotations})
        print(f"{fam}: {len(payloads)} distinct payloads")
        if fam == "xss":
            text = "\n".join(payloads)
            tags = set()
            handlers = set()
            for p in payloads:
                import re
                tags.update(m.lower() for m in re.findall(r"<\s*([A-Za-z0-9]+)", p))
                handlers.update(m.lower() for m in re.findall(r"on[a-z]+\s*=", p, flags=re.IGNORECASE))
            print(f"  distinct tag names: {len(tags)}")
            print(f"  distinct event-handler names: {len(handlers)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
