"""Breakdown of attack-corpus results: family x injection_point, family x
fragment/complete, with counts, 95% Wilson intervals and distinct-payload counts.

Inputs: frozen manifest, annotations file, and an outcomes.jsonl from a run
(--predictions still accepted for backward compatibility, but denominators
always come from the manifest per AGENTS rule 21: samples are never dropped).
With outcomes, recall is reported two ways (rule 21):
  best case  = only inbound blocks count as recalled (outbound-cut and errors
               stay in the denominator, NOT in the numerator);
  worst case = outbound-cut and errors also count as recalled.
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


def load_statuses(args) -> dict[str, str]:
    """Map sample id -> outcome string from --outcomes, or --predictions."""
    statuses: dict[str, str] = {}
    if getattr(args, "outcomes", None):
        for line in open(args.outcomes, encoding="utf-8"):
            if line.strip():
                obj = json.loads(line)
                statuses[obj["id"]] = obj["outcome"]
    else:
        for line in open(args.predictions, encoding="utf-8"):
            if line.strip():
                obj = json.loads(line)
                statuses[obj["id"]] = "waf_block" if obj["flagged"] else "waf_pass"
    return statuses


def family_recall(
    manifest: list[dict], statuses: dict[str, str]
) -> dict[str, dict[str, int]]:
    """Per-family recall counts with manifest-count denominators (rule 21).

    Returns family -> {denominator, best (inbound blocks only),
    worst (outbound-cut and errors also counted as recalled)}.
    Samples with no status row are treated as not recalled in both cases
    but never removed from the denominator.
    """
    out: dict[str, dict[str, int]] = {}
    for s in manifest:
        fam = s["family"]
        d = out.setdefault(fam, {"denominator": 0, "best": 0, "worst": 0})
        d["denominator"] += 1
        st = statuses.get(s["id"])
        if st == "waf_block":
            d["best"] += 1
            d["worst"] += 1
        elif st in ("waf_block_outbound", "error"):
            d["worst"] += 1
    return out


def grouped_recall(
    manifest: list[dict], statuses: dict[str, str], keyfn
) -> dict[tuple, dict[str, int]]:
    """Same counting as family_recall but grouped by an arbitrary key."""
    out: dict[tuple, dict[str, int]] = {}
    for s in manifest:
        key = keyfn(s)
        d = out.setdefault(key, {"denominator": 0, "best": 0, "worst": 0})
        d["denominator"] += 1
        st = statuses.get(s["id"])
        if st == "waf_block":
            d["best"] += 1
            d["worst"] += 1
        elif st in ("waf_block_outbound", "error"):
            d["worst"] += 1
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Break down attack-corpus predictions.")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--annotations", required=True)
    ap.add_argument("--predictions", default=None)
    ap.add_argument("--outcomes", default=None)
    args = ap.parse_args()
    if not args.outcomes and not args.predictions:
        ap.error("one of --outcomes or --predictions is required")

    manifest = [json.loads(l) for l in open(args.manifest, encoding="utf-8") if l.strip()]
    annotations = {a["id"]: a for a in
                   (json.loads(l) for l in open(args.annotations, encoding="utf-8") if l.strip())}
    statuses = load_statuses(args)

    missing = [s["id"] for s in manifest if s["id"] not in statuses]
    if missing:
        print(f"attack_breakdown: {len(missing)} samples without a status row "
              f"(kept in the denominator, rule 21), e.g. {missing[:5]}", file=sys.stderr)

    def recall_table(title: str, keyfn) -> list[str]:
        groups: dict[tuple, dict[str, int]] = grouped_recall(manifest, statuses, keyfn)
        lines = [f"### {title}", "",
                 "| Group | Recall best case (outbound-cut not flagged) | Recall worst case (outbound-cut + errors flagged) |",
                 "|---|---|---|"]
        for key in sorted(groups, key=str):
            d = groups[key]
            lines.append(
                f"| {key} | {row_plain(d['best'], d['denominator'])} "
                f"| {row_plain(d['worst'], d['denominator'])} |")
        return lines

    def row_plain(k: int, n: int) -> str:
        p, lo, hi = wilson(k, n)
        return f"{k}/{n} = {pct(p)} ({pct(lo)}–{pct(hi)})"

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
