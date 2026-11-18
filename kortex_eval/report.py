"""Render an evaluation as a markdown table.

Usage:
    python -m kortex_eval.report --manifest data/test.jsonl --predictions out/crs.jsonl --name "CRS PL1"

predictions file: one JSON object per line, {"id": "...", "flagged": true}
"""
from __future__ import annotations

import argparse
import json

from . import manifest
from .metrics import Evaluation, Rate, evaluate


def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{100 * x:.2f}%"


def _row(name: str, r: Rate) -> str:
    return f"| {name} | {r.count}/{r.total} | {_pct(r.value)} | {_pct(r.low)} – {_pct(r.high)} |"


def render(name: str, ev: Evaluation) -> str:
    lines = [
        f"### {name}",
        "",
        "| Measure | Count | Rate | 95% interval |",
        "|---|---|---|---|",
        _row("Overall attack recall", ev.overall_recall),
    ]
    for fam, rate in ev.recall_by_family.items():
        lines.append(_row(f"Recall: {fam}", rate))
    lines.append(_row("False positive rate (benign flagged)", ev.false_positive_rate))
    fpr = ev.false_positive_rate
    if fpr.total > 0 and fpr.count == 0:
        lines += [
            "",
            f"Zero false positives in {fpr.total} benign requests does not mean the rate is zero. "
            f"The 95% upper bound is {_pct(fpr.high)}.",
        ]
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--predictions", required=True)
    ap.add_argument("--name", default="System under test")
    args = ap.parse_args()

    samples = manifest.load(args.manifest)
    flagged: dict[str, bool] = {}
    with open(args.predictions, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                obj = json.loads(line)
                flagged[obj["id"]] = bool(obj["flagged"])
    print(render(args.name, evaluate(samples, flagged)))


if __name__ == "__main__":
    main()
