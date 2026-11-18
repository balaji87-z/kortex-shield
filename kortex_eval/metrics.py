"""Honest metrics: every rate comes with its count and a 95% Wilson interval.

A rate without n is not reported. "10/10 benign passed" yields an upper bound
near 28% on the false positive rate; the interval shows that directly.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

from .manifest import ATTACK, BENIGN, Sample

Z95 = 1.959963984540054


def wilson_interval(successes: int, n: int, z: float = Z95) -> tuple[float, float]:
    if n < 0 or successes < 0 or successes > n:
        raise ValueError(f"invalid counts: {successes}/{n}")
    if n == 0:
        return (0.0, 1.0)
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


@dataclass(frozen=True)
class Rate:
    count: int
    total: int
    low: float
    high: float

    @property
    def value(self) -> float | None:
        return None if self.total == 0 else self.count / self.total


def make_rate(count: int, total: int) -> Rate:
    lo, hi = wilson_interval(count, total)
    return Rate(count, total, lo, hi)


@dataclass
class Evaluation:
    recall_by_family: dict[str, Rate]   # attacks correctly flagged / attacks, per family
    overall_recall: Rate
    false_positive_rate: Rate           # benign wrongly flagged / benign


def evaluate(samples: list[Sample], flagged: dict[str, bool]) -> Evaluation:
    """`flagged[id]` is True if the system under test blocked/flagged the request.

    Every sample must have a prediction. A missing one raises instead of being
    silently skipped, because skipping hides failures.
    """
    missing = [s.id for s in samples if s.id not in flagged]
    if missing:
        raise KeyError(f"{len(missing)} sample(s) have no prediction, e.g. {missing[:3]}")

    per_family: dict[str, list[int]] = {}
    fp = benign_total = tp = attack_total = 0
    for s in samples:
        hit = bool(flagged[s.id])
        if s.label == ATTACK:
            attack_total += 1
            tp += hit
            counts = per_family.setdefault(s.family, [0, 0])
            counts[0] += hit
            counts[1] += 1
        elif s.label == BENIGN:
            benign_total += 1
            fp += hit
    return Evaluation(
        recall_by_family={fam: make_rate(c[0], c[1]) for fam, c in sorted(per_family.items())},
        overall_recall=make_rate(tp, attack_total),
        false_positive_rate=make_rate(fp, benign_total),
    )
