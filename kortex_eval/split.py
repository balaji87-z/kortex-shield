"""Splits that cannot leak.

Guarantees:
1. Duplicate request content is removed before splitting.
2. Attack families named in `holdout_families` appear ONLY in `test_unseen_attacks`,
   so recall there measures generalisation to attack types never trained on.
3. No request content appears in more than one partition.

Evaluate two views, each paired with the same benign test set:
    seen   = test_seen_attacks   + test_benign
    unseen = test_unseen_attacks + test_benign
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .manifest import ATTACK, BENIGN, Sample


@dataclass
class Split:
    train: list[Sample]
    test_seen_attacks: list[Sample]     # held-out attacks from families that ARE in train
    test_unseen_attacks: list[Sample]   # attacks from families never seen in train
    test_benign: list[Sample]           # held-out benign traffic

    def seen_view(self) -> list[Sample]:
        return self.test_seen_attacks + self.test_benign

    def unseen_view(self) -> list[Sample]:
        return self.test_unseen_attacks + self.test_benign


def dedupe(samples: list[Sample]) -> tuple[list[Sample], int]:
    """Drop samples whose request content has already been seen. Keeps the first.

    Returns (kept, removed_count). Raises if two identical requests carry
    different labels, because that makes the ground truth ambiguous.
    """
    kept: dict[str, Sample] = {}
    removed = 0
    for s in samples:
        h = s.content_hash()
        if h in kept:
            if kept[h].label != s.label:
                raise ValueError(
                    f"identical request content labelled both {kept[h].label!r} "
                    f"({kept[h].id}) and {s.label!r} ({s.id})"
                )
            removed += 1
            continue
        kept[h] = s
    return list(kept.values()), removed


def _bucket(sample: Sample, seed: int) -> float:
    """Deterministic value in [0, 1) derived from content, stable across runs."""
    digest = hashlib.sha256(f"{seed}:{sample.content_hash()}".encode()).digest()
    return int.from_bytes(digest[:8], "big") / 2**64


def split(
    samples: list[Sample],
    holdout_families: set[str],
    test_fraction: float = 0.3,
    seed: int = 0,
) -> Split:
    if not 0.0 < test_fraction < 1.0:
        raise ValueError("test_fraction must be between 0 and 1")
    attack_families = {s.family for s in samples if s.label == ATTACK}
    missing = holdout_families - attack_families
    if missing:
        raise ValueError(f"holdout families not present in data: {sorted(missing)}")
    if holdout_families >= attack_families:
        raise ValueError("cannot hold out every attack family; nothing left to train on")

    clean, _ = dedupe(samples)
    train: list[Sample] = []
    seen_attacks: list[Sample] = []
    unseen_attacks: list[Sample] = []
    benign_test: list[Sample] = []

    for s in clean:
        if s.label == ATTACK and s.family in holdout_families:
            unseen_attacks.append(s)
        elif _bucket(s, seed) < test_fraction:
            (seen_attacks if s.label == ATTACK else benign_test).append(s)
        else:
            train.append(s)
    return Split(train, seen_attacks, unseen_attacks, benign_test)


def assert_no_leakage(sp: Split) -> None:
    train_hashes = {s.content_hash() for s in sp.train}
    parts = {
        "test_seen_attacks": sp.test_seen_attacks,
        "test_unseen_attacks": sp.test_unseen_attacks,
        "test_benign": sp.test_benign,
    }
    hashes = {name: {s.content_hash() for s in part} for name, part in parts.items()}
    for name, h in hashes.items():
        overlap = train_hashes & h
        if overlap:
            raise AssertionError(f"{len(overlap)} request(s) appear in both train and {name}")
    names = list(hashes)
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            if hashes[a] & hashes[b]:
                raise AssertionError(f"request content appears in both {a} and {b}")
    train_attack_families = {s.family for s in sp.train if s.label == ATTACK}
    leaked = {s.family for s in sp.test_unseen_attacks} & train_attack_families
    if leaked:
        raise AssertionError(f"held-out families present in train: {sorted(leaked)}")
    if any(s.label != ATTACK for s in sp.test_seen_attacks + sp.test_unseen_attacks):
        raise AssertionError("non-attack sample in an attack partition")
    if any(s.label != BENIGN for s in sp.test_benign):
        raise AssertionError("non-benign sample in the benign partition")
