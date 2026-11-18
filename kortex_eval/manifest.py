"""Sample manifest: every request in the dataset carries its provenance.

The earlier prototype could not say where its attack samples came from.
Here a sample without a source is rejected at load time.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

ATTACK = "attack"
BENIGN = "benign"
LABELS = {ATTACK, BENIGN}
BENIGN_FAMILY = "benign"


class ManifestError(ValueError):
    pass


@dataclass(frozen=True)
class Sample:
    id: str
    label: str            # "attack" | "benign"
    family: str           # e.g. "sqli", "xss"; "benign" for benign samples
    source: str           # tool or dataset that produced it, e.g. "sqlmap-1.8", "browse-script"
    method: str
    path: str
    query: str = ""
    body: str = ""
    content_type: str = ""
    headers: dict = field(default_factory=dict, compare=False, hash=False)

    def validate(self) -> None:
        if not self.id:
            raise ManifestError("sample has empty id")
        if self.label not in LABELS:
            raise ManifestError(f"{self.id}: label must be one of {sorted(LABELS)}, got {self.label!r}")
        if not self.source.strip():
            raise ManifestError(f"{self.id}: source is required (provenance)")
        if not self.family.strip():
            raise ManifestError(f"{self.id}: family is required")
        if self.label == BENIGN and self.family != BENIGN_FAMILY:
            raise ManifestError(f"{self.id}: benign samples must have family {BENIGN_FAMILY!r}")
        if self.label == ATTACK and self.family == BENIGN_FAMILY:
            raise ManifestError(f"{self.id}: attack samples cannot have family {BENIGN_FAMILY!r}")
        if not self.method or not self.path:
            raise ManifestError(f"{self.id}: method and path are required")

    def content_hash(self) -> str:
        """Identity of the request content, ignoring id/source/headers."""
        raw = "\x00".join([self.method.upper(), self.path, self.query, self.content_type, self.body])
        return hashlib.sha256(raw.encode("utf-8", "surrogatepass")).hexdigest()


def load(path: str | Path) -> list[Sample]:
    samples: list[Sample] = []
    seen_ids: set[str] = set()
    with open(path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                s = Sample(**obj)
            except (json.JSONDecodeError, TypeError) as exc:
                raise ManifestError(f"{path}:{lineno}: {exc}") from exc
            s.validate()
            if s.id in seen_ids:
                raise ManifestError(f"{path}:{lineno}: duplicate id {s.id!r}")
            seen_ids.add(s.id)
            samples.append(s)
    return samples


def dump(samples: Iterable[Sample], path: str | Path) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for s in samples:
            s.validate()
            fh.write(json.dumps(asdict(s), ensure_ascii=False) + "\n")


def iter_by_family(samples: Iterable[Sample]) -> Iterator[tuple[str, list[Sample]]]:
    groups: dict[str, list[Sample]] = {}
    for s in samples:
        groups.setdefault(s.family, []).append(s)
    for fam in sorted(groups):
        yield fam, groups[fam]
