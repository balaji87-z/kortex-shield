"""Build attacks-v1, the held-out attack dataset (docs/plan-attacks-v1.md).

  build_attacks_v1.py build   read the source files, write candidates and the exclusion files
  build_attacks_v1.py freeze <reach-check outcomes.jsonl>
                              drop the candidates the rules did not judge, write the frozen manifest

Sources: PayloadsAllTheThings at one commit; the files, their order and the
caps come from tools/fetch/attacks_v1_sources.sha256, and every file is
checked against its SHA-256 before it is read.

Per family, in the order of that list:
  1. one payload per line, without its line terminator (LF or CRLF); lines
     that hold nothing but whitespace and exact duplicates are dropped;
     lines starting with '#' are kept (they are payloads in these files);
  2. a payload of attacks-v0 is dropped                 -> excluded-in-v0.jsonl
  2a. a payload an earlier family lists is dropped      -> excluded-cross-family.jsonl
  3. not valid UTF-8, or longer than 2,000 bytes        -> excluded-unsendable.jsonl
  4. more than the cap: random.Random(seed).sample, then sorted.
Each payload gives the two requests of attacks-v0 (search query, login JSON).
"label attack" means "listed under this family in this source" (rule 11).
"""
from __future__ import annotations

import argparse
import collections
import hashlib
import json
import random
import sys
import urllib.parse
from pathlib import Path

REPO = "PayloadsAllTheThings"
COMMIT = "08ea40e77db3f42ef8f20c65196f3936a19b6c86"
MAX_PAYLOAD_BYTES = 2000
SEEN_FAMILIES = ("sqli", "xss", "path-traversal", "command-injection")
# outcomes of the reach check that mean "the rules judged this request"
JUDGED = ("waf_pass", "waf_would_block")


def read_source_list(path: Path) -> list[tuple[str, int, list[tuple[str, str]]]]:
    """[(family, cap, [(sha256, relative path)])]; cap 0 means all."""
    families: list[tuple[str, int, list[tuple[str, str]]]] = []
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        if raw.startswith("# family "):
            parts = raw.split()
            if len(parts) != 5 or parts[3] != "cap":
                raise SystemExit(f"{path}: cannot read family line {raw!r}")
            families.append((parts[2], int(parts[4]), []))
        elif raw.startswith("#") or not raw.strip():
            continue
        else:
            sha, sep, rel = raw.partition("  ")
            if not sep or len(sha) != 64 or not families:
                raise SystemExit(f"{path}: cannot read file line {raw!r}")
            families[-1][2].append((sha, rel))
    if not families:
        raise SystemExit(f"{path}: no family")
    return families


def read_lines(external: Path, sha: str, rel: str) -> list[bytes]:
    data = (external / rel).read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        raise SystemExit(f"{rel}: sha256 {got}, the source list has {sha}")
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return [line[:-1] if line.endswith(b"\r") else line for line in lines]


def v0_payloads(annotations: Path) -> set[str]:
    out = set()
    for line in Path(annotations).read_text(encoding="utf-8").splitlines():
        if line.strip():
            payload = json.loads(line)["payload"]
            out.add(payload[:-1] if payload.endswith("\r") else payload)
    return out


def requests_for(family: str, payload: str, source: str) -> list[dict]:
    sha8 = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]
    base = {"label": "attack", "family": family, "source": source}
    return [
        {"id": f"v1-{family}-{sha8}-q", **base, "method": "GET", "path": "/rest/products/search",
         "query": "q=" + urllib.parse.quote(payload, safe=""), "body": "", "content_type": ""},
        {"id": f"v1-{family}-{sha8}-login", **base, "method": "POST", "path": "/rest/user/login", "query": "",
         "body": json.dumps({"email": payload, "password": "x"}), "content_type": "application/json"},
    ]


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")


def build(external: Path, source_list: Path, v0_annotations: Path, out: Path, seed: int = 1) -> dict:
    external, out = Path(external), Path(out)
    families = read_source_list(source_list)
    in_v0 = v0_payloads(v0_annotations)
    rng = random.Random(seed)
    owner: dict[bytes, str] = {}          # payload bytes -> first family that lists it
    candidates: list[dict] = []
    annotations: list[dict] = []
    exc_v0: list[dict] = []
    exc_cross: list[dict] = []
    exc_unsendable: list[dict] = []
    stats: dict = {"seed": seed, "source": f"{REPO}@{COMMIT}", "families": {}}
    for family, cap, files in families:
        st = {"files": len(files), "cap": cap, "raw_lines": 0, "blank_removed": 0, "duplicates_removed": 0,
              "in_v0_removed": 0, "cross_family_removed": 0, "unsendable_removed": collections.Counter(),
              "after_filters": 0, "sampled": 0}
        seen: set[bytes] = set()
        kept: list[tuple[str, str]] = []   # (payload, source)
        for sha, rel in files:
            for lineno, line in enumerate(read_lines(external, sha, rel), 1):
                st["raw_lines"] += 1
                source = f"{REPO}@{COMMIT}:{rel}:{lineno}"
                if not line.strip():
                    st["blank_removed"] += 1
                    continue
                if line in seen:
                    st["duplicates_removed"] += 1
                    continue
                seen.add(line)
                try:
                    text = line.decode("utf-8")
                except UnicodeDecodeError:
                    text = None
                if text is not None and text in in_v0:
                    st["in_v0_removed"] += 1
                    exc_v0.append({"family": family, "source": source, "payload": text})
                    continue
                if owner.setdefault(line, family) != family:
                    st["cross_family_removed"] += 1
                    row = {"family": family, "owner_family": owner[line], "source": source}
                    if text is not None:
                        row["payload"] = text
                    else:
                        row["sha256"] = hashlib.sha256(line).hexdigest()
                    exc_cross.append(row)
                    continue
                reason = None
                if text is None:
                    reason = "not-utf8"
                elif len(line) > MAX_PAYLOAD_BYTES:
                    reason = f"longer-than-{MAX_PAYLOAD_BYTES}-bytes"
                if reason:
                    st["unsendable_removed"][reason] += 1
                    exc_unsendable.append({"family": family, "source": source, "reason": reason,
                                           "bytes": len(line), "sha256": hashlib.sha256(line).hexdigest()})
                    continue
                kept.append((text, source))
        st["after_filters"] = len(kept)
        chosen = sorted(rng.sample(kept, cap)) if cap and len(kept) > cap else kept
        st["sampled"] = len(chosen)
        st["unsendable_removed"] = dict(sorted(st["unsendable_removed"].items()))
        stats["families"][family] = st
        for payload, source in chosen:
            for req in requests_for(family, payload, source):
                candidates.append(req)
                annotations.append({"id": req["id"], "family": family, "payload": payload,
                                    "injection_point": req["id"].rsplit("-", 1)[1],
                                    "family_kind": "seen-family" if family in SEEN_FAMILIES else "new-family"})
    ids = [c["id"] for c in candidates]
    twice = [i for i, n in collections.Counter(ids).items() if n > 1]
    if twice:
        raise SystemExit(f"two payloads share an id (sha8 collision): {twice[:5]}")
    stats["requests"] = len(candidates)
    stats["distinct_payloads"] = len({a["payload"] for a in annotations})
    out.mkdir(parents=True, exist_ok=True)
    write_jsonl(out / "candidates.jsonl", candidates)
    write_jsonl(out / "annotations.jsonl", annotations)
    write_jsonl(out / "excluded-in-v0.jsonl", exc_v0)
    write_jsonl(out / "excluded-cross-family.jsonl", exc_cross)
    write_jsonl(out / "excluded-unsendable.jsonl", exc_unsendable)
    (out / "build-stats.json").write_text(json.dumps(stats, indent=1) + "\n", encoding="utf-8")
    return stats


def freeze(out: Path, reach_outcomes: Path) -> dict:
    """Keep every candidate the rules judged in the reach check; the others go
    to quarantine.jsonl with their outcome as the reason. Never filters on
    would-block against pass."""
    out = Path(out)
    if (out / "MANIFEST.sha256").exists():
        raise SystemExit(f"{out}/MANIFEST.sha256 exists: the dataset is frozen (rule 10)")
    candidates = [json.loads(line) for line in (out / "candidates.jsonl").read_text(encoding="utf-8").splitlines() if line]
    outcome = {}
    for line in Path(reach_outcomes).read_text(encoding="utf-8").splitlines():
        if line.strip():
            row = json.loads(line)
            outcome[row["id"]] = row["outcome"]
    missing = [c["id"] for c in candidates if c["id"] not in outcome]
    if missing:
        raise SystemExit(f"{len(missing)} candidate(s) have no reach-check outcome, e.g. {missing[:3]}")
    kept = [c for c in candidates if outcome[c["id"]] in JUDGED]
    quarantine = [{"id": c["id"], "family": c["family"], "source": c["source"], "reason": outcome[c["id"]]}
                  for c in candidates if outcome[c["id"]] not in JUDGED]
    write_jsonl(out / "manifest.jsonl", kept)
    write_jsonl(out / "quarantine.jsonl", quarantine)
    sha = hashlib.sha256((out / "manifest.jsonl").read_bytes()).hexdigest()
    (out / "MANIFEST.sha256").write_text(f"{sha}  manifest.jsonl\n", encoding="utf-8")
    reach = collections.Counter(outcome[c["id"]] for c in candidates)
    return {"candidates": len(candidates), "kept": len(kept), "quarantined": len(quarantine),
            "reach_outcomes": dict(sorted(reach.items())),
            "quarantine_reasons": dict(sorted(collections.Counter(q["reason"] for q in quarantine).items())),
            "sha256": sha}


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--external-dir", default="data/external/patt-08ea40e")
    b.add_argument("--source-list", default="tools/fetch/attacks_v1_sources.sha256")
    b.add_argument("--v0-annotations", default="data/attacks-v0/annotations.jsonl")
    b.add_argument("--out", default="data/attacks-v1")
    b.add_argument("--seed", type=int, default=1)
    f = sub.add_parser("freeze")
    f.add_argument("reach_outcomes")
    f.add_argument("--out", default="data/attacks-v1")
    args = ap.parse_args(argv)
    if args.cmd == "build":
        if (Path(args.out) / "MANIFEST.sha256").exists():
            raise SystemExit(f"{args.out}/MANIFEST.sha256 exists: the dataset is frozen (rule 10)")
        stats = build(Path(args.external_dir), Path(args.source_list), Path(args.v0_annotations), Path(args.out), args.seed)
        print("| family | files | raw lines | blank | duplicates | in attacks-v0 | in an earlier family | unsendable | after filters | cap | sampled | requests |")
        print("|---|---|---|---|---|---|---|---|---|---|---|---|")
        for fam, st in stats["families"].items():
            print(f"| {fam} | {st['files']} | {st['raw_lines']} | {st['blank_removed']} | {st['duplicates_removed']} | "
                  f"{st['in_v0_removed']} | {st['cross_family_removed']} | {sum(st['unsendable_removed'].values())} "
                  f"{st['unsendable_removed'] or ''} | {st['after_filters']} | {st['cap'] or 'all'} | {st['sampled']} | {2 * st['sampled']} |")
        print(f"candidates: {stats['requests']} requests, {stats['distinct_payloads']} distinct payloads -> {args.out}/candidates.jsonl")
    else:
        res = freeze(Path(args.out), Path(args.reach_outcomes))
        print(f"reach check: {res['candidates']} candidates, outcomes {res['reach_outcomes']}")
        print(f"kept {res['kept']}, quarantined {res['quarantined']} {res['quarantine_reasons'] or ''}")
        print(f"manifest sha256 {res['sha256']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
