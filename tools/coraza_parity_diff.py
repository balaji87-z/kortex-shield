#!/usr/bin/env python3
"""Step-11 T4: per-sample blocked-set diff and rule-presence table between
the ModSecurity and Coraza runs of the same dataset/config/paranoia.

Usage: coraza_parity_diff.py <modsec_run_dir> <coraza_run_dir>
Reads outcomes.jsonl and responses.jsonl in each dir. Prints:
  - blocked-set diff on the block discriminator (responses.jsonl "blocked",
    i.e. status 403 + nginx marker) - this catches discriminator blocks whose
    outcome class is "inconsistent" (e.g. outbound blocks with an unparseable
    audit score); ids only in one engine, with the other engine's status
  - outcome-class counts per engine
  - rule-presence table: for every rule id, samples where only ModSecurity
    matched / only Coraza matched (top 20 rows by total)
"""
from __future__ import annotations

import collections
import json
import sys


def load(run: str, name: str) -> dict[str, dict]:
    return {r["id"]: r for r in map(json.loads, open(f"{run}/{name}"))}


def main() -> int:
    mod_run, cor_run = sys.argv[1], sys.argv[2]
    mod, cor = load(mod_run, "outcomes.jsonl"), load(cor_run, "outcomes.jsonl")
    mod_resp = load(mod_run, "responses.jsonl")
    cor_resp = load(cor_run, "responses.jsonl")
    ids = sorted(set(mod) & set(cor))
    # blocked = block discriminator (docs/block-discriminator.md), not the
    # outcome class: an outbound block with an unparseable audit score is
    # outcome "inconsistent" but the engine did return the block page.
    mod_blocked = {i for i in ids if mod_resp[i]["blocked"]}
    cor_blocked = {i for i in ids if cor_resp[i]["blocked"]}
    print(f"samples compared: {len(ids)}")
    print(f"blocked modsec {len(mod_blocked)}  coraza {len(cor_blocked)}  "
          f"both {len(mod_blocked & cor_blocked)}  only-modsec {len(mod_blocked - cor_blocked)}  "
          f"only-coraza {len(cor_blocked - mod_blocked)}")
    for i in sorted(mod_blocked - cor_blocked)[:20]:
        print(f"  only-modsec {i}: coraza status={cor_resp[i]['status']} outcome={cor[i]['outcome']}")
    for i in sorted(cor_blocked - mod_blocked)[:20]:
        print(f"  only-coraza {i}: modsec status={mod_resp[i]['status']} outcome={mod[i]['outcome']}")

    for name, res in (("modsec", mod), ("coraza", cor)):
        counts = collections.Counter(r["outcome"] for r in res.values())
        summary = "  ".join(f"{k}={v}" for k, v in sorted(counts.items()))
        print(f"outcome classes {name}: {summary}")

    only_m = collections.Counter()
    only_c = collections.Counter()
    both = collections.Counter()
    for i in ids:
        ms = set(mod[i]["rule_ids"])
        cs = set(cor[i]["rule_ids"])
        for r in ms - cs:
            only_m[r] += 1
        for r in cs - ms:
            only_c[r] += 1
        for r in ms & cs:
            both[r] += 1
    rows = sorted(
        ({r: (both[r], only_m[r], only_c[r]) for r in set(both) | set(only_m) | set(only_c)}).items(),
        key=lambda kv: -(kv[1][0] + kv[1][1] + kv[1][2]),
    )[:20]
    print(f"\n{'rule':>8s} {'both':>6s} {'only-modsec':>12s} {'only-coraza':>12s}")
    for r, (b, m, c) in rows:
        print(f"{r:>8s} {b:6d} {m:12d} {c:12d}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
