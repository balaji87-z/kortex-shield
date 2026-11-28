#!/usr/bin/env python3
"""Step-22 DIAGNOSTIC C: per sample id, how many distinct matched-rule sets
and inbound scores a parsed audit.jsonl holds (kortex_eval.crs_audit or
tools/coraza_audit.py output). Prints ids and counts only (rule 51).

Usage: step22_variance_summary.py <audit.jsonl> <label>
"""
import collections, json, sys


def summarise(path):
    sets = collections.defaultdict(collections.Counter)
    scores = collections.defaultdict(collections.Counter)
    for line in open(path, encoding="utf-8", errors="surrogateescape"):
        if not line.strip():
            continue
        e = json.loads(line)
        sid = e.get("sample_id")
        if not sid:
            continue
        ids = sorted({str(r["id"]) for r in (e.get("rules") or []) if r.get("id")})
        sets[sid][",".join(ids)] += 1
        scores[sid][e.get("inbound_score_from_949110")] += 1
    return sets, scores


def main():
    sets, scores = summarise(sys.argv[1])
    label = sys.argv[2]
    for sid in sorted(sets):
        c = sets[sid]
        common = set.intersection(*(set(k.split(",")) for k in c))
        sc = dict(sorted(scores[sid].items(), key=lambda kv: (kv[0] is None, kv[0])))
        print(f"   [{label}] {sid}: {sum(c.values())} audit entries, {len(c)} distinct rule-id set(s), "
              f"{len(sc)} distinct inbound score(s) {sc}")
        if len(c) > 1:
            for k, n in c.most_common():
                print(f"        x{n}: rules outside the common core: {sorted(set(k.split(',')) - common) or 'none'}")
        else:
            print(f"        rules: {sorted(common)}")


if __name__ == "__main__":
    main()
