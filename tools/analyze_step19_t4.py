#!/usr/bin/env python3
"""Step-19 T4 analysis: benign-wcp-v1 (HELD-OUT) — new blocks (post minus pre),
presence in both post runs, run-to-run disagreement, timeouts, classification
by rule family and content type. Counts only (rule 35); new blocks are NEW
BLOCKS, never "gains" (rule 46)."""
import json, collections, sys, os

BASE = "out"
DS = "benign-wcp-v1"
runs = {
    "post1": f"{BASE}/s19-t4-{DS}-post-r1-pl", "post2": f"{BASE}/s19-t4-{DS}-post-r2-pl",
    "pre1": f"{BASE}/s19-t4-{DS}-pre-r1-pl", "pre2": f"{BASE}/s19-t4-{DS}-pre-r2-pl",
}

def load_outcomes(path):
    d = {}
    if not os.path.exists(path): return d
    for line in open(path, encoding="utf-8", errors="replace"):
        try: e = json.loads(line)
        except: continue
        d[e.get("id")] = e
    return d

def blocked_ids(d):
    return {i for i, e in d.items() if e.get("outcome") in ("block", "waf_block")}

def rule_ids(d, ids):
    c = collections.Counter()
    for i in ids:
        for r in (d[i].get("rules") or []):
            c[str(r.get("id"))] += 1
    return c

def ct_of(d, i):
    e = d[i]
    return (e.get("content_type") or "(sin ct)") if "content_type" in e else (e.get("headers", {}) or {}).get("Content-Type", "(sin ct)")

out = []
P = runs
data = {}
for k, base in P.items():
    for pl in ("1", "2"):
        data[(k, pl)] = load_outcomes(f"{base}{pl}/outcomes.jsonl")

for pl in ("1", "2"):
    post1, post2, pre1, pre2 = data[("post1", pl)], data[("post2", pl)], data[("pre1", pl)], data[("pre2", pl)]
    if not post1: continue
    b_post1, b_post2 = blocked_ids(post1), blocked_ids(post2)
    b_pre1, b_pre2 = blocked_ids(pre1), blocked_ids(pre2)
    b_pre = b_pre1 | b_pre2  # pre union (a pre block in either run counts as pre-existing)
    new1 = b_post1 - b_pre
    new2 = b_post2 - b_pre
    new_both = new1 & new2
    new_either = new1 | new2
    # run-to-run disagreement of the SAME binary (post)
    dis_post = (b_post1 - b_post2) | (b_post2 - b_post1)
    dis_pre = (b_pre1 - b_pre2) | (b_pre2 - b_pre1)
    # timeouts (fail-closed)
    to_post = [i for i, e in post1.items() if e.get("outcome") in ("timeout", "error")]
    to_pre = [i for i, e in pre1.items() if e.get("outcome") in ("timeout", "error")]
    print(f"== PL{pl} ==")
    print(f"post r1 bloqueados: {len(b_post1)} | post r2: {len(b_post2)} | pre r1: {len(b_pre1)} | pre r2: {len(b_pre2)}")
    print(f"NEW BLOCKS (post-pre): r1={len(new1)} r2={len(new2)} en-AMBAS={len(new_both)} en-alguna={len(new_either)}")
    print(f"desacuerdo run-a-run MISMO binario: post={len(dis_post)} pre={len(dis_pre)}")
    print(f"timeouts/errors: post r1={len(to_post)} pre r1={len(to_pre)}")
    if new_either:
        rc = rule_ids(post1, new_either)
        print("reglas de los new blocks (top 10):", ", ".join(f"{r}x{n}" for r, n in rc.most_common(10)))
        cts = collections.Counter(ct_of(post1, i) for i in new_either)
        print("content types (top 8):", ", ".join(f"{c}x{n}" for c, n in cts.most_common(8)))
        # families
        fams = collections.Counter()
        for r, n in rc.items():
            fam = r[:3] if len(r) >= 3 else r
            fams[fam] += n
        print("familias:", ", ".join(f"{f}x{n}" for f, n in fams.most_common(8)))
        both_sorted = sorted(new_both)
        print(f"new blocks estables (en ambas): primeros 15 ids: {both_sorted[:15]}")
        only1 = sorted(new1 - new2)[:10]; only2 = sorted(new2 - new1)[:10]
        if only1: print("solo r1 (flip-sospechosos):", only1)
        if only2: print("solo r2 (flip-sospechosos):", only2)
    print()

# comparación con v0 (step-18: post-pre PL1 61, PL2 29)
print("Referencia v0 (step-18, IN-SAMPLE): new blocks PL1=61, PL2=29")
