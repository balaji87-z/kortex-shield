#!/usr/bin/env python3
"""Step-10 T4: decompose WCP default-config blocks (analysis only).

CLASS DEFINITIONS AND ATTRIBUTION RULE — fixed here, BEFORE any analysis run:

- non-threshold rules of a blocked request = all rule IDs in its audit
  entries except 949110 / 959100 / 950100.
- rule class (docs/rule-classes.md): policy = 911xxx/920xxx; detection =
  930/931/932/933/934/941/942/943/944xxx; everything else unclassified.
- SOLE-RULE ATTRIBUTION (fixed before analysis): each blocked request is
  attributed to exactly one non-threshold rule — the one with the highest
  CRS severity (audit severity field, 0=high .. 5=low; missing severity
  ranks last), ties broken by ascending rule ID. This is an attribution
  convention, not a counterfactual claim about which rule "caused" the
  block: blocking is threshold-based.
- detection-involved = blocked request with >=1 detection rule among its
  non-threshold rules (bound from rule presence, NOT a counterfactual:
  without the detection rule the request might still block on policy rules).
"""

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

THRESHOLD = {"949110", "959100", "950100"}
POLICY = ("911", "920")
DETECTION = ("930", "931", "932", "933", "934", "941", "942", "943", "944")


def rule_class(rid: str) -> str:
    if rid[:3] in POLICY:
        return "policy"
    if rid[:3] in DETECTION:
        return "detection"
    return "unclassified"


def severity_key(entry_rule):
    sev = entry_rule.get("severity")
    try:
        return int(sev)
    except (TypeError, ValueError):
        return 99


def wilson(k, n, z=1.959963984540054):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    a = z * ((p * (1 - p) + z * z / (4 * n)) / n) ** 0.5
    return p, (c - a) / d, (c + a) / d


def pct(k, n):
    p, lo, hi = wilson(k, n)
    return f"{k}/{n} = {100*p:.2f}% ({100*lo:.2f}-{100*hi:.2f}%)"


def load(run_dir: Path):
    rows = {json.loads(l)["id"]: json.loads(l)
            for l in open(run_dir / "outcomes.jsonl")}
    ann = {json.loads(l)["id"]: json.loads(l)
           for l in open("data/benign-wcp-v0/annotations.jsonl")}
    rules = defaultdict(list)  # id -> list of {id, severity}
    for l in open(run_dir / "audit.jsonl"):
        e = json.loads(l)
        for m in e.get("rules", []):
            rules[e["sample_id"]].append(m)
    return rows, ann, rules


def main():
    for tag, run in (("PL1", "out/benign-wcp-v0-pl1-default-ua"),
                     ("PL2", "out/benign-wcp-v0-pl2-default-ua")):
        run_dir = Path(run)
        rows, ann, rules = load(run_dir)
        n = len(rows)
        blk = [r for r in rows.values() if r["outcome"] == "waf_block"]
        print("=" * 25, tag, f"(n={n}, blocked={len(blk)})")

        # (a) sole-rule attribution, top 15
        attr = Counter()
        for r in blk:
            nonth = [m for m in rules[r["id"]]
                     if str(m["id"]) not in THRESHOLD]
            if not nonth:
                attr["<threshold-only>"] += 1
                continue
            best = sorted(nonth, key=lambda m: (severity_key(m), str(m["id"])))[0]
            attr[str(best["id"])] += 1
        print("(a) sole-rule attribution top 15:")
        for rid, c in attr.most_common(15):
            print(f"    {rid}: {c} ({100*c/len(blk):.1f}% of blocks)")

        # (b) rule IDs of the 'neither' requests
        neither = []
        for r in blk:
            nonth = {str(m["id"]) for m in rules[r["id"]]
                     if str(m["id"]) not in THRESHOLD}
            if nonth and not any(rule_class(x) in ("policy", "detection")
                                 for x in nonth):
                neither.append((r["id"], sorted(nonth)))
        print(f"(b) 'neither' requests: {len(neither)}")
        for i, rl in neither:
            print(f"    {i}: {rl}")

        # (c) 920420 by content type; 911100 by method
        ct_total = Counter()
        ct_blk = Counter()
        for r in rows.values():
            ct = ann[r["id"]].get("content_type") or "<none>"
            # content type from manifest annotations? annotations lack it; use manifest
        # load content types from manifest
        ct_all = {}
        for l in open("data/benign-wcp-v0/manifest.jsonl"):
            s = json.loads(l)
            ct_all[s["id"]] = s["content_type"] or "<none>"
        for r in rows.values():
            ct = ct_all[r["id"]]
            ct_total[ct] += 1
            if r["outcome"] == "waf_block" and any(
                    str(m["id"]) == "920420" for m in rules[r["id"]]):
                ct_blk[ct] += 1
        print("(c) 920420 blocks by request content type (top 15 by blocks):")
        for ct, c in ct_blk.most_common(15):
            print(f"    {ct!r}: blocked {c}, type total {ct_total[ct]}, "
                  f"share of type {100*c/ct_total[ct]:.1f}%")
        m_total = Counter(); m_blk = Counter()
        for l in open("data/benign-wcp-v0/manifest.jsonl"):
            s = json.loads(l)
            m_total[s["method"]] += 1
        for r in rows.values():
            meth = ann[r["id"]]["endpoint"].split()[0]
            if r["outcome"] == "waf_block" and any(
                    str(m["id"]) == "911100" for m in rules[r["id"]]):
                m_blk[meth] += 1
        print("    911100 blocks by method:")
        for meth, c in sorted(m_blk.items()):
            print(f"    {meth}: blocked {c}, method total {m_total[meth]}, "
                  f"share of method {100*c/m_total[meth]:.1f}%")

        # (d) per host
        h_tot = Counter(); h_blk = Counter()
        for r in rows.values():
            h = ann[r["id"]]["host"]
            h_tot[h] += 1
            if r["outcome"] == "waf_block":
                h_blk[h] += 1
        hosts_with_block = sum(1 for h in h_tot if h_blk[h] > 0)
        macro = [h_blk[h] / h_tot[h] for h in h_tot if h_tot[h] >= 5]
        micro_k = sum(h_blk.values()); micro_n = sum(h_tot.values())
        p, lo, hi = wilson(micro_k, micro_n)
        print(f"(d) hosts with >=1 block: {hosts_with_block}/{len(h_tot)}")
        print(f"    macro-average rate over hosts with >=5 requests "
              f"({len(macro)} hosts): {100*sum(macro)/len(macro):.2f}%")
        print(f"    micro rate: {pct(micro_k, micro_n)}")
        print("    top 10 hosts by blocks:")
        for h, c in h_blk.most_common(10):
            print(f"    {h}: {c}/{h_tot[h]} = {100*c/h_tot[h]:.1f}%")

        # (e) detection-only and detection-involved bounds
        det_only_k = det_inv_k = 0
        for r in blk:
            cls = {rule_class(str(m["id"])) for m in rules[r["id"]]
                   if str(m["id"]) not in THRESHOLD}
            if "detection" in cls and "policy" not in cls:
                det_only_k += 1
            if "detection" in cls:
                det_inv_k += 1
        print("(e) bounds from rule presence (NOT counterfactual):")
        print(f"    detection-only blocks: {pct(det_only_k, n)}")
        print(f"    detection-involved blocks: {pct(det_inv_k, n)}")


if __name__ == "__main__":
    main()
