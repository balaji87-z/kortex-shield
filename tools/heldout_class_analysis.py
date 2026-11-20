#!/usr/bin/env python3
"""Step-12 T1: wcp-train / heldout class analysis (analysis of existing runs only).

For each run: blocked composition by class (policy-only / detection-only /
detection+policy / neither), the rule IDs behind policy-only blocks, and the
ids + rule IDs of 'neither'-class blocked requests.

Class definitions are the step-10 ones (tools/wcp_decompose.py, fixed before
any analysis): non-threshold rules of a blocked request = all rule IDs in its
audit entries except 949110/959100/950100; policy = 911xxx/920xxx;
detection = 930/931/932/933/934/941/942/943/944xxx; everything else
unclassified. 'neither' = blocked with NO policy and NO detection rule among
its non-threshold rules.

No body values are printed (rule 25).
"""
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

THRESHOLD = {"949110", "959100", "950100"}
DETECTION = ("930", "931", "932", "933", "934", "941", "942", "943", "944")


def rule_class(rid: str) -> str:
    if rid[:3] in ("911", "920"):
        return "policy"
    if rid[:3] in DETECTION:
        return "detection"
    return "unclassified"


def main(run_dirs):
    for run in run_dirs:
        d = Path(run)
        rows = {json.loads(l)["id"]: json.loads(l) for l in open(d / "outcomes.jsonl")}
        rules = defaultdict(set)
        for l in open(d / "audit.jsonl"):
            e = json.loads(l)
            for m in e.get("rules", []):
                rules[e["sample_id"]].add(str(m.get("id")))
        blocked = {i for i, r in rows.items() if r["outcome"] == "waf_block"}
        comp = Counter()
        policy_rule_counts = Counter()
        neither = {}
        for i in blocked:
            nonthr = {r for r in rules.get(i, set()) if r not in THRESHOLD}
            classes = {rule_class(r) for r in nonthr}
            if "policy" in classes and "detection" in classes:
                comp["detection+policy"] += 1
            elif "policy" in classes:
                comp["policy-only"] += 1
                for r in nonthr:
                    if rule_class(r) == "policy":
                        policy_rule_counts[r] += 1
            elif "detection" in classes:
                comp["detection-only"] += 1
            else:
                comp["neither"] += 1
                neither[i] = sorted(nonthr)
        print(f"== {run}: blocked {len(blocked)} composition {dict(comp)}")
        print(f"   policy-only rule IDs: {dict(policy_rule_counts.most_common())}")
        if neither:
            print(f"   neither-class ids ({len(neither)}):")
            for i in sorted(neither):
                print(f"     {i}: rules={neither[i]} status={rows[i]['status']}")


if __name__ == "__main__":
    main(sys.argv[1:])
