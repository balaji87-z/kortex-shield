#!/usr/bin/env python3
"""Step-27, rule 16: show that paranoia level 2 took effect in the differential.

The cases are answered alike at PL1 and PL2 (the canary is blocked at PL1
already), so the two runs must be told apart some other way: the matched
rule ids per case in the two audit logs of the same engine.

Usage: step27_pl_effect.py PL1_AUDIT_LOG PL2_AUDIT_LOG
"""
import json
import re
import sys

RULE_ID = re.compile(r'\[id "(\d+)"\]')


def rule_ids(path):
    out = {}
    for line in open(path, encoding="utf-8"):
        if not line.startswith('{"transaction"'):
            continue
        entry = json.loads(line)
        headers = entry["transaction"]["request"].get("headers") or {}
        sid = (headers.get("x-kortex-sample-id") or [""])[0]
        ids = {int(i) for m in entry.get("messages") or [] for i in RULE_ID.findall(m.get("error_message") or "")}
        out.setdefault(sid, set()).update(ids)
    return out


def compare(pl1, pl2):
    both = sorted(set(pl1) & set(pl2))
    differ = [c for c in both if pl1[c] != pl2[c]]
    only2 = sorted(set().union(*pl2.values()) - set().union(*pl1.values())) if pl2 else []
    return [f"== rule 16: cases with an audit entry at PL1 {len(pl1)}, at PL2 {len(pl2)}, at both {len(both)}; "
            f"matched rule-id set differs between PL1 and PL2 for {len(differ)} of {len(both)}",
            f"   rule ids matched at PL2 and in no case at PL1: {len(only2)}: " + (", ".join(map(str, only2)) or "none")]


def main(argv):
    print("\n".join(compare(rule_ids(argv[1]), rule_ids(argv[2]))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
