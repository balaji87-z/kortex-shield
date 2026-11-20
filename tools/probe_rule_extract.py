#!/usr/bin/env python3
"""Step-12 T3: extract per-probe rule IDs from an engine audit log, keyed by
the /probe-pNN path marker. Usage: probe_rule_extract.py <audit.jsonl-converted> <out-jsonl>
Accepts BOTH converted schemas (kortex_eval.crs_audit and tools.coraza_audit:
{"sample_id":..., "rules":[...]} with the uri in "uri")."""
import json
import re
import sys

MARK = re.compile(r"/probe-p(\d+)")


def main():
    src, dst = sys.argv[1], sys.argv[2]
    by_probe = {}
    for line in open(src):
        try:
            e = json.loads(line)
        except Exception:
            continue
        uri = e.get("uri", "")
        m = MARK.search(uri)
        if not m:
            continue
        pid = f"P{int(m.group(1)):02d}"
        rids = sorted({str(r.get("id")) for r in e.get("rules", [])})
        by_probe.setdefault(pid, set()).update(rids)
    with open(dst, "w") as f:
        for pid in sorted(by_probe):
            f.write(json.dumps({"probe": pid, "rule_ids": sorted(by_probe[pid])}) + "\n")
    for pid in sorted(by_probe):
        print(pid, sorted(by_probe[pid]))


if __name__ == "__main__":
    main()
