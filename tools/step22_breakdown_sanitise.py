#!/usr/bin/env python3
"""Step-22: replace docs/logs/wcp-baseline-breakdown.json (step-09) by a copy
without request paths.

The original keys its per-endpoint table by "METHOD path" taken from the
external WCP traffic; the pre-push scan finds e-mail and JWT shapes in those
paths and the file is over the 5 MB limit (rules 25, 51). The copy keeps every
number and replaces each endpoint key by "METHOD sha256:<first 16 hex of the
SHA-256 of the original key>", so tables can still be joined by anyone who
has the dataset. Hosts, sample ids and rule ids are kept as they are.

Usage: step22_breakdown_sanitise.py <original.json> <sanitised.json>
Prints counts only.
"""
import hashlib, json, sys


def endpoint_key(key):
    method, _, _ = key.partition(" ")
    return f"{method} sha256:{hashlib.sha256(key.encode('utf-8', 'surrogatepass')).hexdigest()[:16]}"


def sanitise(doc):
    out, stats = {}, {}
    for config, section in doc.items():
        new = dict(section)
        table = {}
        for key, value in section.get("per_endpoint", {}).items():
            k = endpoint_key(key)
            if k in table:
                raise SystemExit(f"{config}: hash collision between endpoint keys")
            table[k] = value
        new["per_endpoint"] = table
        new["per_endpoint_key"] = "METHOD sha256:<first 16 hex of SHA-256 of 'METHOD path'>; paths removed in step-22 (rules 25, 51)"
        out[config] = new
        stats[config] = (len(table), len(section.get("per_host", {})), len(section.get("blocked_rule_sets", {})))
    return out, stats


def main():
    src, dst = sys.argv[1], sys.argv[2]
    doc = json.load(open(src, encoding="utf-8"))
    out, stats = sanitise(doc)
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(out, f, separators=(",", ":"), sort_keys=True)
        f.write("\n")
    for config, (e, h, b) in stats.items():
        print(f"{config}: {e} endpoints, {h} hosts, {b} blocked ids")


if __name__ == "__main__":
    main()
