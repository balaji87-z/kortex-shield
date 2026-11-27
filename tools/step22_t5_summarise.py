#!/usr/bin/env python3
"""Step-22 T5: summarise padding + content-encoding probe results.

Reads the JSONL produced by run_step22_t5_padding.py / run_step22_t5_encoding.py
and prints per-cell status counts. 403 = blocked by detection or policy;
400/413/503 = fail-closed, reported SEPARATELY from 403 (rule: never merge).
With a body-less audit index as 4th argument it also prints, per cell,
whether each block matched a 941/942 rule (the canary payload itself was
seen) or only protocol/policy rules, and the rule-id sets.

Usage: step22_t5_summarise.py padding|encoding <rows.jsonl> [label] [audit-index.jsonl]
"""
import collections, json, sys

# CRS rule families whose ids at or above x00 are real checks; the x01x ids
# are paranoia-level skip markers and 941010 is a target-selection rule.
PAYLOAD_FAMILIES = ("941", "942")
POLICY_FAMILIES = ("911", "913", "920", "921", "930", "931", "932", "933", "934", "943", "944")

def load_index(path):
    """sample id -> rule ids, from a body-less audit index
    (tools/step22_body_index.py). None when no index was given."""
    if not path:
        return None
    out = {}
    for line in open(path):
        e = json.loads(line)
        if e.get("sample_id"):
            out.setdefault(e["sample_id"], set()).update(e.get("rule_ids") or [])
    return out

def load_sizes(path):
    """sample id -> size of the body the engine handed to the rules."""
    if not path:
        return {}
    return {e["sample_id"]: e.get("body_bytes") for e in map(json.loads, open(path))
            if e.get("sample_id")}

def check_ids(rule_ids):
    return sorted(i for i in rule_ids
                  if i[:3] in PAYLOAD_FAMILIES + POLICY_FAMILIES and int(i[3:]) >= 100)

def block_kind(rule_ids):
    """payload = a 941/942 rule matched (the canary itself was seen);
    policy-only = blocked without any 941/942 match; no-audit = no entry."""
    if rule_ids is None:
        return "no-audit-entry"
    ids = check_ids(rule_ids)
    if any(i[:3] in PAYLOAD_FAMILIES for i in ids):
        return "payload-detected"
    return "policy-only" if ids else "no-check-rule"

def report_kinds(rows, index, key):
    """Per group: how many 403s saw the payload itself (rule 47)."""
    if index is None:
        print("   rule ids per cell: NOT MEASURED (no audit index given)")
        return
    kinds = collections.defaultdict(collections.Counter)
    ids = collections.defaultdict(collections.Counter)
    for r in rows:
        rid = index.get(r["id"])
        kinds[key(r)][(r["status"], block_kind(rid))] += 1
        ids[key(r)][",".join(check_ids(rid or ()))] += 1
    for k in sorted(kinds, key=str):
        print(f"   {k}: " + "; ".join(f"status {s} {kind}={n}" for (s, kind), n in sorted(kinds[k].items(), key=str)))
        for rule_set, n in sorted(ids[k].items()):
            print(f"       rules [{rule_set}] x{n}")

def summarise_padding(path, label, index=None):
    rows = [json.loads(l) for l in open(path)]
    print(f"== {label}: {len(rows)} requests")
    st = collections.Counter(r["status"] for r in rows)
    print("   status counts:", dict(sorted(st.items(), key=lambda kv: (kv[0] is None, kv[0]))))
    # per-k and per-ct breakdown of non-403
    odd = [r for r in rows if r["status"] != 403]
    if odd:
        print(f"   non-403 cells: {len(odd)}")
        for r in odd[:20]:
            print("    ", r["id"], r["status"], r.get("error", "")[:60])
    by_k = collections.Counter((r["k"], r["status"]) for r in rows)
    for k in (8, 32, 120000):
        line = {s: n for (kk, s), n in by_k.items() if kk == k}
        print(f"   k={k}: {line}")
    passed = [r["id"] for r in rows if r["status"] == 200]
    print(f"   PASSED (evasion candidates): {len(passed)}" + (f" ids: {passed[:10]}" if passed else ""))
    report_kinds(rows, index, lambda r: (r["k"], r["payload"], r["ct"].split("/")[-1][:12]))

def summarise_encoding(path, label, index=None, sizes=None):
    rows = [json.loads(l) for l in open(path)]
    print(f"== {label}: {len(rows)} requests")
    cells = collections.defaultdict(collections.Counter)
    rules = collections.defaultdict(collections.Counter)
    for r in rows:
        cells[(r["cell"], r["ct"].split("/")[-1][:12], r["payload"])][r["status"]] += 1
        if r["status"] == 403 and "resp_head" in r and "rules=" in r.get("resp_head", ""):
            head = r["resp_head"]
            ids = head.split("rules=")[1].split(",")[:6]
            rules[(r["cell"])][ids[0]] += 1
    for k in sorted(cells):
        print(f"   cell {k}: {dict(cells[k])}")
    passed = [(r["cell"], r["payload"], r["ct"]) for r in rows if r["status"] == 200]
    print(f"   PASSED (evasion candidates): {len(passed)}")
    for p in passed:
        print("    ", p)
    report_kinds(rows, index, lambda r: (r["cell"], r["variant"], r["payload"], r["ct"].split("/")[-1][:12]))
    listed = [r["id"] for r in rows if r.get("block_page_lists_920450")]
    if any("block_page_lists_920450" in r for r in rows):
        print(f"   block pages that list rule 920450 among the matched rules: {len(listed)} {listed}")
    if sizes:
        # A decoded body would have the size of the raw control; the size of
        # the compressed bytes means the rules saw the body undecoded.
        print("   body bytes the engine recorded per sample (raw control of the same payload and content type in brackets):")
        raw = {(r["payload"], r["ct"]): sizes.get(r["id"]) for r in rows if r["variant"] == "raw"}
        for r in rows:
            if r["variant"] != "raw" and r["id"] in sizes:
                print(f"     {r['id']} {r['variant']}: {sizes[r['id']]} [{raw.get((r['payload'], r['ct']))}]")

if __name__ == "__main__":
    index = load_index(sys.argv[4] if len(sys.argv) > 4 else None)
    if sys.argv[1] == "padding":
        summarise_padding(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "padding", index)
    else:
        summarise_encoding(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "encoding", index,
                           load_sizes(sys.argv[4] if len(sys.argv) > 4 else None))
