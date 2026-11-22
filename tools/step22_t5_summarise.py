#!/usr/bin/env python3
"""Step-22 T5: summarise padding + content-encoding probe results.

Reads the JSONL produced by run_step22_t5_padding.py / run_step22_t5_encoding.py
and prints per-cell status counts. 403 = blocked by detection or policy;
400/413/503 = fail-closed, reported SEPARATELY from 403 (rule: never merge).
"""
import collections, json, sys

def summarise_padding(path, label):
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
    for k in (8192, 32768, 120000):
        line = {s: n for (kk, s), n in by_k.items() if kk == k}
        print(f"   k={k}: {line}")
    passed = [r["id"] for r in rows if r["status"] == 200]
    print(f"   PASSED (evasion candidates): {len(passed)}" + (f" ids: {passed[:10]}" if passed else ""))

def summarise_encoding(path, label):
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

if __name__ == "__main__":
    if sys.argv[1] == "padding":
        summarise_padding(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "padding")
    else:
        summarise_encoding(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "encoding")
