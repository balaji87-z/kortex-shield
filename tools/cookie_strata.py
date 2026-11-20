#!/usr/bin/env python3
"""Step-12 T5: cookie-strata analysis — dropped vs restored vs no-cookie.

Strata (from out/benign-wcp-v0-baseline-manifest.jsonl, 19,994 rows — the
population every run below replayed; the frozen 20,000-row manifest adds 5
rows that no run covers):
  cookie-dropped : a cookie header (any casing) with value "[DROPPED]"  (13,261)
  cookie-absent  : no cookie header at all                              ( 6,733)

Runs compared (all ModSecurity, same engine/config family, blocking mode):
  dropped  : out/wcp-cookie-dropped-pl{1,2}                       (cookie replaced
             by the literal string "[DROPPED]")
  restored : out/modsec-wcp-cookie-restored-all-pl{1,2}           (real cookie
             restored for ALL 13,261 dropped rows; step-12 re-run after the
             case-sensitivity fix in tools/restore_wcp_cookies.py — the
             step-11 restored run covered only the 7,511 lowercase-"cookie"
             rows and skipped the 5,750 "Cookie"-spelled rows)
  full-run : out/modsec-benign-wcp-v0-pl{1,2}-stub                (both strata
             in one 20,000-row run, cookie still "[DROPPED]")

Reported per AGENTS rules 14/20/21: dropped and absent strata are NEVER merged;
every rate states its denominator; worst case = waf_block + waf_deny_status +
inconsistent + error; best case = waf_block only. Wilson 95% intervals.

Also: top-10 sole-rule attributions in the restored runs (samples whose rule
list, excluding 949110, contains exactly one id).
"""
import json
import math
from collections import Counter

MANIFEST = "out/benign-wcp-v0-baseline-manifest.jsonl"
RUNS = {
    "dropped": {1: "out/wcp-cookie-dropped-pl1", 2: "out/wcp-cookie-dropped-pl2"},
    "restored": {1: "out/modsec-wcp-cookie-restored-all-pl1",
                 2: "out/modsec-wcp-cookie-restored-all-pl2"},
    "full": {1: "out/modsec-benign-wcp-v0-pl1-stub",
             2: "out/modsec-benign-wcp-v0-pl2-stub"},
}
WORST = {"waf_block", "waf_deny_status", "inconsistent", "error"}


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)


def fmt(k, n):
    if n == 0:
        return "n/a"
    lo, hi = wilson(k, n)
    return f"{k}/{n} = {100*k/n:.2f}% (95% Wilson {100*lo:.2f}-{100*hi:.2f}%)"


def load_outcomes(path):
    return {r["id"]: r for r in map(json.loads, open(path + "/outcomes.jsonl"))}


def main():
    dropped_ids, absent_ids, host_of = set(), set(), {}
    for line in open(MANIFEST):
        r = json.loads(line)
        h = {k.lower(): v for k, v in r["headers"].items()}
        host_of[r["id"]] = h.get("host", "?")
        if h.get("cookie") == "[DROPPED]":
            dropped_ids.add(r["id"])
        elif "cookie" not in h:
            absent_ids.add(r["id"])

    print(f"strata sizes (baseline manifest): dropped={len(dropped_ids)} "
          f"absent={len(absent_ids)} total={len(dropped_ids)+len(absent_ids)}")

    for pl in (1, 2):
        print(f"\n===================== PL{pl} =====================")
        om = {s: load_outcomes(RUNS[s][pl]) for s in RUNS}

        for stratum, ids in (("dropped", dropped_ids), ("absent", absent_ids)):
            for src in ("dropped", "restored", "full"):
                if stratum == "absent" and src == "dropped":
                    continue  # the dropped-run replayed only dropped-stratum ids
                sub = [om[src][i] for i in ids if i in om[src]]
                worst = sum(o["outcome"] in WORST for o in sub)
                block = sum(o["outcome"] == "waf_block" for o in sub)
                print(f"PL{pl} {stratum:7} via {src:8}: worst {fmt(worst, len(sub))}"
                      f" | waf_block-only {fmt(block, len(sub))}")

        hosts = sorted({host_of[i] for i in dropped_ids})
        print(f"\nPL{pl} per-host worst-case rates, cookie-dropped stratum "
              f"(dropped-run vs restored-run; hosts with any flagged request):")
        print(f"{'host':40} {'dropped-run':30} {'restored-run':30}")
        for h in hosts:
            ids = [i for i in dropped_ids if host_of[i] == h]
            cells = []
            for src in ("dropped", "restored"):
                sub = [om[src][i] for i in ids if i in om[src]]
                if not sub:
                    cells.append("n/a")
                    continue
                k = sum(o["outcome"] in WORST for o in sub)
                cells.append(f"{k}/{len(sub)} = {100*k/len(sub):.1f}%")
            if cells[0] == "n/a" and cells[1] == "n/a":
                continue
            def _k(cell):
                return 0 if cell == "n/a" else int(cell.split("/")[0])
            if _k(cells[0]) > 0 or _k(cells[1]) > 0:
                print(f"{h[:40]:40} {cells[0]:30} {cells[1]:30}")

        print(f"\nPL{pl} top-10 sole-rule attributions (restored run, cookie-dropped "
              f"stratum, worst-case outcomes; 949110 excluded):")
        cnt = Counter()
        for i in dropped_ids:
            o = om["restored"].get(i)
            if not o or o["outcome"] not in WORST:
                continue
            rules = [r for r in o.get("rule_ids") or [] if r != "949110"]
            if len(rules) == 1:
                cnt[rules[0]] += 1
        for rid, n in cnt.most_common(10):
            print(f"  {rid}: {n}")
        print(f"  (sole-rule samples total: {sum(cnt.values())})")


if __name__ == "__main__":
    main()
