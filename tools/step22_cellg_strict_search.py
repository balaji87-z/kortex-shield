#!/usr/bin/env python3
"""Step-22 follow-up (F3): look for a zlib stream of an attack canary that
holds no byte below 32 and no DEL, i.e. one that CRS 920271 (PL2) would not
match. Time-bounded (200 s per canary, seed 1), so the number of tries
depends on the machine; a result "found: False" is not a proof that no such
stream exists. The canaries are my own strings, not dataset content.

Usage: step22_cellg_strict_search.py sqli|xss
"""
import zlib, random, string, sys, time, json
XSS = '"><script>alert(1)</script>'
SQLI = 'admin" or "1"="1"#'
alpha = string.ascii_lowercase + "     "
def forbid(b): return b < 32 or b == 127
def search(text, seconds, seed):
    rng = random.Random(seed); t0 = time.time(); n = 0
    while time.time() - t0 < seconds:
        n += 1
        pre = "".join(rng.choice(alpha) for _ in range(rng.randint(1, 30))).strip() or "a"
        suf = "".join(rng.choice(alpha) for _ in range(rng.randint(0, 60))).strip()
        raw = (pre + " " + text + (" " + suf if suf else "")).encode()
        for level in (6, 9):
            for strat in (zlib.Z_DEFAULT_STRATEGY, zlib.Z_FILTERED, zlib.Z_HUFFMAN_ONLY, zlib.Z_FIXED):
                c = zlib.compressobj(level, zlib.DEFLATED, 15, 8, strat)
                out = c.compress(raw) + c.flush()
                if not any(forbid(b) for b in out):
                    return {"tries": n, "level": level, "strategy": strat, "raw": raw.decode(), "hex": out.hex()}
    return {"tries": n, "found": False}
name = sys.argv[1]
print(json.dumps({name: search({"xss": XSS, "sqli": SQLI}[name], 200, 1)}), flush=True)
