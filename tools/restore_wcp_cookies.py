#!/usr/bin/env python3
"""Step-10 T7: restore ORIGINAL cookie values for a seeded subset of WCP samples.

- Seeded (seed 1) sample of 2,000 requests from the frozen benign-wcp-v0
  baseline manifest (19,994) whose `cookie` header value was dropped at
  build time (`[DROPPED]`).
- Reads the ORIGINAL cookie values from the source zip by streaming it
  (data/external/legitimate.zip, never extracted); each manifest row's
  `source` field points at `file:global_index` in the zip.
- Authorization stays dropped (per task).
- Output: out/wcp-cookie-restored/manifest.jsonl (gitignored; rule 25 —
  cookie values are credentials and must not be committed). Only this
  script is committed.
- Nothing in the frozen dataset is modified.
"""

import hashlib
import json
import random
import sys
import zipfile
from pathlib import Path

ZIP_PATH = Path("data/external/legitimate.zip")
BASE_MANIFEST = Path("out/benign-wcp-v0-baseline-manifest.jsonl")
OUT_DIR = Path("out/wcp-cookie-restored")
SEED = 1
N = 2_000


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Restore original WCP cookie values from the source zip.")
    ap.add_argument("--all", action="store_true",
                    help="restore ALL cookie-dropped rows instead of the seeded 2,000 subset "
                         "(step-11 T6); output dir becomes out/wcp-cookie-restored-all")
    args = ap.parse_args()
    global OUT_DIR
    if args.all:
        OUT_DIR = Path("out/wcp-cookie-restored-all")
    rows = [json.loads(l) for l in open(BASE_MANIFEST)]
    # Step-12 T5 fix: the dataset stores the dropped cookie under BOTH header
    # spellings ("cookie" and "Cookie"). The original case-sensitive lookup
    # silently skipped every "Cookie"-spelled row (5,750 of 13,261 in the
    # baseline), which is why the restored-all manifest had only 7,511 rows.
    # Selection is now case-insensitive; nothing else changes.
    dropped = [r for r in rows
               if any(k.lower() == "cookie" and v == "[DROPPED]"
                      for k, v in r.get("headers", {}).items())]
    print(f"baseline rows {len(rows)}; cookie-dropped rows {len(dropped)}")
    if args.all:
        chosen = sorted(dropped, key=lambda r: r["id"])
    else:
        if len(dropped) < N:
            sys.exit("not enough cookie-dropped rows")
        chosen = random.Random(SEED).sample(sorted(dropped, key=lambda r: r["id"]), N)
    want = {}
    for r in chosen:
        # source = openappsec-wcp@<commit>:<zipname>:<global_index>
        _tag, zname, gidx = r["source"].split(":")
        want[(zname, int(gidx))] = r["id"]
    print(f"selected {len(want)} records to restore (seed {SEED})")

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    z = zipfile.ZipFile(ZIP_PATH)
    names = sorted(n for n in z.namelist() if n.endswith(".json"))
    restored = 0
    missing_cookie = 0
    g = 0  # global record counter across files, same order as the builder
    out = open(OUT_DIR / "manifest.jsonl", "w")
    for fi, name in enumerate(names):
        data = json.load(z.open(name))
        file_len = len(data)
        idxs = sorted(gg for n, gg in want if n == name)
        if not idxs:
            g += file_len
            continue
        for gg in idxs:
            rec = data[gg - g]  # global index -> offset within this file
            sid = want[(name, gg)]
            row = next(r for r in chosen if r["id"] == sid)
            headers = dict(row["headers"])
            orig_cookie = None
            for k, v in rec.get("headers", {}).items():
                if k.lower() == "cookie":
                    orig_cookie = v
                    break
            if orig_cookie is None:
                missing_cookie += 1
                continue
            headers["cookie"] = orig_cookie
            row = dict(row)
            row["headers"] = headers
            out.write(json.dumps(row, ensure_ascii=False) + "\n")
            restored += 1
        g += file_len
        if (fi + 1) % 50 == 0:
            print(f"  {fi+1}/{len(names)} files, restored {restored}", flush=True)
    out.close()
    print(f"restored {restored}; records without a cookie header: {missing_cookie}")
    # integrity check: restored rows differ from baseline ONLY in cookie value
    base = {json.loads(l)["id"]: json.loads(l) for l in open(BASE_MANIFEST)}
    for l in open(OUT_DIR / "manifest.jsonl"):
        r = json.loads(l)
        b = base[r["id"]]
        if r["method"] != b["method"] or r["path"] != b["path"] \
                or r["query"] != b["query"] or r["body"] != b["body"]:
            sys.exit(f"integrity: non-cookie difference in {r['id']}")
        hb = dict(b["headers"]); hb.pop("cookie", None)
        hr = dict(r["headers"]); hr.pop("cookie", None)
        if hb != hr:
            sys.exit(f"integrity: header difference in {r['id']}")
        if hr.get("authorization") == "[DROPPED]" and \
                r["headers"].get("authorization") != "[DROPPED]":
            sys.exit(f"integrity: authorization restored in {r['id']}")
    print("integrity check passed: only cookie values differ")


if __name__ == "__main__":
    main()
