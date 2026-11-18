#!/usr/bin/env python3
"""Build data/benign-wcp-v0 from the openappsec WCP legitimate zip.

Implements docs/plan-benign-wcp-v0.md exactly (preregistered, seed 0).
Streams the zip twice; never extracts it to disk; keeps memory low by never
holding request bodies (pass 1 stores only content hashes and indices).
"""

import hashlib
import json
import random
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

ZIP_PATH = Path("data/external/legitimate.zip")
OUT_DIR = Path("data/benign-wcp-v0")
WCP_COMMIT = "8ec8263eebba76816601f7c7052f8ffb83e31312"
SAMPLE_SIZE = 20_000
SITE_CAP = 400  # 2% of 20,000
SEED = 0
DROP_HEADERS = {"authorization", "proxy-authorization", "cookie"}
ASSET_EXT = re.compile(
    r"\.(js|css|png|jpe?g|gif|svg|woff2?|ttf|ico|json|xml|map|webp|mp4)$",
    re.I,
)
API_RE = re.compile(r"^/(api|rest)/|/(v1|v2)/|/graphql", re.I)


def endpoint_class(path: str) -> str:
    last = path.rstrip("/").rsplit("/", 1)[-1]
    if ASSET_EXT.search(last):
        return "static"
    if API_RE.search(path):
        return "api"
    return "page"


def content_key(method, path, query, content_type, body):
    raw = "\x00".join([method.upper(), path, query, content_type, body])
    return hashlib.sha1(raw.encode("utf-8", "surrogatepass")).digest()


def parse_record(r):
    """-> (method, path, query, content_type, body, headers)"""
    method = r["method"].upper()
    path, _, query = r["url"].partition("?")
    headers = r.get("headers", {})
    ct = ""
    for k, v in headers.items():
        if k.lower() == "content-type":
            ct = v
            break
    body = r.get("data", "") or ""
    return method, path, query, ct, body, headers


def main():
    if not ZIP_PATH.exists():
        sys.exit(f"missing {ZIP_PATH}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    z = zipfile.ZipFile(ZIP_PATH)
    names = sorted(n for n in z.namelist() if n.endswith(".json"))

    # ---- pass 1: dedupe, keep only hashes + first-occurrence indices ----
    seen = set()
    strata = {}   # file -> list of global indices (first occurrences, in order)
    g = 0
    for fi, name in enumerate(names):
        data = json.load(z.open(name))
        bucket = strata.setdefault(name, [])
        for r in data:
            method, path, query, ct, body, _h = parse_record(r)
            key = content_key(method, path, query, ct, body)
            if key not in seen:
                seen.add(key)
                bucket.append(g)
            g += 1
        if (fi + 1) % 100 == 0:
            print(f"pass1: {fi+1}/{len(names)} files, g={g}, "
                  f"distinct={len(seen)}", flush=True)
    total_scanned = g
    dropped_dups = total_scanned - len(seen)
    print(f"scanned {total_scanned}; distinct {len(seen)}; "
          f"duplicate tuples dropped {dropped_dups}", flush=True)

    # ---- allocation: proportional, min 1, cap 400, redistribute ----
    nonempty = sorted(s for s in strata if strata[s])
    counts = {s: len(strata[s]) for s in nonempty}
    alloc = {s: 0 for s in nonempty}
    remaining = SAMPLE_SIZE
    for _ in range(100):
        if remaining <= 0:
            break
        open_strata = [s for s in nonempty
                       if alloc[s] < min(SITE_CAP, counts[s])]
        tot = sum(counts[s] for s in open_strata)
        if tot == 0:
            break
        added = 0
        for s in open_strata:
            give = int(counts[s] / tot * remaining)
            give = min(give, min(SITE_CAP, counts[s]) - alloc[s],
                       remaining - added)
            if give > 0:
                alloc[s] += give
                added += give
        if added == 0:
            for s in open_strata:
                if remaining <= 0:
                    break
                alloc[s] += 1
                remaining -= 1
                added += 1
            if added == 0:
                break
        remaining -= added
    under = SAMPLE_SIZE - sum(alloc.values())
    if under > 0:
        sys.exit(f"allocation short by {under}")
    print(f"allocation done; max per site {max(alloc.values())} "
          f"(cap {SITE_CAP}); sites used {sum(1 for v in alloc.values() if v)}",
          flush=True)

    # ---- sample positions within each stratum (seed 0) ----
    rng = random.Random(SEED)
    chosen_global = set()
    plan = {}
    ordinal = {}  # file -> running ordinal of first occurrences (dedup order)
    for s in nonempty:
        k = alloc[s]
        if k == 0:
            continue
        positions = range(len(strata[s]))
        pick = sorted(rng.sample(list(positions), k))
        plan[s] = [strata[s][p] for p in pick]
        chosen_global.update(plan[s])
    print(f"sampled {len(chosen_global)} global indices", flush=True)

    # ---- pass 2: emit chosen records ----
    manifest_lines = []
    annotation_lines = []
    cred_counts = Counter()
    hosts = Counter()
    classes = Counter()
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    key_qs = re.compile(
        r"(?i)(api[_-]?key|token|secret|password|apikey|access[_-]?token)=[^&\s]+")
    seen2 = set()
    g = 0
    for fi, name in enumerate(names):
        if not any(strata[name]):
            g += len(json.load(z.open(name)))
            continue
        data = json.load(z.open(name))
        for r in data:
            if g in chosen_global:
                method, path, query, ct, body, headers = parse_record(r)
                key = content_key(method, path, query, ct, body)
                # safety: must be a first occurrence
                if key in seen2:
                    sys.exit(f"internal: g={g} chosen but not first occurrence")
                seen2.add(key)
                headers = dict(headers)
                for k in list(headers):
                    lk = k.lower()
                    if lk in DROP_HEADERS:
                        cred_counts[f"{lk} header value dropped"] += 1
                        headers[k] = "[DROPPED]"
                if email_re.search(query):
                    cred_counts["email-like string in URL query"] += 1
                if any(email_re.search(str(v)) for v in headers.values()):
                    cred_counts["email-like string in a header value"] += 1
                if email_re.search(body):
                    cred_counts["email-like string in body"] += 1
                if key_qs.search(query):
                    cred_counts["API-key-like query parameter"] += 1
                host = ""
                for k, v in headers.items():
                    if k.lower() == "host":
                        host = v
                        break
                kh = hashlib.sha1(
                    "\x00".join([method, path, query, ct, body])
                    .encode("utf-8", "surrogatepass")).hexdigest()
                sid = f"wcp-{kh[:12]}"
                source = f"openappsec-wcp@{WCP_COMMIT}:{name}:{g}"
                manifest_lines.append(json.dumps({
                    "id": sid, "label": "benign", "family": "benign",
                    "source": source, "method": method, "path": path,
                    "query": query, "body": body, "content_type": ct,
                    "headers": headers,
                }, ensure_ascii=False))
                ep = f"{method} {path}" + (f"?{query}" if query else "")
                ec = endpoint_class(path)
                annotation_lines.append(json.dumps({
                    "id": sid, "endpoint": ep, "host": host,
                    "endpoint_class": ec, "site_file": name,
                    "global_index": g,
                }, ensure_ascii=False))
                hosts[host] += 1
                classes[ec] += 1
            g += 1
        if (fi + 1) % 100 == 0:
            print(f"pass2: {fi+1}/{len(names)} files, "
                  f"emitted={len(manifest_lines)}", flush=True)

    if len(manifest_lines) != SAMPLE_SIZE:
        sys.exit(f"emitted {len(manifest_lines)} != {SAMPLE_SIZE}")
    ids = [json.loads(l)["id"] for l in manifest_lines]
    if len(ids) != len(set(ids)):
        sys.exit("duplicate ids produced")

    (OUT_DIR / "manifest.jsonl").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8")
    (OUT_DIR / "annotations.jsonl").write_text(
        "\n".join(annotation_lines) + "\n", encoding="utf-8")
    (OUT_DIR / "sample-plan.json").write_text(
        json.dumps({"seed": SEED, "sample_size": SAMPLE_SIZE,
                    "site_cap": SITE_CAP, "allocation": alloc,
                    "strata": plan}, indent=1), encoding="utf-8")
    sha = hashlib.sha256(
        (OUT_DIR / "manifest.jsonl").read_bytes()).hexdigest()
    (OUT_DIR / "MANIFEST.sha256").write_text(sha + "\n", encoding="utf-8")
    print("manifest sha256:", sha, flush=True)
    print("credential scan:", dict(cred_counts), flush=True)
    print("distinct hosts in sample:", len(hosts), flush=True)
    print("top hosts:", hosts.most_common(5), flush=True)
    print("endpoint classes:", dict(classes), flush=True)
    print("BUILD OK", flush=True)


if __name__ == "__main__":
    main()
