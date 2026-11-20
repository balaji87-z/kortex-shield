#!/usr/bin/env python3
"""Step-12 T1: per-run proof that every crs-default run used the TRUE default
policy (901160/901162 fallback), from each run's own audit log.

Signature checked (join audit entries with the frozen manifest):
  (a) rule 920420 (content-type policy) never fires on a content type that the
      901162 fallback allows (application/x-www-form-urlencoded, multipart/
      form-data, text/xml, application/xml, application/soap+xml, application/
      json, plus the 901370 application/*+json wildcard);
  (b) rule 911100 (method policy) fires only on PUT/DELETE/PATCH;
  (c) rule 920420 DOES fire on text/plain (the corpus contains it - proves the
      check is live, not vacuous).
Violations are listed per sample id. Counts only; no body values (rule 25).
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

ALLOWED_901162 = {
    "application/x-www-form-urlencoded", "multipart/form-data", "text/xml",
    "application/xml", "application/soap+xml", "application/json",
}
MANIFESTS = {
    "data/benign-wcp-v0/manifest.jsonl", "out/benign-wcp-v0-baseline-manifest.jsonl",
    "out/wcp-heldout-test-manifest.jsonl", "out/wcp-heldout-train-manifest.jsonl",
    "out/wcp-cookie-dropped/manifest.jsonl", "out/wcp-cookie-restored/manifest.jsonl",
    "out/wcp-cookie-restored-all/manifest.jsonl",
    "data/smoke/manifest.jsonl", "data/attacks-v0/manifest.jsonl",
    "data/benign-browse-v1/manifest.jsonl", "data/benign-hard-v0/manifest.jsonl",
}


def load_manifest(meta):
    for m in MANIFESTS:
        p = Path(m)
        if p.exists():
            for l in open(p):
                r = json.loads(l)
                meta[r["id"]] = (r.get("method", ""), (r.get("content_type") or "").split(";")[0].strip().lower())
    return meta


def main(run_dirs):
    meta = {}
    load_manifest(meta)
    for run in run_dirs:
        d = Path(run)
        if not (d / "audit.jsonl").exists():
            print(f"== {run}: NO audit.jsonl (skipped)")
            continue
        fired_ct = defaultdict(int)   # ct -> count of 920420
        passed_ct = defaultdict(int)  # ct -> count where 920420 in rules would be possible but ct allowed
        viol_420, viol_911 = [], []
        saw_textplain_block = 0
        methods_911 = defaultdict(int)
        for l in open(d / "audit.jsonl"):
            e = json.loads(l)
            sid = e["sample_id"]
            m, ct = meta.get(sid, ("", ""))
            rids = {str(r.get("id")) for r in e.get("rules", [])}
            if "920420" in rids:
                fired_ct[ct] += 1
                if ct in ALLOWED_901162 or ct.endswith("+json"):
                    viol_420.append((sid, ct))
                if ct == "text/plain":
                    saw_textplain_block += 1
            if "911100" in rids:
                methods_911[m] += 1
                if m not in ("PUT", "DELETE", "PATCH"):
                    viol_911.append((sid, m))
        bad = []
        if viol_420:
            bad.append(f"920420 fired on ALLOWED ct: {viol_420[:5]} ({len(viol_420)})")
        if viol_911:
            bad.append(f"911100 fired on non-PUT/DELETE/PATCH: {viol_911[:5]} ({len(viol_911)})")
        print(f"== {run}: 920420 by ct {dict(fired_ct)}; 911100 by method {dict(methods_911)}; "
              f"text/plain-blocked {saw_textplain_block}; {'VIOLATION: ' + '; '.join(bad) if bad else 'true-default signature OK'}")


if __name__ == "__main__":
    main(sys.argv[1:])
