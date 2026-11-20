#!/usr/bin/env python3
"""Step-12 T3: forensics on the 17 status-400 samples (200002/200007 denies).

For each sample:
  1. stored manifest body string vs the ORIGINAL zip record body string
     (dataset fidelity - did the build alter anything?);
  2. what the runner puts on the wire: body.encode('utf-8','surrogatepass') -
     its length, and whether the stored string is pure ASCII / contains
     non-ASCII / contains lone surrogates (lone surrogates mean the ORIGINAL
     bytes were not valid UTF-8 and the re-encode does NOT restore them, i.e.
     the replayed bytes differ from the original bytes);
  3. does the body parse as its declared content type (JSON / form-urlencoded);
  4. cause class: replay_artifact | malformed_original | unknown.
Counts only; no body contents are printed (rule 25).
"""
import json
import sys
import zipfile
from pathlib import Path
from urllib.parse import parse_qsl

ZIP_PATH = Path("data/external/legitimate.zip")
IDS = [
    "wcp-2600366d4ecb", "wcp-2895d7e869c5", "wcp-2ec9a3436296", "wcp-376b3b37ef12",
    "wcp-384ae4521001", "wcp-4be3821497ed", "wcp-62b3375148b4", "wcp-672911deadaa",
    "wcp-71461e371348", "wcp-96a594e2ae57", "wcp-9958e07b65ec", "wcp-a4a6f9fb8303",
    "wcp-aec2a2311eb9", "wcp-c7970d727861", "wcp-decac4aed757", "wcp-ef1d0324c278",
    "wcp-f78d7afa532c",
]


def has_lone_surrogates(s: str) -> bool:
    try:
        s.encode("utf-8", "strict")
        return False
    except UnicodeEncodeError:
        return True


def classify(row, zip_body):
    body = row["body"]
    ct = (row.get("content_type") or "").split(";")[0].strip().lower()
    notes = []
    if body != zip_body:
        notes.append("STORED!=ZIP")
    nonascii = any(ord(c) > 127 for c in body)
    lone = has_lone_surrogates(body)
    sent = len(body.encode("utf-8", "surrogatepass"))
    reclen = row.get("headers", {}).get("content-length") or row.get("headers", {}).get("Content-Length")
    reclen = int(reclen) if reclen and str(reclen).isdigit() else None
    cl_match = (reclen == sent)
    # parse check
    enc = row.get("headers", {}).get("content-encoding") or row.get("headers", {}).get("Content-Encoding")
    parses = None
    if ct == "application/json":
        try:
            json.loads(body)
            parses = True
        except Exception:
            parses = False
    elif ct == "application/x-www-form-urlencoded":
        try:
            parse_qsl(body, strict_parsing=False)
            parses = True
        except Exception:
            parses = False
    # class
    if lone or notes or enc:
        # content-encoding recorded (gzip): the dataset stored the DECOMPRESSED
        # body but the runner sends the header verbatim -> engine decode fails.
        # Replay artifact, proven by recorded CL != sent length for every such
        # sample here.
        cls = "replay_artifact"
    elif parses is False and cl_match:
        # bytes on the wire match the recorded original length and the stored
        # string round-trips from the zip -> the deny reflects the original
        # body content (not valid for its declared type)
        cls = "malformed_original"
    elif parses is False:
        cls = "unknown"  # non-parsing AND byte length differs from recorded
    elif ct == "application/json" and parses:
        # valid JSON: 200007 (argument count) or body limit -> neither replay nor malformed
        cls = "unknown"
    else:
        cls = "unknown"
    return cls, notes, nonascii, lone, parses, cl_match, reclen, sent, enc


def main():
    rows = {}
    for l in open("data/benign-wcp-v0/manifest.jsonl"):
        r = json.loads(l)
        if r["id"] in IDS:
            rows[r["id"]] = r
    # step-11 run evidence: status + rules
    run = {}
    for l in open("out/modsec-benign-wcp-v0-pl1-stub/outcomes.jsonl"):
        r = json.loads(l)
        if r["id"] in IDS:
            run[r["id"]] = (r["status"], r["outcome"], r["rule_ids"])
    # zip bodies
    want = {}
    for sid, r in rows.items():
        _tag, zname, gidx = r["source"].split(":")
        want[(zname, int(gidx))] = sid
    zipbodies = {}
    z = zipfile.ZipFile(ZIP_PATH)
    names = sorted(n for n in z.namelist() if n.endswith(".json"))
    g = 0
    for name in names:
        data = json.load(z.open(name))
        for n, gg in list(want.items()):
            if n[0] == name and n[1] - g < len(data):
                zipbodies[want[n]] = data[n[1] - g].get("data", "") or ""
        g += len(data)
    from collections import Counter
    classes = Counter()
    print(f"{'id':22} {'len(sent)':>9} {'CLrec':>7} {'CL==sent':>8} {'nonascii':>8} {'lone-surr':>9} {'parses':>7} {'stored==zip':>11} class  status/outcome")
    for sid in IDS:
        r = rows[sid]
        zb = zipbodies.get(sid, "<NOT FOUND>")
        cls, notes, nonascii, lone, parses, cl_match, reclen, sent, enc = classify(r, zb)
        classes[cls] += 1
        st, oc, rl = run.get(sid, ("?", "?", "?"))
        args = ""
        if "200007" in (rl if isinstance(rl, list) else []):
            try:
                def count(x):
                    if isinstance(x, dict):
                        return sum(count(v) for v in x.values()) + len(x)
                    if isinstance(x, list):
                        return sum(count(v) for v in x)
                    return 0
                args = f" json_members={count(json.loads(r['body']))}"
            except Exception:
                args = " json_members=<unparseable>"
        print(f"{sid:22} {sent:>9} {str(reclen):>7} {str(cl_match):>8} {str(nonascii):>8} {str(lone):>9} "
              f"{str(parses):>7} {str(r['body']==zb):>11} {cls:18} {st}/{oc} rules={rl}{args} enc={enc}")
    print("class counts:", dict(classes))


if __name__ == "__main__":
    main()
