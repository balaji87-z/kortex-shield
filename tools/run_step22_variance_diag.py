#!/usr/bin/env python3
"""Step-22 DIAGNOSTIC C (rule 34): replay a few requests many times and count
the statuses each one gets. A request that is identical every time should get
one status and one set of matched rules; the parity runs showed 3 ids whose
logged rule-id set differs between replays.

Synthetic requests (written for this probe, no external data):
  syn-chain          JSON {"filter":"color=blue","note":"1=1"}
                     CRS 942130 (PL2) captures both sides of "x=y" from each
                     value and a chained rule compares the two captures; both
                     values match the regex, only "1=1" is a tautology
  syn-chain-rev      the same two members in the other order
  syn-chain-single   JSON {"note":"1=1"}                     (control)
  syn-dup            urlencoded, the key "tag" twice: "hello" and an XSS
                     canary, plus eight other keys
  syn-dup-single     the same without the duplicate "hello"   (control)
Extra samples (for example two benign-wcp ids, read from a local manifest
that is never committed) can be added with --manifest.

Requests are built by kortex_eval.runner.send_one, as in every replay run.
Never produces a baseline or parity number. Local testbed only (rule 6).

Usage: run_step22_variance_diag.py --base-url URL --out FILE [--reps 200]
           [--manifest FILE] [--block-marker REGEX]
"""
import argparse, collections, json, os, re, sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from kortex_eval import manifest, runner  # noqa: E402

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36")
XSS = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
OTHERS = "&a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8"
SYNTHETIC = [
    ("syn-chain", '{"filter":"color=blue","note":"1=1"}', "application/json"),
    ("syn-chain-rev", '{"note":"1=1","filter":"color=blue"}', "application/json"),
    ("syn-chain-single", '{"note":"1=1"}', "application/json"),
    ("syn-dup", "tag=hello&tag=" + XSS + OTHERS, "application/x-www-form-urlencoded"),
    ("syn-dup-single", "tag=" + XSS + OTHERS, "application/x-www-form-urlencoded"),
]


def synthetic_samples():
    return [manifest.Sample(id=sid, label="attack", family="diagnostic", source="step22-variance-diag",
                            method="POST", path="/", query="", body=body, content_type=ct)
            for sid, body, ct in SYNTHETIC]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--reps", type=int, default=200)
    ap.add_argument("--manifest")
    ap.add_argument("--block-marker", default="")
    args = ap.parse_args()
    u = urlsplit(args.base_url)
    samples = synthetic_samples() + (manifest.load(args.manifest) if args.manifest else [])
    marker = re.compile(args.block_marker) if args.block_marker else None
    status = {s.id: collections.Counter() for s in samples}
    for _ in range(args.reps):
        for s in samples:
            row = runner.send_one(s, u.hostname, u.port or 80, 15, 403, marker, UA)
            status[s.id][str(row["status"]) if row["error"] is None else "error:" + row["error_class"]] += 1
    out = {"base_url": args.base_url, "reps": args.reps,
           "status_counts": {k: dict(sorted(v.items())) for k, v in status.items()}}
    with open(args.out, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    for k, v in out["status_counts"].items():
        print(f"   {k}: statuses {v}")


if __name__ == "__main__":
    main()
