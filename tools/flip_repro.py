#!/usr/bin/env python3
"""Step-19 T1: pass-through flip reproducer.

Replays a fixed set of would-block samples (GET, query-based 942370+942430
matches) in a fixed order for N rounds against a running engine, records per
round which samples passed, and prints flips/rounds.

Usage: flip_repro.py --base-url http://127.0.0.1:PORT --rounds 500 \
         [--pl 2] [--out /tmp/flip-rounds.jsonl]
Samples (fixed order): wcp-62cd1bd36bf7, wcp-b6f2246ef4b8 (same-path
neighbours). Both block on the query at PL2 (942370/942430 are
paranoia-level/2 rules). At PL1 they match nothing and pass through to the
stub (200) on coraza v3.7.0 AND v3.8.1 alike (step-20 probe: 0 audit lines,
pass event), so a PL1 run reports rounds=flips trivially - the flip metric
is only meaningful at PL2.

Exit code 0 always; results on stdout and --out jsonl (one line per round).
"""
import argparse
import http.client
import json
import sys
import time

SAMPLES = ["wcp-62cd1bd36bf7", "wcp-b6f2246ef4b8"]
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36")


def load_samples(manifest):
    want = set(SAMPLES)
    out = {}
    with open(manifest) as f:
        for line in f:
            s = json.loads(line)
            if s["id"] in want:
                out[s["id"]] = s
    missing = want - set(out)
    if missing:
        sys.exit(f"missing samples in manifest: {sorted(missing)}")
    return [out[i] for i in SAMPLES]


def send(s, host, port, timeout):
    hdrs = {"Accept-Encoding": "identity",
            "X-Kortex-Sample-Id": s["id"] + "-fliprepro"}
    for k, v in (s.get("headers") or {}).items():
        if k.lower() in ("host", "content-length", "x-kortex-sample-id"):
            continue
        hdrs[k] = v
    if not any(k.lower() == "user-agent" for k in hdrs):
        hdrs["User-Agent"] = UA
    body = (s.get("body") or "").encode("utf-8", "surrogatepass")
    if body:
        if s.get("content_type"):
            hdrs.setdefault("Content-Type", s["content_type"])
        hdrs["Content-Length"] = str(len(body))
    c = http.client.HTTPConnection(host, port, timeout=timeout)
    t0 = time.monotonic()
    try:
        c.request(s["method"].upper(),
                  s["path"] + (("?" + s["query"]) if s.get("query") else ""),
                  body=body or None, headers=hdrs)
        r = c.getresponse()
        r.read()
        status = r.status
    except Exception as e:  # noqa: BLE001 - record any transport error
        status = f"error:{type(e).__name__}"
    finally:
        c.close()
    return status, (time.monotonic() - t0) * 1000.0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://127.0.0.1:8090")
    ap.add_argument("--manifest", default="data/benign-wcp-v0/manifest.jsonl")
    ap.add_argument("--rounds", type=int, default=500)
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    host = a.base_url.split("//", 1)[1].split(":")[0]
    port = int(a.base_url.rsplit(":", 1)[1])
    samples = load_samples(a.manifest)
    fh = open(a.out, "w") if a.out else None
    flip_rounds = 0
    per_sample_flips = {sid: 0 for sid in SAMPLES}
    t0 = time.monotonic()
    for rnd in range(1, a.rounds + 1):
        passed = []
        row = {"round": rnd}
        for s in samples:
            status, ms = send(s, host, port, 30)
            row[s["id"]] = {"status": str(status), "ms": round(ms, 1)}
            if status != 403:
                passed.append(s["id"])
                per_sample_flips[s["id"]] += 1
        row["passed"] = passed
        if passed:
            flip_rounds += 1
            print(f"round {rnd}: PASSED {passed} "
                  f"{[row[i] for i in passed]}", flush=True)
        if fh:
            fh.write(json.dumps(row) + "\n")
            fh.flush()
    dt = time.monotonic() - t0
    print(f"rounds={a.rounds} flip_rounds={flip_rounds} "
          f"flips/round={flip_rounds / a.rounds:.4f} "
          f"per_sample={per_sample_flips} wall_s={dt:.1f}")
    if fh:
        fh.close()


if __name__ == "__main__":
    main()
