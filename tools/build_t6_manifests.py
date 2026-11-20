#!/usr/bin/env python3
"""Step-13 T6 (DIAGNOSTIC): build the two scratch manifests — as-recorded and
Content-Type -> application/x-www-form-urlencoded (body unchanged)."""
import json

ids = [l.strip() for l in open("out/step13-t6/picked.txt") if l.strip()]
rows = {json.loads(l)["id"]: json.loads(l)
        for l in open("data/benign-wcp-v0/manifest.jsonl")}

for variant in ("recorded", "urlenc"):
    with open(f"out/step13-t6/manifest-{variant}.jsonl", "w") as f:
        for i in ids:
            r = rows[i]
            r = dict(r)
            h = {k: v for k, v in r["headers"].items()
                 if k.lower() != "content-type"}
            if variant == "urlenc":
                h["Content-Type"] = "application/x-www-form-urlencoded"
                r["content_type"] = "application/x-www-form-urlencoded"
            else:
                if r["content_type"]:
                    h["Content-Type"] = r["content_type"]
            r["headers"] = h
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
print("built", len(ids), "x 2 manifests")
