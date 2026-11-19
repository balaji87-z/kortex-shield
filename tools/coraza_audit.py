#!/usr/bin/env python3
"""Convert a Coraza JSON audit log to the kortex_eval audit.jsonl schema.

Coraza format (docs/samples/coraza-log-*.txt): one JSON object per line,
{"transaction": {...}, "messages": [...]}. Rule IDs are extracted from
messages[].error_message `[id "N"]`; the message text from `[msg "..."]`;
severity from `[severity "..."]`.

Exit code 1 if any line that starts with {"transaction" cannot be parsed
(same contract as kortex_eval.crs_audit, rule 13).
"""

import json
import re
import sys

ID_RE = re.compile(r'\[id "(\d+)"\]')
MSG_RE = re.compile(r'\[msg "([^"]*)"\]')
SEV_RE = re.compile(r'\[severity "([^"]*)"\]')


def parse_line(line: str):
    e = json.loads(line)
    t = e["transaction"]
    headers = {k.lower(): v for k, v in t["request"].get("headers", {}).items()}
    sid = (headers.get("x-kortex-sample-id") or [""])[0]
    rules = []
    for m in e.get("messages", []) or []:
        text = (m.get("error_message") or "") + " " + (m.get("message") or "")
        ids = ID_RE.findall(text)
        if not ids:
            continue
        msg = MSG_RE.search(text)
        sev = SEV_RE.search(text)
        for rid in ids:
            rules.append({"id": rid,
                          "message": msg.group(1) if msg else "",
                          "severity": sev.group(1) if sev else ""})
    return {
        "sample_id": sid,
        "time_stamp": t.get("timestamp", ""),
        "method": t["request"].get("method", ""),
        "uri": t["request"].get("uri", ""),
        "status": t["response"].get("status"),
        "engine": t.get("producer", {}).get("rule_engine", ""),
        "rules": rules,
        "inbound_score_from_949110": next(
            (int(m.group(1)) for r in rules if r["id"] == "949110"
             for m in [re.search(r"Total Score: (\d+)", r["message"])] if m),
            None,
        ),
    }


def main():
    src, dst = sys.argv[2], sys.argv[4]  # --logs X --out Y
    n_bad = 0
    n_ok = 0
    with open(dst, "w") as out:
        for line in open(src):
            line = line.strip()
            if not line:
                continue
            if line.startswith('{"transaction"'):
                try:
                    out.write(json.dumps(parse_line(line)) + "\n")
                    n_ok += 1
                except Exception as exc:  # noqa: BLE001
                    n_bad += 1
                    print(f"coraza_audit: unparseable line: {exc}", file=sys.stderr)
    print(f"coraza_audit: {n_ok} audit entr(ies) -> {dst}")
    if n_bad:
        print(f"coraza_audit: {n_bad} unparseable transaction line(s)", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
