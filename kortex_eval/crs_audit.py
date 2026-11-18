"""Correlate CRS audit-log transactions with sample ids.

The audit JSON carries the request headers in ``transaction.request.headers``
(a name -> value map), verified against the real samples in docs/samples/.
The runner sends ``X-Kortex-Sample-Id`` on every request, so each audit
transaction can be attributed to a sample by that header. No other
correlation method is used.

Per sample id the parser reports, using only fields present in the real
samples: matched rule IDs, messages, severities, and the inbound anomaly
score. The score is taken from the 949110 message text
("Inbound Anomaly Score Exceeded (Total Score: N)").

Input is a docker-logs capture: lines that start with {"transaction": are
audit entries; everything else (nginx access/error lines) is ignored.
"""
from __future__ import annotations

import argparse
import json
import re
import sys

SAMPLE_ID_HEADER = "X-Kortex-Sample-Id"
_SCORE_RE = re.compile(r"Total Score:\s*(\d+)")


class AuditError(ValueError):
    pass


def parse_line(line: str) -> dict | None:
    """Parse one audit-log line. Returns None for non-audit lines."""
    stripped = line.strip()
    if not stripped.startswith('{"transaction":'):
        return None
    try:
        txn = json.loads(stripped)["transaction"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise AuditError(f"malformed audit line: {exc}") from exc

    headers = txn.get("request", {}).get("headers", {}) or {}
    messages = txn.get("messages", []) or []
    rules = []
    score = None
    for m in messages:
        details = m.get("details", {}) or {}
        rule = {
            "id": details.get("ruleId"),
            "message": m.get("message"),
            "severity": details.get("severity"),
        }
        rules.append(rule)
        if details.get("ruleId") == "949110":
            match = _SCORE_RE.search(m.get("message", ""))
            if match:
                score = int(match.group(1))

    return {
        "sample_id": headers.get(SAMPLE_ID_HEADER),
        "time_stamp": txn.get("time_stamp"),
        "method": txn.get("request", {}).get("method"),
        "uri": txn.get("request", {}).get("uri"),
        "status": txn.get("response", {}).get("http_code"),
        "engine": txn.get("producer", {}).get("secrules_engine"),
        "rules": rules,
        "anomaly_score": score,
    }


def parse_logs(text: str) -> list[dict]:
    """Parse a docker-logs capture into audit entries, in file order."""
    entries = []
    for lineno, line in enumerate(text.splitlines(), 1):
        try:
            entry = parse_line(line)
        except AuditError as exc:
            raise AuditError(f"line {lineno}: {exc}") from exc
        if entry is not None:
            entries.append(entry)
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract per-sample CRS audit findings from a docker-logs file.")
    ap.add_argument("--logs", required=True, help="path to a docker logs capture file")
    ap.add_argument("--out", required=True, help="output JSONL path")
    args = ap.parse_args()

    try:
        entries = parse_logs(open(args.logs, encoding="utf-8", errors="replace").read())
    except OSError as exc:
        print(f"crs_audit: {exc}", file=sys.stderr)
        return 2
    except AuditError as exc:
        print(f"crs_audit: {exc}", file=sys.stderr)
        return 2

    with open(args.out, "w", encoding="utf-8") as fh:
        for entry in entries:
            fh.write(json.dumps(entry) + "\n")
    print(f"crs_audit: {len(entries)} audit entr(ies) -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
