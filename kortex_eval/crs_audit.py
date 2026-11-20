"""Correlate CRS audit-log transactions with sample ids.

The audit JSON carries the request headers in ``transaction.request.headers``
(a name -> value map), verified against the real samples in docs/samples/.
The runner sends ``X-Kortex-Sample-Id`` on every request, so each audit
transaction can be attributed to a sample by that header. No other
correlation method is used.

Per sample id the parser reports, using only fields present in the real
samples: matched rule IDs, messages, severities, and the inbound anomaly
score. Two score readings are reported per entry:

- ``inbound_score_from_949110``: parsed from the 949110 message text
  ("Inbound Anomaly Score Exceeded (Total Score: N)").
- ``inbound_score_from_severities``: sum of per-rule weights over the logged
  messages (critical=5, error=4, warning=3, notice=2), using the numeric
  severity field of the audit entry (verified against the real samples:
  "2" = CRITICAL, "0" = EMERGENCY for 949110 itself, which has no weight).

These can disagree: see docs/samples/crs-log-trav02.txt - rule 930100 scored
twice (matched REQUEST_URI_RAW and ARGS:q) but logged one message, so the
severity sum (25) undercounts the engine total (30). ``score_mismatch``
records whether the two readings differ.

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

# ModSecurity numeric severity -> anomaly-score weight (CRS default:
# critical_anomaly_score=5, error=4, warning=3, notice=2).
# Verified in the real samples: attack rules carry severity "2" (CRITICAL),
# the 949110 evaluation rule carries "0" (EMERGENCY, no weight).
SEVERITY_WEIGHTS = {
    "2": 5, "critical": 5,
    "3": 4, "error": 4,
    "4": 3, "warning": 3,
    "5": 2, "notice": 2,
}


def _sample_id(headers: dict) -> str | None:
    """Sample id from the request headers of an audit transaction.

    Container audit logs keep the exact-cased string form
    ("X-Kortex-Sample-Id": "sqli-02"); the engine skeleton's Coraza audit
    lowercases header names and stores list values
    ("x-kortex-sample-id": ["sqli-02"]). Both must attribute.
    """
    value = headers.get(SAMPLE_ID_HEADER)
    if value is None:
        value = headers.get(SAMPLE_ID_HEADER.lower())
    if isinstance(value, list):
        value = value[0] if value else None
    return value


class AuditError(ValueError):
    pass


# Engine-skeleton (Coraza v3 library) audit dialect: messages carry an empty
# "message" field and the rule id/msg/severity as bracketed fields inside
# "error_message". Container connectors put the same fields in structured
# "message"/"details". Both dialects must attribute (see tests).
_ENGINE_ID_RE = re.compile(r'\[id "(\d+)"\]')
_ENGINE_MSG_RE = re.compile(r'\[msg "([^"]*)"\]')
_ENGINE_SEV_RE = re.compile(r'\[severity "([^"]*)"\]')


def parse_line(line: str) -> dict | None:
    """Parse one audit-log line. Returns None for non-audit lines."""
    stripped = line.strip()
    if not stripped.startswith('{"transaction":'):
        return None
    try:
        doc = json.loads(stripped)
        txn = doc["transaction"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise AuditError(f"malformed audit line: {exc}") from exc

    headers = txn.get("request", {}).get("headers", {}) or {}
    # container dialect: messages inside transaction; engine dialect: top level
    messages = txn.get("messages")
    if messages is None:
        messages = doc.get("messages") or []
    rules = []
    score_from_949110 = None
    score_from_severities = 0
    for m in messages:
        details = m.get("details", {}) or {}
        rule_id = details.get("ruleId")
        message_text = m.get("message")
        severity = details.get("severity")
        if rule_id is None and m.get("error_message"):
            em = m["error_message"]
            id_match = _ENGINE_ID_RE.search(em)
            if id_match:
                rule_id = id_match.group(1)
            msg_match = _ENGINE_MSG_RE.search(em)
            if msg_match:
                message_text = msg_match.group(1)
            sev_match = _ENGINE_SEV_RE.search(em)
            if sev_match:
                severity = sev_match.group(1)
        if not message_text and m.get("error_message"):
            # score fallback: 949110's total score is in the error text
            message_text = m["error_message"]
        rule = {
            "id": rule_id,
            "message": message_text,
            "severity": severity,
        }
        rules.append(rule)
        score_from_severities += SEVERITY_WEIGHTS.get(str(severity).lower(), 0)
        if rule_id == "949110":
            match = _SCORE_RE.search(message_text or "")
            if match:
                score_from_949110 = int(match.group(1))

    return {
        "sample_id": _sample_id(headers),
        "time_stamp": txn.get("time_stamp"),
        "method": txn.get("request", {}).get("method"),
        "uri": txn.get("request", {}).get("uri"),
        "status": txn.get("response", {}).get("http_code"),
        "engine": txn.get("producer", {}).get("secrules_engine"),
        "rules": rules,
        "inbound_score_from_949110": score_from_949110,
        "inbound_score_from_severities": score_from_severities,
        "score_mismatch": (
            score_from_949110 is not None and score_from_949110 != score_from_severities
        ),
    }


def parse_logs(text: str) -> list[dict]:
    """Parse a docker-logs capture into audit entries, in file order.

    Rule 13 (capture hygiene): any line that starts with {"transaction" but
    cannot be parsed is a capture defect, never silently skipped. Raises
    AuditError listing how many such lines exist (and their line numbers).
    """
    entries = []
    bad: list[int] = []
    # Audit entries are newline-delimited. str.splitlines() ALSO splits on
    # U+0085/U+2028/U+2029, which occur unescaped inside JSON string values
    # (recorded request bodies), splitting a valid {"transaction"} line in
    # half and wrongly rejecting the capture (step-17 T4 harness bug;
    # regression test in tests/test_crs_audit.py). Split on \n only.
    for lineno, raw in enumerate(text.split("\n"), 1):
        line = raw[:-1] if raw.endswith("\r") else raw
        if not line.strip().startswith('{"transaction":'):
            continue
        try:
            entry = parse_line(line)
        except AuditError:
            bad.append(lineno)
            continue
        if entry is not None:
            entries.append(entry)
    if bad:
        raise AuditError(
            f"{len(bad)} unparseable audit line(s) starting with {{\"transaction\" "
            f"at line(s) {bad[:10]}{'...' if len(bad) > 10 else ''} - capture is corrupt; "
            "refusing to emit a partial result (rule 13)"
        )
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
