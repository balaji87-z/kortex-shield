"""Outcome classification: one verdict per sample from runner + audit evidence.

The verdict we measure is the WAF's decision, not the target app's status
(instructor decision, step-03). Classification per sample:

    error            the request failed (timeout / connection error)
    waf_block_outbound  (blocking mode) the response errored with an
                     incomplete read / reset, the audit entry contains rule
                     959100 (outbound threshold), and the inbound score is
                     below the threshold — the WAF blocked the OUTBOUND side
                     and cut the response (see docs/block-discriminator.md)
    waf_block        (blocking mode) runner says blocked AND audit score >= threshold
    waf_would_block  (detection mode) audit score >= threshold and nothing was blocked
    waf_pass         reached the engine, score below threshold or no rule match
    proxy_reject     not blocked, nginx error-page marker present, status != 403,
                     and no audit entry (nginx refused it before the engine)
    inconsistent     any other combination (e.g. blocked without a qualifying
                     audit score); every inconsistent sample is listed

Inputs: the runner's responses.jsonl and the crs_audit output JSONL.
Rows in either file without a counterpart are still classified (audit entries
without a sample id or response row cannot be attributed and are reported).
"""
from __future__ import annotations

import argparse
import json
import sys

THRESHOLD_DEFAULT = 5

_OUTBOUND_ERROR_MARKERS = (
    "incompleteread", "connectionreset", "remotedisconnected", "badstatusline",
)


def _outbound_cut(response: dict, audit: dict | None, threshold: int) -> bool:
    """True when an errored response is an outbound block that cut the stream.

    Definition (docs/block-discriminator.md, step-06 T3): error is an
    incomplete read / reset, audit contains rule 959100, inbound score below
    the threshold.
    """
    err = (response.get("error") or "")
    if not any(m in err.lower() for m in _OUTBOUND_ERROR_MARKERS):
        return False
    if not audit:
        return False
    rule_ids = {str(rule.get("id")) for rule in audit.get("rules", [])}
    if "959100" not in rule_ids:
        return False
    score = audit.get("inbound_score_from_949110")
    return score is None or score < threshold


class OutcomeError(ValueError):
    pass


def classify(
    response: dict | None,
    audit: dict | None,
    engine_mode: str,
    threshold: int = THRESHOLD_DEFAULT,
) -> str:
    """Classify one sample from its response row and audit entry (either may be None)."""
    if engine_mode not in ("blocking", "detection"):
        raise OutcomeError(f"engine-mode must be blocking|detection, got {engine_mode!r}")

    if response is not None and response.get("error") is not None:
        if engine_mode == "blocking" and _outbound_cut(response, audit, threshold):
            return "waf_block_outbound"
        return "error"

    score = audit.get("inbound_score_from_949110") if audit else None
    scored = score is not None and score >= threshold

    if response is None:
        # audit entry with no response row: cannot have been sent by this run
        return "inconsistent"

    if engine_mode == "blocking":
        if response.get("blocked"):
            return "waf_block" if scored else "inconsistent"
        # Step-11 T3: engine deny with a non-403 status (e.g. the image's
        # body-parser rules 200002/200007 deny with status 400). Definition:
        # docs/block-discriminator.md. Not blocked by the 403 discriminator,
        # status 4xx/5xx, audit entry with a deny rule (id starting '2').
        status = response.get("status")
        if (
            status is not None and 400 <= status < 600
            and audit is not None
            and any(str(rule.get("id", "")).startswith("2")
                    for rule in audit.get("rules", []))
        ):
            return "waf_deny_status"
        # not blocked
        if (
            not response.get("body_marker")
            and response.get("status") != 403
        ):
            return "waf_pass"
        if response.get("body_marker") and response.get("status") != 403 and audit is None:
            return "proxy_reject"
        return "inconsistent"
    else:  # detection
        if response.get("blocked"):
            return "inconsistent"  # nothing should be blocked in detection mode
        if scored:
            return "waf_would_block"
        if (
            not response.get("body_marker")
            and response.get("status") != 403
        ):
            return "waf_pass"
        if response.get("body_marker") and response.get("status") != 403 and audit is None:
            return "proxy_reject"
        return "inconsistent"


def classify_all(
    responses: list[dict],
    audit_entries: list[dict],
    engine_mode: str,
    threshold: int = THRESHOLD_DEFAULT,
) -> tuple[list[dict], list[dict]]:
    """Classify every response row. Returns (rows, unattributed_audit_entries)."""
    by_id = {r["id"]: r for r in responses if r.get("id") is not None}
    rows = []
    unattributed = []
    for entry in audit_entries:
        sid = entry.get("sample_id")
        if sid is None or sid not in by_id:
            unattributed.append(entry)
    for r in responses:
        audit = next((e for e in audit_entries if e.get("sample_id") == r["id"]), None)
        rows.append({
            "id": r["id"],
            "status": r.get("status"),
            "outcome": classify(r, audit, engine_mode, threshold),
            "audit_score": audit.get("inbound_score_from_949110") if audit else None,
            "audit_score_from_severities": audit.get("inbound_score_from_severities") if audit else None,
            "score_mismatch": audit.get("score_mismatch") if audit else None,
            "rule_ids": [rule.get("id") for rule in audit["rules"]] if audit else [],
        })
    return rows, unattributed


def main() -> int:
    ap = argparse.ArgumentParser(description="Classify per-sample outcomes from runner + audit evidence.")
    ap.add_argument("--responses", required=True, help="runner responses.jsonl")
    ap.add_argument("--audit", required=True, help="crs_audit output JSONL")
    ap.add_argument("--out", required=True, help="output JSONL path")
    ap.add_argument("--engine-mode", choices=("blocking", "detection"), required=True)
    ap.add_argument("--threshold", type=int, default=THRESHOLD_DEFAULT)
    args = ap.parse_args()

    try:
        responses = [json.loads(l) for l in open(args.responses, encoding="utf-8") if l.strip()]
        audit_entries = [json.loads(l) for l in open(args.audit, encoding="utf-8") if l.strip()]
    except (OSError, json.JSONDecodeError) as exc:
        print(f"outcome: {exc}", file=sys.stderr)
        return 2

    rows, unattributed = classify_all(responses, audit_entries, args.engine_mode, args.threshold)

    with open(args.out, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    counts: dict[str, int] = {}
    for row in rows:
        counts[row["outcome"]] = counts.get(row["outcome"], 0) + 1
    for outcome in sorted(counts):
        print(f"{outcome}: {counts[outcome]}")
    inconsistent = [r["id"] for r in rows if r["outcome"] == "inconsistent"]
    if inconsistent:
        print("inconsistent samples: " + ", ".join(inconsistent), file=sys.stderr)
    if unattributed:
        print(f"warning: {len(unattributed)} audit entr(ies) could not be attributed to a sample id",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
