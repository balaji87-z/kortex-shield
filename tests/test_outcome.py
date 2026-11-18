"""Tests for kortex_eval.outcome: synthetic rows plus the real step-02 smoke data."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from kortex_eval import outcome

ROOT = Path(__file__).resolve().parent.parent
SMOKE = ROOT / "out" / "smoke-pl1-on"


def resp(id, status=200, blocked=False, error=None, body_marker=False):
    return {"id": id, "status": status, "elapsed_ms": 1.0, "blocked": blocked,
            "body_marker": body_marker, "error": error}


def audit(id, score, severities=None):
    return {"sample_id": id, "status": 403,
            "inbound_score_from_949110": score,
            "inbound_score_from_severities": severities if severities is not None else score,
            "score_mismatch": False,
            "rules": [{"id": "949110", "message": "x", "severity": "0"}]}


# ---------- synthetic ----------

def test_error_outcome():
    assert outcome.classify(resp("a", error="timeout"), audit("a", 20), "blocking") == "error"


def test_waf_block_requires_qualifying_score():
    assert outcome.classify(resp("a", 403, blocked=True, body_marker=True), audit("a", 20), "blocking") == "waf_block"
    # blocked but no qualifying audit score -> inconsistent
    assert outcome.classify(resp("b", 403, blocked=True, body_marker=True), None, "blocking") == "inconsistent"
    assert outcome.classify(resp("c", 403, blocked=True, body_marker=True), audit("c", 3), "blocking") == "inconsistent"


def test_waf_pass_below_threshold():
    assert outcome.classify(resp("a", 200), None, "blocking") == "waf_pass"
    assert outcome.classify(resp("b", 200), audit("b", 3), "blocking") == "waf_pass"
    assert outcome.classify(resp("c", 500), None, "blocking") == "waf_pass"  # target-own 500


def test_waf_would_block_in_detection_mode():
    assert outcome.classify(resp("a", 200), audit("a", 20), "detection") == "waf_would_block"
    assert outcome.classify(resp("b", 200), audit("b", 4), "detection") == "waf_pass"


def test_proxy_reject():
    # nginx refused before the engine: marker present, status != 403, no audit entry
    assert outcome.classify(resp("a", 400, body_marker=True), None, "blocking") == "proxy_reject"
    assert outcome.classify(resp("b", 400, body_marker=True), None, "detection") == "proxy_reject"


def test_blocked_in_detection_mode_is_inconsistent():
    assert outcome.classify(resp("a", 403, blocked=True, body_marker=True), audit("a", 20), "detection") == "inconsistent"


def test_audit_entry_without_response_row_is_inconsistent():
    rows, unattr = outcome.classify_all([], [audit("ghost", 20)], "blocking")
    assert unattr and unattr[0]["sample_id"] == "ghost"


def test_bad_engine_mode_raises():
    with pytest.raises(outcome.OutcomeError):
        outcome.classify(resp("a"), None, "on")


# ---------- real step-02 smoke data ----------

@pytest.mark.skipif(not (SMOKE / "responses.jsonl").exists(), reason="smoke run artifacts not present")
def test_real_smoke_expected_outcomes():
    responses = [json.loads(l) for l in open(SMOKE / "responses.jsonl", encoding="utf-8") if l.strip()]
    audit_entries = [json.loads(l) for l in open(SMOKE / "audit.jsonl", encoding="utf-8") if l.strip()]
    rows, _ = outcome.classify_all(responses, audit_entries, "blocking", threshold=5)
    by_id = {r["id"]: r["outcome"] for r in rows}
    # expected from step-02: trav-01 proxy_reject, whoami-01 waf_block, login-01 waf_pass
    assert by_id["trav-01"] == "proxy_reject"
    assert by_id["whoami-01"] == "waf_block"
    assert by_id["login-01"] == "waf_pass"
    # attacks that were blocked with qualifying scores
    for sid in ("sqli-01", "sqli-02", "xss-01", "xss-02", "trav-02"):
        assert by_id[sid] == "waf_block", sid
    # clean benign traffic
    for sid in ("home-01", "search-01", "js-01", "img-01"):
        assert by_id[sid] == "waf_pass", sid


@pytest.mark.skipif(not (SMOKE / "responses.jsonl").exists(), reason="smoke run artifacts not present")
def test_cli_on_real_smoke_data(tmp_path):
    out = tmp_path / "outcomes.jsonl"
    proc = subprocess.run(
        [sys.executable, "-m", "kortex_eval.outcome", "--responses", str(SMOKE / "responses.jsonl"),
         "--audit", str(SMOKE / "audit.jsonl"), "--out", str(out), "--engine-mode", "blocking"],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    rows = [json.loads(l) for l in open(out, encoding="utf-8") if l.strip()]
    assert len(rows) == 12
    counts = {}
    for r in rows:
        counts[r["outcome"]] = counts.get(r["outcome"], 0) + 1
    assert counts == {"waf_block": 6, "waf_pass": 5, "proxy_reject": 1}
