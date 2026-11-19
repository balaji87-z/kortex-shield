"""Tests for kortex_eval.outcome: synthetic rows plus the real step-02 smoke data."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from kortex_eval.outcome import classify

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


def test_outbound_cut_real_step05_samples():
    """The real step-05 error samples classify as waf_block_outbound."""
    responses = [
        {"id": "sqli-730d16ce-q", "status": None, "blocked": False,
         "error": "http_error: IncompleteRead: IncompleteRead(994 bytes read)"},
        {"id": "sqli-730d16ce-login", "status": None, "blocked": False,
         "error": "http_error: IncompleteRead: IncompleteRead(1449 bytes read)"},
    ]
    rules = [
        {"id": "920320", "message": "Missing User Agent Header", "severity": "2"},
        {"id": "950100", "message": "The Application Returned a 500-Level Status Code", "severity": "2"},
        {"id": "959100", "message": "Outbound Anomaly Score Exceeded (Total Score: 4)", "severity": "0"},
    ]
    audit_entries = [
        {"sample_id": "sqli-730d16ce-q", "status": 403, "rules": rules,
         "inbound_score_from_949110": 2, "inbound_score_from_severities": 2, "score_mismatch": False},
        {"sample_id": "sqli-730d16ce-login", "status": 403, "rules": rules,
         "inbound_score_from_949110": 2, "inbound_score_from_severities": 2, "score_mismatch": False},
    ]
    rows, _ = outcome.classify_all(responses, audit_entries, "blocking")
    by_id = {r["id"]: r["outcome"] for r in rows}
    assert by_id["sqli-730d16ce-q"] == "waf_block_outbound"
    assert by_id["sqli-730d16ce-login"] == "waf_block_outbound"


def test_outbound_cut_synthetic_edges():
    # error without 959100 stays error
    r = {"id": "x", "error": "http_error: IncompleteRead: IncompleteRead(1 bytes read)"}
    a = {"sample_id": "x", "rules": [{"id": "920320"}], "inbound_score_from_949110": 2}
    assert outcome.classify(r, a, "blocking") == "error"
    # 959100 present but inbound score at/above threshold stays error
    a2 = {"sample_id": "x", "rules": [{"id": "959100"}], "inbound_score_from_949110": 5}
    assert outcome.classify(r, a2, "blocking") == "error"
    # timeout (not an incomplete read) stays error
    r2 = {"id": "y", "error": "timeout"}
    a3 = {"sample_id": "y", "rules": [{"id": "959100"}], "inbound_score_from_949110": None}
    assert outcome.classify(r2, a3, "blocking") == "error"
    # detection mode never produces the new outcome
    assert outcome.classify(r, a, "detection") == "error"
    # non-error rows unaffected
    ok = {"id": "z", "status": 200, "blocked": False, "error": None, "body_marker": False}
    assert outcome.classify(ok, None, "blocking") == "waf_pass"


def test_outbound_cut_hard_benign_step05_logs(tmp_path):
    """The 18 hard-benign errors from step-05 PL2 runs, if their logs exist."""
    base = Path("out/benign-hard-v0-pl2-on-v05")
    if not (base / "responses.jsonl").exists():
        pytest.skip("step-05 hard PL2 run output not present")
    responses = [json.loads(l) for l in open(base / "responses.jsonl") if l.strip()]
    audit_entries = [json.loads(l) for l in open(base / "audit.jsonl") if l.strip()]
    rows, _ = outcome.classify_all(responses, audit_entries, "blocking")
    errs = [r for r in rows if r["outcome"] == "error"]
    outbound = [r for r in rows if r["outcome"] == "waf_block_outbound"]
    # step-05 observed 18 errors, all with {920320, 950100, 959100}
    assert len(outbound) == 18
    assert len(errs) == 0


def test_waf_deny_status_body_parser_400():
    """Step-11 T3: 400 + 200002 deny rule -> waf_deny_status (blocking)."""
    resp = {"id": "x", "status": 400, "blocked": False, "body_marker": False, "error": None}
    audit = {"inbound_score_from_949110": None,
             "rules": [{"id": "200002", "message": "Failed to parse request body."}]}
    assert classify(resp, audit, "blocking") == "waf_deny_status"


def test_waf_deny_status_not_in_detection_mode():
    resp = {"id": "x", "status": 400, "blocked": False, "body_marker": False, "error": None}
    audit = {"inbound_score_from_949110": None,
             "rules": [{"id": "200002", "message": "Failed to parse request body."}]}
    assert classify(resp, audit, "detection") != "waf_deny_status"


def test_waf_deny_status_requires_deny_rule():
    resp = {"id": "x", "status": 400, "blocked": False, "body_marker": False, "error": None}
    audit = {"inbound_score_from_949110": None,
             "rules": [{"id": "920420", "message": "content type"}]}
    # additive change only: without a 2xxxxx deny rule the pre-existing
    # classification (waf_pass) is unchanged
    assert classify(resp, audit, "blocking") == "waf_pass"


def test_waf_deny_status_does_not_override_block():
    resp = {"id": "x", "status": 403, "blocked": True, "body_marker": True, "error": None}
    audit = {"inbound_score_from_949110": 10,
             "rules": [{"id": "200002", "message": "deny"}, {"id": "949110", "message": "t"}]}
    assert classify(resp, audit, "blocking") == "waf_block"
