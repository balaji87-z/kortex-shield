"""Tests for kortex_eval.crs_audit, run against the REAL samples in docs/samples/."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kortex_eval import crs_audit

SAMPLES = Path(__file__).resolve().parent.parent / "docs" / "samples"
ROOT = SAMPLES.parent.parent


def load_audit(filename):
    text = (SAMPLES / filename).read_text(encoding="utf-8")
    return crs_audit.parse_logs(text)


def test_real_sqli_sample_rules_and_score():
    entries = load_audit("crs-log-sqli.txt")
    assert len(entries) == 1
    e = entries[0]
    ids = [r["id"] for r in e["rules"]]
    assert ids == ["942100", "949110"]
    assert e["inbound_score_from_949110"] == 5
    assert e["inbound_score_from_severities"] == 5
    assert e["score_mismatch"] is False
    assert e["status"] == 403
    assert e["rules"][0]["severity"] == "2"
    assert e["rules"][0]["message"] == "SQL Injection Attack Detected via libinjection"
    assert e["sample_id"] is None  # curl requests carried no sample-id header


def test_real_xss_sample_rules_and_score():
    entries = load_audit("crs-log-xss.txt")
    assert len(entries) == 1
    e = entries[0]
    ids = [r["id"] for r in e["rules"]]
    assert ids == ["941100", "941110", "941160", "941390", "949110"]
    assert e["inbound_score_from_949110"] == 20
    assert e["inbound_score_from_severities"] == 20
    assert e["score_mismatch"] is False
    assert e["status"] == 403


def test_real_trav02_sample_shows_score_mismatch():
    """The trav-02 entry: 5 logged critical rules sum to 25, engine total is 30.

    The gap is rule 930100, which scored twice (matched REQUEST_URI_RAW and
    ARGS:q) but logged one message - proven with the ModSecurity debug log;
    see docs/samples/crs-log-trav02.txt.
    """
    entries = load_audit("crs-log-trav02.txt")
    assert len(entries) == 1
    e = entries[0]
    ids = [r["id"] for r in e["rules"]]
    assert ids == ["930100", "930110", "930110", "930120", "932160", "949110"]
    # every logged scoring rule is severity 2 (CRITICAL, weight 5)
    assert all(r["severity"] == "2" for r in e["rules"] if r["id"] != "949110")
    assert e["inbound_score_from_severities"] == 25
    assert e["inbound_score_from_949110"] == 30
    assert e["score_mismatch"] is True


def test_real_benign_sample_has_no_audit_entry():
    # the benign sample is an access-log line; the parser must ignore it
    entries = load_audit("crs-log-benign.txt")
    assert entries == []


def test_non_audit_lines_are_ignored():
    text = (
        "2026/11/18 08:52:16 [notice] 1#1: libmodsecurity3 version 3.0.17\n"
        '172.20.0.1 - - [18/Nov/2026:08:52:16 +0000] "GET / HTTP/1.1" 200 9984 "-" "curl/8.5.0" "-"\n'
        "some random output\n"
    )
    assert crs_audit.parse_logs(text) == []


def test_sample_id_header_is_correlated():
    txn = {
        "transaction": {
            "time_stamp": "Wed Nov 18 09:00:00 2026",
            "request": {
                "method": "GET",
                "uri": "/x",
                "headers": {"Host": "h", "X-Kortex-Sample-Id": "sqli-02"},
            },
            "response": {"http_code": 403},
            "producer": {"secrules_engine": "Enabled"},
            "messages": [
                {
                    "message": "Inbound Anomaly Score Exceeded (Total Score: 15)",
                    "details": {"ruleId": "949110", "severity": "0"},
                }
            ],
        }
    }
    entry = crs_audit.parse_line(json.dumps(txn))
    assert entry["sample_id"] == "sqli-02"
    assert entry["inbound_score_from_949110"] == 15
    assert entry["inbound_score_from_severities"] == 0  # 949110 itself has no weight
    assert entry["score_mismatch"] is True
    assert entry["engine"] == "Enabled"


def test_sample_id_header_lowercase_list_form_is_correlated():
    """The engine skeleton's Coraza audit lowercases header names and stores
    list values (x-kortex-sample-id: ["sqli-02"]); the attribution must
    still work. Baseline logs keep the exact-cased string form."""
    txn = {
        "transaction": {
            "time_stamp": "Wed Nov 18 09:00:00 2026",
            "request": {
                "method": "GET",
                "uri": "/x",
                "headers": {"host": ["h"], "x-kortex-sample-id": ["sqli-02"]},
            },
            "response": {"http_code": 403},
            "producer": {"secrules_engine": "On"},
            "messages": [
                {
                    "message": "Inbound Anomaly Score Exceeded (Total Score: 15)",
                    "details": {"ruleId": "949110", "severity": "0"},
                }
            ],
        }
    }
    entry = crs_audit.parse_line(json.dumps(txn))
    assert entry["sample_id"] == "sqli-02"


def test_engine_dialect_error_message_rules_are_correlated():
    """The engine skeleton's Coraza audit puts rule id/msg/severity in
    error_message brackets with an empty message field; 949110's total score
    must still be parsed and weighted severities must still sum."""
    txn = {
        "transaction": {
            "time_stamp": "Wed Nov 18 09:00:00 2026",
            "request": {
                "method": "GET",
                "uri": "/x",
                "headers": {"x-kortex-sample-id": ["sqli-03"]},
            },
            "response": {"status": 0},
            "producer": {"secrules_engine": "On"},
        },
        # engine dialect: messages are a TOP-LEVEL sibling of transaction
        "messages": [
                {
                    "actionset": "",
                    "message": "",
                    "error_message": '[client "127.0.0.1"] Coraza: Warning. SQLi [file "r.conf"] '
                                     '[line "1"] [id "942100"] [rev ""] '
                                     '[msg "SQL Injection Attack Detected via libinjection"] '
                                     '[data ""] [severity "critical"]',
                },
                {
                    "actionset": "",
                    "message": "",
                    "error_message": '[client "127.0.0.1"] Coraza: Access denied (phase 2). '
                                     'Inbound Anomaly Score Exceeded (Total Score: 5) '
                                     '[file "r.conf"] [line "2"] [id "949110"] [rev ""] '
                                     '[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] '
                                     '[data ""] [severity "unknown"]',
                },
            ],
    }
    entry = crs_audit.parse_line(json.dumps(txn))
    assert entry["sample_id"] == "sqli-03"
    assert [r["id"] for r in entry["rules"]] == ["942100", "949110"]
    assert entry["rules"][0]["message"] == "SQL Injection Attack Detected via libinjection"
    assert entry["rules"][0]["severity"] == "critical"
    assert entry["inbound_score_from_949110"] == 5
    assert entry["inbound_score_from_severities"] == 5  # 942100 critical=5; 949110 unknown=0
    assert entry["score_mismatch"] is False


def test_malformed_audit_line_raises():
    with pytest.raises(crs_audit.AuditError):
        crs_audit.parse_line('{"transaction": {"request": "broken"')


def test_truncated_capture_line_fails_the_whole_parse():
    """Rule 13: a corrupt {"transaction" line must abort the parse, not be skipped."""
    good = json.dumps({
        "transaction": {
            "time_stamp": "t", "request": {"method": "GET", "uri": "/x", "headers": {}},
            "response": {"http_code": 200}, "producer": {"secrules_engine": "Enabled"},
            "messages": [],
        }
    })
    text = good + '\n' + '{"transaction":{"client_ip":"1.2.3.4" broken'
    with pytest.raises(crs_audit.AuditError) as excinfo:
        crs_audit.parse_logs(text)
    msg = str(excinfo.value)
    assert "1 unparseable audit line" in msg and "line(s) [2]" in msg


def test_cli_exits_nonzero_on_corrupt_capture(tmp_path):
    import subprocess
    import sys
    corrupt = tmp_path / "logs.txt"
    corrupt.write_text('{"transaction": {"request": broken', encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "-m", "kortex_eval.crs_audit", "--logs", str(corrupt),
         "--out", str(tmp_path / "out.jsonl")],
        capture_output=True, text=True, cwd=ROOT,
    )
    assert proc.returncode != 0
    assert "1 unparseable audit line" in proc.stderr


# --- step-16 T4: real KORTEX engine-dialect samples --------------------------

def test_kortex_engine_attack_entry_parses():
    """The engine's own audit dialect (docs/samples/kortex-audit-attack.txt,
    captured from the step-16 T2 run) must parse: sample id correlated from
    the lowercase list-valued header, detection + threshold rule ids from the
    error_message brackets, status 403."""
    entries = load_audit("kortex-audit-attack.txt")
    assert len(entries) == 1
    e = entries[0]
    assert e["sample_id"] == "sqli-01"
    ids = [r["id"] for r in e["rules"]]
    assert "942100" in ids and "949110" in ids
    assert e["status"] in (403, 0, None)  # engine dialect may omit response.status
    assert e["inbound_score_from_949110"] >= 5


@pytest.mark.parametrize("case", ["benign", "limit", "timeout"])
def test_kortex_engine_non_attack_cases_have_no_audit_entries(case):
    """Real captures for the benign, limit and timeout cases: the engine
    writes NO coraza audit entry for any of them (RelevantOnly never records
    a passed request; limit/timeout short-circuit before coraza). The sample
    files document this with comment lines only; the parser must return zero
    entries and must not invent entries from the comments."""
    entries = load_audit(f"kortex-audit-{case}.txt")
    assert entries == []


def test_kortex_engine_limit_and_timeout_event_rows():
    """The engine's own decision records for the limit/timeout cases are the
    events rows embedded in the sample files."""
    import json as _json
    limit_lines = [l for l in (SAMPLES / "kortex-audit-limit.txt").read_text().splitlines()
                   if l.startswith("{")]
    rows = [_json.loads(l) for l in limit_lines]
    assert len(rows) == 1
    assert rows[0]["decision"] == "limit" and rows[0]["status"] == 413
    assert rows[0]["sample_id"] == "t4-limit"

    timeout_lines = [l for l in (SAMPLES / "kortex-audit-timeout.txt").read_text().splitlines()
                     if l.startswith("{")]
    rows = [_json.loads(l) for l in timeout_lines]
    decisions = [r["decision"] for r in rows]
    assert "timeout" in decisions and "abandoned-body-processing-finished" in decisions
    for r in rows:
        if r["decision"] == "timeout":
            assert r["status"] == 503
