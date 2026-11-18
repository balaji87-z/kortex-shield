"""Tests for kortex_eval.crs_audit, run against the REAL samples in docs/samples/."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from kortex_eval import crs_audit

SAMPLES = Path(__file__).resolve().parent.parent / "docs" / "samples"


def load_audit(filename):
    text = (SAMPLES / filename).read_text(encoding="utf-8")
    return crs_audit.parse_logs(text)


def test_real_sqli_sample_rules_and_score():
    entries = load_audit("crs-log-sqli.txt")
    assert len(entries) == 1
    e = entries[0]
    ids = [r["id"] for r in e["rules"]]
    assert ids == ["942100", "949110"]
    assert e["anomaly_score"] == 5
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
    assert e["anomaly_score"] == 20
    assert e["status"] == 403


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
    assert entry["anomaly_score"] == 15
    assert entry["engine"] == "Enabled"


def test_malformed_audit_line_raises():
    with pytest.raises(crs_audit.AuditError):
        crs_audit.parse_line('{"transaction": {"request": "broken"')
