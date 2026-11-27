"""Tests for tools/prepush_scan.sh (rules 25, 51): size limit, request-body
dumps, credential shapes, staged paths only.

Every sensitive-looking input is an obvious dummy, and each one is assembled
at run time so this file holds no contiguous key-shaped string itself.
"""
import gzip
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "tools" / "prepush_scan.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("git") is None or shutil.which("bash") is None,
    reason="git and bash are required")

DUMMY_BODY = "DUMMY-BODY-" + "not-real-content"
FAKE = {
    "aws_access_key": "AK" + "IA" + "FAKE" * 4,
    "private_key_block": "-----BEGIN " + "DUMMY PRIVATE " + "KEY-----",
    "bearer_header": "Authorization: " + "Bearer " + "dummy-" * 4 + "token",
    "slack_token": "xo" + "xb-" + "dummy-dummy-dummy",
    "email": "dummy.user" + "@" + "example.invalid",
}


def git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", ".")
    git(tmp_path, "config", "user.email", "tester" + "@" + "example.invalid")
    git(tmp_path, "config", "user.name", "tester")
    return tmp_path


def write(repo, name, content):
    path = repo / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        path.write_bytes(content)
    else:
        path.write_text(content)
    return path


def stage(repo, name, content):
    write(repo, name, content)
    git(repo, "add", "--", name)


def scan(repo, *args, **env):
    base = {k: v for k, v in os.environ.items() if not k.startswith("PREPUSH_")}
    proc = subprocess.run(["bash", str(SCRIPT), *args], cwd=repo, capture_output=True,
                          text=True, env={**base, **env})
    return proc.returncode, proc.stdout + proc.stderr


def jsonl(*records):
    return "".join(json.dumps(r) + "\n" for r in records)


# --- clean input -------------------------------------------------------------

def test_clean_staged_file_passes_before_the_first_commit(repo):
    stage(repo, "notes.txt", "nothing to see\n")
    code, out = scan(repo)
    assert code == 0, out
    assert "prepush: OK, 1 staged path(s) scanned" in out


def test_nothing_staged_passes(repo):
    stage(repo, "notes.txt", "nothing to see\n")
    git(repo, "commit", "-qm", "init")
    code, out = scan(repo)
    assert code == 0, out
    assert "prepush: OK, 0 staged path(s) scanned" in out


# --- size limit --------------------------------------------------------------

def test_file_over_the_size_limit_is_rejected(repo):
    stage(repo, "big.txt", "x" * 2000)
    code, out = scan(repo, PREPUSH_MAX_BYTES="1000")
    assert code == 1
    assert "FAIL: SIZE big.txt 2000 bytes is over the limit of 1000" in out
    assert "prepush: BLOCKED" in out


def test_file_at_the_size_limit_passes_and_large_file_gets_a_note(repo):
    stage(repo, "edge.txt", "x" * 1000)
    code, out = scan(repo, PREPUSH_MAX_BYTES="1000", PREPUSH_WARN_BYTES="500")
    assert code == 0, out
    assert "prepush: large file: edge.txt (1000 bytes)" in out


def test_default_size_limit_is_5_mb(repo):
    five_mb = 5 * 1024 * 1024
    stage(repo, "at-limit.txt", "x" * five_mb)
    stage(repo, "over-limit.txt", "x" * (five_mb + 1))
    code, out = scan(repo)
    assert code == 1
    assert f"FAIL: SIZE over-limit.txt {five_mb + 1} bytes is over the limit of {five_mb}" in out
    assert "SIZE at-limit.txt" not in out
    assert f"prepush: large file: at-limit.txt ({five_mb} bytes)" in out


def test_oversized_file_still_gets_the_content_checks(repo):
    stage(repo, "big-dump.jsonl", jsonl({"id": "s1", "body": DUMMY_BODY}) + "x" * 2000)
    code, out = scan(repo, PREPUSH_MAX_BYTES="1000")
    assert code == 1
    assert "FAIL: SIZE big-dump.jsonl" in out
    assert "FAIL: BODY_DUMP big-dump.jsonl reason=json-body-field records=1 keys=body" in out


def test_size_limit_applies_to_files_whose_content_is_not_scanned(repo):
    stage(repo, "blob.bin", b"\x00" * 2000)
    code, out = scan(repo, PREPUSH_MAX_BYTES="1000")
    assert code == 1
    assert "FAIL: SIZE blob.bin" in out


# --- request-body dumps ------------------------------------------------------

def test_jsonl_with_body_fields_is_rejected_without_printing_the_body(repo):
    stage(repo, "dump.jsonl", jsonl(
        {"id": "s1", "method": "POST", "body": DUMMY_BODY},
        {"id": "s2", "method": "GET", "body": ""},
        {"id": "s3", "method": "POST", "body": DUMMY_BODY},
    ))
    code, out = scan(repo)
    assert code == 1
    assert "FAIL: BODY_DUMP dump.jsonl reason=json-body-field records=2 keys=body" in out
    assert DUMMY_BODY not in out


def test_jsonl_with_only_empty_bodies_passes(repo):
    stage(repo, "manifest.jsonl", jsonl(
        {"id": "s1", "method": "GET", "body": "", "content_type": ""},
        {"id": "s2", "method": "GET", "body": None},
    ))
    code, out = scan(repo)
    assert code == 0, out


def test_ids_sizes_and_hashes_pass(repo):
    stage(repo, "bodies-meta.jsonl", jsonl(
        {"id": "s1", "body_size": 1234, "content_type": "application/json", "body_sha256": "0" * 64},
    ))
    code, out = scan(repo)
    assert code == 0, out


def test_audit_style_nested_request_body_is_rejected(repo):
    stage(repo, "audit.log", jsonl(
        {"transaction": {"request": {"method": "POST", "body": DUMMY_BODY},
                         "response": {"status": 200, "body": ""}}},
    ))
    code, out = scan(repo)
    assert code == 1
    assert "BODY_DUMP audit.log reason=json-body-field records=1 keys=body" in out


def test_every_record_is_counted_when_bodies_hold_unicode_line_separators(repo):
    tricky = DUMMY_BODY + "\u2028" + DUMMY_BODY + "\x85" + DUMMY_BODY
    lines = [json.dumps({"id": f"s{i}", "body": tricky}, ensure_ascii=False) for i in range(3)]
    stage(repo, "dump.jsonl", "\n".join(lines) + "\n")
    code, out = scan(repo)
    assert code == 1
    assert "BODY_DUMP dump.jsonl reason=json-body-field records=3 keys=body" in out


def test_response_body_alone_is_not_a_request_body_dump(repo):
    stage(repo, "audit.log", jsonl(
        {"transaction": {"request": {"method": "GET", "body": ""},
                         "response": {"status": 200, "body": "dummy response text"}}},
    ))
    code, out = scan(repo)
    assert code == 0, out


def test_multi_line_json_document_with_post_data_is_rejected(repo):
    doc = {"log": {"entries": [{"request": {"method": "POST", "postData": {"text": DUMMY_BODY}}}]}}
    stage(repo, "capture.json", json.dumps(doc, indent=2))
    code, out = scan(repo)
    assert code == 1
    assert "BODY_DUMP capture.json reason=json-body-field records=1 keys=postData" in out


def test_gzipped_body_dump_is_rejected(repo):
    stage(repo, "derived.jsonl.gz", gzip.compress(jsonl({"id": "s1", "request_body": DUMMY_BODY}).encode()))
    code, out = scan(repo)
    assert code == 1
    assert "BODY_DUMP derived.jsonl.gz reason=json-body-field records=1 keys=request_body" in out


@pytest.mark.parametrize("name", ["sample-0001.body", "session.har"])
def test_body_and_har_file_names_are_rejected(repo, name):
    stage(repo, name, DUMMY_BODY)
    code, out = scan(repo)
    assert code == 1
    assert f"BODY_DUMP {name} reason=name" in out


def test_raw_http_request_with_a_body_is_rejected(repo):
    stage(repo, "request.txt",
          "POST /dummy HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 27\r\n\r\n" + DUMMY_BODY)
    code, out = scan(repo)
    assert code == 1
    assert "BODY_DUMP request.txt reason=raw-http-request" in out


def test_raw_http_request_without_a_body_passes(repo):
    stage(repo, "request.txt", "DELETE /dummy HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
    code, out = scan(repo)
    assert code == 0, out


def test_source_code_mentioning_a_body_key_passes(repo):
    stage(repo, "tool.py", 'row = {"id": "s1", "body": "x=1"}\nprint(row)\n')
    code, out = scan(repo)
    assert code == 0, out


# --- body-dump allowlist: own datasets, by path only ---------------------------

OWN = jsonl({"id": "sqli-0001", "method": "POST", "body": DUMMY_BODY})


@pytest.mark.parametrize("name", [
    "data/attacks-v9/manifest.jsonl",
    "data/attacks-ct-v9/candidates.jsonl",
    "data/benign-browse-v9/manifest.jsonl",
    "data/benign-hard-v9/sub/manifest.jsonl",
])
def test_own_dataset_paths_are_allowed_and_reported(repo, name):
    stage(repo, name, OWN)
    code, out = scan(repo)
    assert code == 0, out
    assert f"prepush: body fields allowed by path (own dataset): {name} reason=json-body-field records=1" in out
    assert DUMMY_BODY not in out


@pytest.mark.parametrize("name", [
    "data/encoding-diff-v0/manifest.jsonl",   # not one of the three families
    "data/smoke/manifest.jsonl",
    "data/attacks-v9.jsonl",                  # a file, not a dataset directory
    "attacks-v9/manifest.jsonl",              # not under data/
    "other/data/attacks-v9/manifest.jsonl",
    "docs/logs/runs/x/manifest.jsonl",
    "docs/logs/data/attacks-v9/manifest.jsonl",
])
def test_other_paths_are_not_allowed(repo, name):
    stage(repo, name, OWN)
    code, out = scan(repo)
    assert code == 1
    assert f"FAIL: BODY_DUMP {name}" in out


@pytest.mark.parametrize("name", [
    "data/attacks-wcp-v9/manifest.jsonl",
    "data/benign-browse-v9/WCP-sample.jsonl",
    "data/benign-hard-v9/from-wcp/manifest.jsonl",
])
def test_wcp_in_the_path_is_never_allowed(repo, name):
    stage(repo, name, OWN)
    code, out = scan(repo)
    assert code == 1
    assert f"FAIL: BODY_DUMP {name}" in out


def test_wcp_sample_ids_are_never_allowed_even_on_an_allowed_path(repo):
    stage(repo, "data/attacks-v9/manifest.jsonl", jsonl(
        {"id": "sqli-0001", "body": DUMMY_BODY},
        {"id": "wcp-000000000000", "body": DUMMY_BODY},
    ))
    code, out = scan(repo)
    assert code == 1
    assert ("FAIL: BODY_DUMP data/attacks-v9/manifest.jsonl reason=json-body-field "
            "records=2 keys=body wcp_ids=1") in out


def test_wcp_sample_id_in_an_audit_entry_header_is_counted(repo):
    entry = {"transaction": {"request": {
        "headers": {"X-Kortex-Sample-Id": ["wcp-000000000000"]}, "body": DUMMY_BODY}}}
    stage(repo, "data/benign-hard-v9/audit.log", jsonl(entry))
    code, out = scan(repo)
    assert code == 1
    assert "BODY_DUMP data/benign-hard-v9/audit.log reason=json-body-field records=1 keys=body wcp_ids=1" in out


# --- the one exact docs/logs directory with own attack-sample logs ---------------

DUPARGS = "docs/logs/runs/s20-t1-dupargs"
OWN_AUDIT = jsonl({"transaction": {"request": {
    "headers": {"X-Kortex-Sample-Id": ["sqli-0001"]}, "body": DUMMY_BODY}}})


def test_dupargs_directory_is_allowed_and_reported(repo):
    name = f"{DUPARGS}/audit-engine-dummy.log.gz"
    stage(repo, name, gzip.compress(OWN_AUDIT.encode()))
    code, out = scan(repo)
    assert code == 0, out
    assert (f"prepush: body fields allowed by path (own attack-sample logs): {name} "
            "reason=json-body-field records=1 keys=body") in out
    assert DUMMY_BODY not in out


@pytest.mark.parametrize("name", [
    f"{DUPARGS}/sub/audit.log",                     # a subdirectory, not the directory itself
    f"{DUPARGS}-2/audit.log",                       # a sibling with the same prefix
    "docs/logs/runs/s20-t1-dupargs.log",            # a file with the directory's name
    "docs/logs/runs/s20-t1-flip-v381/audit.log",    # any other run directory
    f"copy/{DUPARGS}/audit.log",                    # the same path elsewhere
    "docs/logs/audit.log",
])
def test_nothing_else_under_docs_logs_is_allowed(repo, name):
    stage(repo, name, OWN_AUDIT)
    code, out = scan(repo)
    assert code == 1
    assert f"FAIL: BODY_DUMP {name}" in out


def test_dupargs_directory_does_not_allow_wcp_sample_ids(repo):
    entry = {"transaction": {"request": {
        "headers": {"X-Kortex-Sample-Id": ["wcp-000000000000"]}, "body": DUMMY_BODY}}}
    stage(repo, f"{DUPARGS}/audit.log", jsonl(entry))
    code, out = scan(repo)
    assert code == 1
    assert f"FAIL: BODY_DUMP {DUPARGS}/audit.log reason=json-body-field records=1 keys=body wcp_ids=1" in out


def test_dupargs_directory_does_not_allow_a_wcp_file_name(repo):
    stage(repo, f"{DUPARGS}/audit-wcp.log", OWN_AUDIT)
    code, out = scan(repo)
    assert code == 1
    assert f"FAIL: BODY_DUMP {DUPARGS}/audit-wcp.log" in out


def test_dupargs_directory_still_gets_size_and_credential_checks(repo):
    stage(repo, f"{DUPARGS}/audit.log", OWN_AUDIT + FAKE["slack_token"] + "\n" + "x" * 2000)
    code, out = scan(repo, PREPUSH_MAX_BYTES="1000")
    assert code == 1
    assert f"FAIL: SIZE {DUPARGS}/audit.log" in out
    assert f"FAIL: CRED_SHAPES {DUPARGS}/audit.log slack_token=1" in out


def test_allowlist_does_not_cover_credential_shapes(repo):
    stage(repo, "data/attacks-v9/manifest.jsonl",
          jsonl({"id": "sqli-0001", "body": DUMMY_BODY, "note": FAKE["aws_access_key"]}))
    code, out = scan(repo)
    assert code == 1
    assert "body fields allowed by path (own dataset): data/attacks-v9/manifest.jsonl" in out
    assert "FAIL: CRED_SHAPES data/attacks-v9/manifest.jsonl aws_access_key=1" in out


def test_allowlist_does_not_cover_the_size_limit(repo):
    stage(repo, "data/attacks-v9/manifest.jsonl", OWN + "x" * 2000)
    code, out = scan(repo, PREPUSH_MAX_BYTES="1000")
    assert code == 1
    assert "FAIL: SIZE data/attacks-v9/manifest.jsonl" in out


# --- staged paths only -------------------------------------------------------

def test_untracked_body_dump_is_ignored(repo):
    stage(repo, "notes.txt", "clean\n")
    write(repo, "untracked-dump.jsonl", jsonl({"id": "s1", "body": DUMMY_BODY}))
    code, out = scan(repo)
    assert code == 0, out
    assert "1 staged path(s) scanned" in out


def test_unstaged_edit_of_a_tracked_file_is_ignored(repo):
    stage(repo, "data.jsonl", jsonl({"id": "s1", "body": ""}))
    git(repo, "commit", "-qm", "init")
    write(repo, "data.jsonl", jsonl({"id": "s1", "body": DUMMY_BODY}))  # not staged
    code, out = scan(repo)
    assert code == 0, out
    assert "0 staged path(s) scanned" in out


def test_staged_content_is_scanned_not_the_working_tree_copy(repo):
    stage(repo, "data.jsonl", jsonl({"id": "s1", "body": DUMMY_BODY}))
    write(repo, "data.jsonl", jsonl({"id": "s1", "body": ""}))  # cleaned up, but not re-staged
    code, out = scan(repo)
    assert code == 1
    assert "BODY_DUMP data.jsonl" in out


def test_staged_deletion_of_a_body_dump_passes(repo):
    stage(repo, "dump.jsonl", jsonl({"id": "s1", "body": DUMMY_BODY}))
    git(repo, "commit", "-qm", "init")
    git(repo, "rm", "-q", "dump.jsonl")
    code, out = scan(repo)
    assert code == 0, out
    assert "0 staged path(s) scanned" in out


def test_only_the_staged_path_is_scanned_when_others_are_committed(repo):
    stage(repo, "old-dump.jsonl", jsonl({"id": "s1", "body": DUMMY_BODY}))
    git(repo, "commit", "-qm", "init")
    stage(repo, "notes.txt", "clean\n")
    code, out = scan(repo)
    assert code == 0, out
    assert "1 staged path(s) scanned" in out


def test_path_with_spaces(repo):
    stage(repo, "run dir/my dump.jsonl", jsonl({"id": "s1", "body": DUMMY_BODY}))
    code, out = scan(repo)
    assert code == 1
    assert "BODY_DUMP run dir/my dump.jsonl reason=json-body-field" in out


# --- credential shapes (dummy values) ----------------------------------------

@pytest.mark.parametrize("kind", sorted(FAKE))
def test_credential_shape_is_rejected_by_count_without_printing_it(repo, kind):
    stage(repo, "config.txt", f"first line\nvalue {FAKE[kind]} here\n")
    code, out = scan(repo)
    assert code == 1
    assert f"FAIL: CRED_SHAPES config.txt {kind}=1" in out
    assert FAKE[kind] not in out


def test_email_shape_is_found_deep_inside_a_very_long_line(repo):
    stage(repo, "long.txt", "x" * 300_000 + " " + FAKE["email"] + " " + "y" * 300_000 + "\n")
    code, out = scan(repo)
    assert code == 1
    assert "FAIL: CRED_SHAPES long.txt email=1" in out


def test_multi_megabyte_line_is_scanned_quickly(repo):
    stage(repo, "one-line.txt", "x" * (2 * 1024 * 1024))
    proc = subprocess.run(["bash", str(SCRIPT)], cwd=repo, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_this_test_file_and_the_script_hold_no_key_shaped_text(repo):
    stage(repo, "tests/test_prepush_scan.py", Path(__file__).read_text())
    stage(repo, "tools/prepush_scan.sh", SCRIPT.read_text())
    code, out = scan(repo)
    assert code == 0, out


# --- range mode --------------------------------------------------------------

def test_range_mode_applies_the_same_checks_to_committed_blobs(repo):
    stage(repo, "notes.txt", "clean\n")
    git(repo, "commit", "-qm", "base")
    stage(repo, "dump.jsonl", jsonl({"id": "s1", "body": DUMMY_BODY}))
    stage(repo, "big.txt", "x" * 2000)
    git(repo, "commit", "-qm", "adds a dump and a big file")
    code, out = scan(repo, "--range", "HEAD~1..HEAD", PREPUSH_MAX_BYTES="1000")
    assert code == 1
    assert "BODY_DUMP dump.jsonl reason=json-body-field records=1 keys=body" in out
    assert "SIZE big.txt 2000 bytes is over the limit of 1000" in out
    code, out = scan(repo, "--range", "HEAD~1..HEAD~1")
    assert code == 0, out


def test_unknown_argument_is_a_usage_error(repo):
    code, out = scan(repo, "--everything")
    assert code == 2
    assert "usage:" in out
