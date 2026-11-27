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
    proc = subprocess.run(["bash", str(SCRIPT), *args], cwd=repo, capture_output=True,
                          text=True, env={**os.environ, **env})
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
