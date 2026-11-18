"""Tests for kortex_eval.runner using a local fake HTTP server (no Docker).

The fake server records the raw request line and headers it receives, so the
tests can prove that the runner sends path+query verbatim and carries the
X-Kortex-Sample-Id header.
"""
from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from kortex_eval import manifest, runner


class FakeWaf(BaseHTTPRequestHandler):
    """Programmable fake target/WAF. State lives on the class."""

    lock = threading.Lock()
    seen_request_lines: list[str] = []
    seen_sample_ids: list[str] = []
    seen_bodies: list[bytes] = []
    seen_headers: list[dict] = []
    # path -> (status, body). Default for unknown paths.
    routes: dict[str, tuple[int, str]] = {}

    def log_message(self, *args):  # silence test output
        pass

    def _record(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        with self.lock:
            self.seen_request_lines.append(self.requestline)
            self.seen_sample_ids.append(self.headers.get("X-Kortex-Sample-Id"))
            self.seen_bodies.append(body)
            self.seen_headers.append({k.lower(): v for k, v in self.headers.items()})

    def _respond(self):
        status, body = self.routes.get(self.path, (200, '{"ok":true}'))
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html" if status == 403 else "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self._record()
        if self.path == "/slow":
            threading.Event().wait(2.0)  # longer than the client timeout in the test
        self._respond()

    do_POST = do_GET


@pytest.fixture()
def fake_server():
    FakeWaf.seen_request_lines = []
    FakeWaf.seen_sample_ids = []
    FakeWaf.seen_bodies = []
    FakeWaf.seen_headers = []
    FakeWaf.routes = {
        "/blocked": (403, "<html><head><title>403 Forbidden</title></head>"
                         "<body><center><h1>403 Forbidden</h1></center>"
                         "<hr><center>nginx</center></body></html>"),
        "/target-403": (403, "<html><title>Error: app says no</title></html>"),
        "/clean": (200, '{"ok":true}'),
        "/slow": (200, '{"ok":true}'),
    }
    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeWaf)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def make_manifest(tmp_path, samples):
    path = tmp_path / "manifest.jsonl"
    manifest.dump(samples, path)
    return str(path)


def sample(**overrides):
    base = dict(
        id="s1", label="attack", family="sqli", source="hand-written-smoke",
        method="GET", path="/clean", query="", body="",
    )
    base.update(overrides)
    return manifest.Sample(**base)


def read_jsonl(path):
    return [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]


def test_block_detected_on_403_with_marker(tmp_path, fake_server):
    m = make_manifest(tmp_path, [sample(id="atk-1", path="/blocked")])
    summary = runner.run([sample(id="atk-1", path="/blocked")],
                         f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    rows = read_jsonl(tmp_path / "run" / "responses.jsonl")
    assert rows[0]["status"] == 403 and rows[0]["blocked"] is True and rows[0]["error"] is None
    preds = read_jsonl(tmp_path / "run" / "predictions.jsonl")
    assert preds == [{"id": "atk-1", "flagged": True}]
    assert summary["blocked"] == 1


def test_clean_200_not_blocked(tmp_path, fake_server):
    runner.run([sample(id="benign-1", path="/clean")],
               f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    rows = read_jsonl(tmp_path / "run" / "responses.jsonl")
    assert rows[0]["status"] == 200 and rows[0]["blocked"] is False
    assert read_jsonl(tmp_path / "run" / "predictions.jsonl") == [{"id": "benign-1", "flagged": False}]


def test_target_own_403_without_marker_is_not_blocked(tmp_path, fake_server):
    runner.run([sample(id="t403-1", path="/target-403")],
               f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    rows = read_jsonl(tmp_path / "run" / "responses.jsonl")
    assert rows[0]["status"] == 403 and rows[0]["blocked"] is False


def test_timeout_is_error_never_not_flagged(tmp_path, fake_server):
    summary = runner.run([sample(id="slow-1", path="/slow")],
                         f"http://127.0.0.1:{fake_server.server_port}",
                         tmp_path / "run", timeout=0.2)
    rows = read_jsonl(tmp_path / "run" / "responses.jsonl")
    assert rows[0]["error"] == "timeout"
    assert rows[0]["status"] is None
    # an error sample must NOT appear in predictions as flagged=false
    assert read_jsonl(tmp_path / "run" / "predictions.jsonl") == []
    assert summary["error_count"] == 1


def test_sample_id_header_arrives(tmp_path, fake_server):
    runner.run([sample(id="hdr.check:1")],
               f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    assert FakeWaf.seen_sample_ids == ["hdr.check:1"]


def test_raw_query_reaches_server_unmodified(tmp_path, fake_server):
    # stored percent-encoded exactly as it must go on the wire; a library that
    # re-encodes would turn %27 into %2527 and the test would fail.
    q = "%27%20OR%201%3d1--"
    runner.run([sample(id="raw-1", path="/rest/products/search", query=q)],
               f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    assert FakeWaf.seen_request_lines == ["GET /rest/products/search?%27%20OR%201%3d1-- HTTP/1.1"]


def test_invalid_ids_refused_and_listed(tmp_path, fake_server):
    bad = [sample(id="bad id"), sample(id="ok.id"), sample(id="x" * 65)]
    with pytest.raises(runner.RunnerError) as excinfo:
        runner.run(bad, f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    msg = str(excinfo.value)
    assert "bad id" in msg and "x" * 65 in msg
    assert "ok.id" not in msg  # valid ids are not listed
    assert FakeWaf.seen_request_lines == []  # nothing was sent


def test_run_json_contents(tmp_path, fake_server):
    summary = runner.run(
        [sample(id="a-1", path="/blocked"), sample(id="b-1", path="/clean")],
        f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run",
        block_status=403, block_marker="<center>nginx</center>", workers=2, timeout=5.0,
        manifest_sha256="abc123", labels={"engine_mode": "On", "paranoia": "1"},
    )
    data = json.load(open(tmp_path / "run" / "run.json", encoding="utf-8"))
    assert data["base_url"].startswith("http://127.0.0.1:")
    assert data["started_utc"].endswith("Z") or "+00:00" in data["started_utc"]
    assert data["ended_utc"]
    assert data["total_samples"] == 2 and data["responses_ok"] == 2
    assert data["blocked"] == 1 and data["error_count"] == 0
    assert data["block_rule"] == {"block_status": 403, "block_marker": "<center>nginx</center>"}
    assert data["manifest_sha256"] == "abc123"
    assert data["labels"] == {"engine_mode": "On", "paranoia": "1"}
    assert summary == data


def test_cli_records_manifest_sha256_and_labels(tmp_path, fake_server):
    m = make_manifest(tmp_path, [sample(id="prov-1", path="/clean")])
    import subprocess, sys
    proc = subprocess.run(
        [sys.executable, "-m", "kortex_eval.runner", "--manifest", m,
         "--base-url", f"http://127.0.0.1:{fake_server.server_port}",
         "--out", str(tmp_path / "run"), "--label", "engine_mode=On", "--label", "paranoia=1"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.load(open(tmp_path / "run" / "run.json", encoding="utf-8"))
    import hashlib
    assert data["manifest_sha256"] == hashlib.sha256(open(m, "rb").read()).hexdigest()
    assert data["labels"] == {"engine_mode": "On", "paranoia": "1"}


def test_cli_rejects_bad_label(tmp_path, fake_server):
    m = make_manifest(tmp_path, [sample(id="lbl-1", path="/clean")])
    import subprocess, sys
    proc = subprocess.run(
        [sys.executable, "-m", "kortex_eval.runner", "--manifest", m,
         "--base-url", f"http://127.0.0.1:{fake_server.server_port}",
         "--out", str(tmp_path / "run"), "--label", "noequalsign"],
        capture_output=True, text=True,
    )
    assert proc.returncode == 2


def test_post_body_and_content_type_sent_verbatim(tmp_path, fake_server):
    FakeWaf.routes["/login"] = (200, "{}")
    body = 'email="a@b.c"&password=%27+OR+1%3d1--'
    runner.run(
        [sample(id="post-1", method="POST", path="/login", body=body,
                content_type="application/x-www-form-urlencoded")],
        f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run",
    )
    assert FakeWaf.seen_request_lines == ["POST /login HTTP/1.1"]
    assert FakeWaf.seen_bodies == [body.encode()]


def test_connection_error_is_error(tmp_path):
    # port with nothing listening on localhost
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        free_port = s.getsockname()[1]
    summary = runner.run([sample(id="dead-1")], f"http://127.0.0.1:{free_port}", tmp_path / "run")
    rows = read_jsonl(tmp_path / "run" / "responses.jsonl")
    assert rows[0]["error"] and rows[0]["error"].startswith("connection_error")
    assert summary["error_count"] == 1


def test_recorded_headers_sent_and_sample_id_wins(tmp_path, fake_server):
    FakeWaf.routes["/hdrcheck"] = (200, "{}")
    s = sample(id="hdr-win-1", path="/hdrcheck",
               headers={"Accept": "text/html", "X-Kortex-Sample-Id": "RECORDED-OVERRIDE"})
    runner.run([s], f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    assert FakeWaf.seen_sample_ids == ["hdr-win-1"]  # ours, not the recorded one
    assert FakeWaf.seen_headers[0]["accept"] == "text/html"  # recorded header sent


def test_recorded_content_type_not_duplicated(tmp_path, fake_server):
    FakeWaf.routes["/dupct"] = (200, "{}")
    s = sample(id="dupct-1", path="/dupct", method="POST", body='{"a":1}',
               content_type="application/json",
               headers={"content-type": "application/json"})
    runner.run([s], f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    ctypes = [v for k, v in FakeWaf.seen_headers[0].items()
              if k.lower() == "content-type"]
    assert ctypes == ["application/json"]  # exactly one


def test_default_user_agent_absent_flag_unchanged(tmp_path, fake_server):
    FakeWaf.routes["/ua"] = (200, "{}")
    s = sample(id="ua-off-1", path="/ua")
    summary = runner.run([s], f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run")
    assert summary["default_user_agent"] is None
    assert "user-agent" not in FakeWaf.seen_headers[0]


def test_default_user_agent_added_when_sample_has_none(tmp_path, fake_server):
    FakeWaf.routes["/ua"] = (200, "{}")
    s = sample(id="ua-add-1", path="/ua")
    runner.run([s], f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run",
               default_user_agent="Chrome/158.0.0.0 test")
    assert FakeWaf.seen_headers[0]["user-agent"] == "Chrome/158.0.0.0 test"


def test_default_user_agent_never_overrides_recorded(tmp_path, fake_server):
    FakeWaf.routes["/ua"] = (200, "{}")
    s = sample(id="ua-keep-1", path="/ua",
               headers={"User-Agent": "RecordedBrowser/1.0"})
    runner.run([s], f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run",
               default_user_agent="Chrome/158.0.0.0 test")
    assert FakeWaf.seen_headers[0]["user-agent"] == "RecordedBrowser/1.0"


def test_default_user_agent_case_insensitive_recorded(tmp_path, fake_server):
    FakeWaf.routes["/ua"] = (200, "{}")
    s = sample(id="ua-case-1", path="/ua",
               headers={"user-agent": "lowercase-recorded/2.0"})
    runner.run([s], f"http://127.0.0.1:{fake_server.server_port}", tmp_path / "run",
               default_user_agent="Chrome/158.0.0.0 test")
    assert FakeWaf.seen_headers[0]["user-agent"] == "lowercase-recorded/2.0"


def test_send_one_encoding_error_is_per_sample_row():
    """Step-10 T1: non-latin-1 header value -> per-sample 'encoding' error row."""
    from kortex_eval.manifest import Sample
    from kortex_eval.runner import send_one

    s = Sample(id="enc-1", label="benign", family="benign", source="t",
               method="GET", path="/", query="", body="", content_type="",
               headers={"X-Bad": "ok\ufffd"})
    row = send_one(s, "127.0.0.1", 1, timeout=2, block_status=403,
                   block_marker=None)
    assert row["error_class"] == "encoding"
    assert row["error"] is not None and row["error"].startswith("encoding:")
    assert row["status"] is None


def test_send_one_nonlatin1_request_line_is_encoding_error():
    from kortex_eval.manifest import Sample
    from kortex_eval.runner import send_one

    s = Sample(id="enc-2", label="benign", family="benign", source="t",
               method="GET", path="/\ufffd", query="", body="", content_type="")
    row = send_one(s, "127.0.0.1", 1, timeout=2, block_status=403,
                   block_marker=None)
    assert row["error_class"] == "encoding"
