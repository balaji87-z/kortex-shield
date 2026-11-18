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
    )
    data = json.load(open(tmp_path / "run" / "run.json", encoding="utf-8"))
    assert data["base_url"].startswith("http://127.0.0.1:")
    assert data["started_utc"].endswith("Z") or "+00:00" in data["started_utc"]
    assert data["ended_utc"]
    assert data["total_samples"] == 2 and data["responses_ok"] == 2
    assert data["blocked"] == 1 and data["error_count"] == 0
    assert data["block_rule"] == {"block_status": 403, "block_marker": "<center>nginx</center>"}
    assert summary == data


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
