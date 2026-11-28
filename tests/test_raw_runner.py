"""Tests for tools/raw_runner.py: the bytes it sends and how it reads answers (local sockets only)."""
import http.client
import importlib.util
import json
import socket
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_tool():
    spec = importlib.util.spec_from_file_location("raw_runner", ROOT / "tools" / "raw_runner.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class OneShotServer:
    """Accepts connections, records what each one sent, answers with the next canned answer."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.received = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        for answer in self.answers:
            conn, _ = self.sock.accept()
            conn.settimeout(0.3)
            data = b""
            try:
                while True:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    data += chunk
            except (socket.timeout, TimeoutError):
                pass
            self.received.append(data)
            if answer is not None:
                conn.sendall(answer)
            conn.close()


def sample(tool, **kw):
    from kortex_eval.manifest import Sample
    base = dict(id="s-1", label="attack", family="sqli", source="test", method="GET", path="/", query="", body="", content_type="")
    base.update(kw)
    return Sample(**base)


def test_request_bytes_are_written_as_stored_even_with_a_space_in_the_query():
    tool = load_tool()
    raw = tool.request_bytes(sample(tool, id="encd-1", query='q=" or 1=1'), "localhost", 8097, "UA/1")
    assert raw == (b'GET /?q=" or 1=1 HTTP/1.1\r\nHost: localhost:8097\r\nAccept-Encoding: identity\r\n'
                   b"X-Kortex-Sample-Id: encd-1\r\nUser-Agent: UA/1\r\n\r\n")


def test_a_sendable_sample_goes_out_as_the_bytes_http_client_sends():
    tool = load_tool()
    s = sample(tool, id="s-2", method="POST", path="/rest/user/login", body='{"email": "x"}', content_type="application/json")
    server = OneShotServer([b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"])
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    body = s.body.encode()
    conn.request("POST", s.path, body=body, headers={"Accept-Encoding": "identity", "X-Kortex-Sample-Id": s.id,
                                                    "User-Agent": "UA/1", "Content-Type": s.content_type,
                                                    "Content-Length": str(len(body))})
    conn.getresponse().read()
    conn.close()
    server.thread.join(2)
    assert server.received[0] == tool.request_bytes(s, "127.0.0.1", server.port, "UA/1")


def test_answers_are_read_into_runner_rows(tmp_path):
    tool = load_tool()
    server = OneShotServer([
        b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n403 kortex-decision=block\n",
        b"HTTP/1.1 400 Bad Request\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1c\r\n400 kortex-decision=framing\n\r\n0\r\n\r\n",
        b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nstub-ok",
        None,
    ])
    man = tmp_path / "m.jsonl"
    man.write_text("".join(json.dumps({"id": f"s-{i}", "label": "attack", "family": "sqli", "source": "t", "method": "GET",
                                       "path": "/", "query": "q=a b", "body": "", "content_type": ""}) + "\n"
                           for i in range(4)))
    assert tool.main(["--manifest", str(man), "--base-url", f"http://127.0.0.1:{server.port}", "--out", str(tmp_path / "run"),
                      "--block-marker", "kortex-decision=block", "--timeout", "3"]) == 0
    rows = [json.loads(line) for line in (tmp_path / "run" / "responses.jsonl").read_text().splitlines()]
    assert [(r["status"], r["blocked"], r["engine_decision"], r["error_class"]) for r in rows] == [
        (403, True, "block", None), (400, False, "framing", None), (200, False, None, None), (None, False, None, "http_error")]
    run = json.loads((tmp_path / "run" / "run.json").read_text())
    assert run["total_samples"] == 4 and run["error_count"] == 1 and run["blocked"] == 1 and run["runner"] == "tools/raw_runner.py"
    assert all(b"GET /?q=a b HTTP/1.1\r\n" in got for got in server.received)


def test_only_local_addresses_are_accepted(tmp_path):
    tool = load_tool()
    import pytest
    with pytest.raises(SystemExit):
        tool.run([], "http://example.org:80", tmp_path / "x")
