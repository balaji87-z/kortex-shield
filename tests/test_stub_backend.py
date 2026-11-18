"""Tests for the neutral stub backend (step-09 T5) — no Docker needed."""

import http.client
import threading

import pytest

from tools.stub_backend import StubHandler, main  # noqa: F401  (main imported to prove importability)
from http.server import ThreadingHTTPServer


@pytest.fixture()
def stub_url():
    server = ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _request(url, method, path="/", body=None, headers=None):
    host, port = url.split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    conn.request(method, path, body=body, headers=headers or {})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, dict(resp.getheaders()), data


def test_get_root_returns_200_fixed_html(stub_url):
    status, headers, body = _request(stub_url, "GET", "/")
    assert status == 200
    assert b"<h1>ok</h1>" in body
    assert headers["Content-Type"] == "text/html; charset=utf-8"


def test_unknown_path_still_200(stub_url):
    status, _, body = _request(stub_url, "GET", "/rest/products/1/reviews?x=1")
    assert status == 200
    assert b"<h1>ok</h1>" in body


def test_all_methods_return_200(stub_url):
    for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
        status, _, _ = _request(stub_url, method, "/anything", body="a=1")
        assert status == 200, method


def test_post_with_body_returns_200(stub_url):
    status, _, body = _request(
        stub_url, "POST", "/api/Users",
        body='{"email":"a@b.c"}',
        headers={"Content-Type": "application/json"},
    )
    assert status == 200
    assert b"<h1>ok</h1>" in body


def test_head_returns_200_no_body(stub_url):
    status, headers, body = _request(stub_url, "HEAD", "/")
    assert status == 200
    assert body == b""
    assert int(headers["Content-Length"]) > 0
