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


# --- Step-11 (2026-11-19): keep-alive body draining -------------------------
# Live failure this guards against (observed on the coraza->stub hop): the
# handler never read request bodies, so with HTTP/1.1 keep-alive the next
# request was parsed from the leftover body bytes - the stub answered
# '501 Unsupported method ('{"url":...}GET')' and the 501 page echoed the
# body, which CRS 953110/959100 then outbound-blocked. "Mismatched length"
# here means the RECORDED Content-Length in a sample's metadata differs from
# the encoded byte length; the wire framing itself is always correct (the
# runner sends len(encoded bytes)), so the second request must arrive intact.

def test_keepalive_body_drained_next_request_intact(stub_url):
    host, port = stub_url.split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    body = '{"url":"https://x","session_start":1660633827110}'.encode()  # no trailing CRLF
    conn.request("POST", "/site", body=body,
                 headers={"Content-Length": str(len(body)),
                          "Content-Type": "application/json"})
    r1 = conn.getresponse()
    assert r1.status == 200
    r1.read()
    conn.request("GET", "/bags?product_list_order=low_to_high&ajax=1")
    r2 = conn.getresponse()
    data = r2.read()
    assert r2.status == 200, f"next keep-alive request poisoned: {r2.status} {data[:120]!r}"
    assert b"<h1>ok</h1>" in data
    conn.close()


def test_keepalive_multibyte_body_next_request_intact(stub_url):
    host, port = stub_url.split(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=5)
    body = "naïve—✓—日本語".encode("utf-8", "surrogatepass")  # 22 bytes, 12 chars
    # Wire Content-Length is the byte length (what the runner sends); the
    # mismatching "12" is only what a sample's RECORDED metadata would claim.
    conn.request("POST", "/api/collect", body=body,
                 headers={"Content-Length": str(len(body)),
                          "Content-Type": "application/json"})
    r1 = conn.getresponse()
    assert r1.status == 200
    r1.read()
    conn.request("GET", "/next")
    r2 = conn.getresponse()
    assert r2.status == 200
    r2.read()
    conn.close()
