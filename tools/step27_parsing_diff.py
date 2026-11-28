#!/usr/bin/env python3
"""Step-27: parsing differential, second slice (heads) and first body slice.

Hand-written raw HTTP requests (no external data) are sent to the engine in
front of each backend and to each backend directly. Backends (the frameworks
in scope, docs/plan-step27-parsing.md): Python http.server, Go net/http,
Node.js http. Local testbed only (rule 6): every address is 127.0.0.1.

Cases:
  - the 61 cases of step 23 (tools/step23_parsing_diff.py), unchanged;
  - head families of this step: bare-lf, conn-reuse, host, version, expect,
    request-line, head-size;
  - body families: urlencoded, multipart, json, xml, content-type. Each body
    case carries the canary `<script>alert(1)</script>` in some encoding; a
    family's control sends it plainly and must be blocked (rule 47).

Classes per case and backend (a case can be in several; nothing is a rate,
the cases are chosen: rule 35):
  engine-refuses-backend-accepts, engine-forwards-backend-refuses,
  view-differs, canary-reaches-backend        as in step 23
  canary-reaches-parser    the engine forwarded the request and the backend
                           behind it, parsing the body with its standard
                           parser, gets a key or value that holds the canary
                           (A3's failure condition)
  canary-in-file-part      the same for the content of an uploaded file part
  second-request-served    conn-reuse: more than one answer on the connection
                           or an engine `pass` event for the second request
Per case for the engine: a refusal without the kortex marker or without an
event, and no answer at all, are counted (the step-24 criterion).

Usage: step27_parsing_diff.py --backend NAME=ENGINE_PORT,BACKEND_PORT,EVENTS_FILE ... --out DIR
"""
import argparse
import collections
import importlib.util
import json
import os
import re
import socket
import sys
import time

_spec = importlib.util.spec_from_file_location(
    "step23_parsing_diff", os.path.join(os.path.dirname(os.path.abspath(__file__)), "step23_parsing_diff.py"))
s23 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s23)

UA = s23.UA
CANARY = "<script>alert(1)</script>"
CANARY_PCT = "%3Cscript%3Ealert(1)%3C%2Fscript%3E"
STATUS_LINE = re.compile(rb"(?m)^HTTP/1\.[01] \d{3}")


def head(case_id, request_line, lines=(), eol=b"\r\n", blank=None, host=True):
    """Raw head: request line, the standard headers, the given lines, a blank line."""
    out = [request_line.encode("latin-1") if isinstance(request_line, str) else request_line]
    if host:
        out.append(b"Host: localhost")
    out += [b"User-Agent: " + UA.encode(), b"Accept: */*", b"X-Kortex-Sample-Id: " + case_id.encode()]
    out += [l if isinstance(l, bytes) else l.encode("latin-1") for l in lines]
    return eol.join(out) + eol + (eol if blank is None else blank)


def body_request(case_id, content_type, payload, extra=()):
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    lines = ([] if content_type is None else ["Content-Type: " + content_type]) + list(extra)
    if not any(l.lower().startswith("transfer-encoding") for l in lines):
        lines.append(f"Content-Length: {len(payload)}")
    return head(case_id, "POST /body HTTP/1.1", lines) + payload


def multipart(parts, boundary="xyzBOUNDARY", eol="\r\n", final=True, preamble=""):
    """parts: [(list of part header lines, content)]."""
    out = preamble
    for headers, content in parts:
        out += "--" + boundary + eol + eol.join(headers) + eol + eol + content + eol
    if final:
        out += "--" + boundary + "--" + eol
    return out


CD_Q = 'Content-Disposition: form-data; name="q"'


def build_cases():
    """[{id, family, note, raw, canary, control, second_id, kind}]"""
    c = []

    def add(cid, family, note, raw, canary=None, control=False, second_id=None, kind="head"):
        c.append({"id": cid, "family": family, "note": note, "raw": raw, "canary": canary, "control": control,
                  "second_id": second_id, "kind": kind})

    for old in s23.build_cases():
        add(old["id"], old["family"], old["note"], old["raw"], old["canary"], kind="step23")

    # ---- bare LF ----
    lf = b"\n"
    add("blf-all-lf", "bare-lf", "every line of the head ended by LF", head("blf-all-lf", "GET /s?q=1 HTTP/1.1", eol=lf))
    add("blf-blank-only", "bare-lf", "CRLF lines, the blank line ended by LF",
        head("blf-blank-only", "GET /s?q=1 HTTP/1.1", blank=lf))
    add("blf-crlf-blank", "bare-lf", "LF lines, the blank line in CRLF",
        head("blf-crlf-blank", "GET /s?q=1 HTTP/1.1", eol=lf, blank=b"\r\n"))
    add("blf-body", "bare-lf", "all-LF head with Content-Length 5 and a body",
        head("blf-body", "POST /form HTTP/1.1", ["Content-Type: text/plain", "Content-Length: 5"], eol=lf) + b"hello")
    add("blf-canary", "bare-lf", "all-LF head with the canary in the query (must be blocked)",
        head("blf-canary", "GET /s?q=" + s23.XSS_PLAIN + " HTTP/1.1", eol=lf), s23.CANARY, control=True)
    add("blf-hidden-cl", "bare-lf", "Transfer-Encoding: chunked, then Content-Length after a bare LF",
        head("blf-hidden-cl", "POST /form HTTP/1.1", ["Content-Type: text/plain", b"Transfer-Encoding: chunked\nContent-Length: 5"])
        + s23.CHUNKED_HELLO)
    add("blf-cr-only", "bare-lf", "header lines ended by a bare CR",
        b"GET /s?q=1 HTTP/1.1\r\nHost: localhost\rX-Kortex-Sample-Id: blf-cr-only\r\n\r\n")

    # ---- connection reuse: two requests in one write ----
    def two(cid, first, second_line, second_lines=(), second_body=b""):
        sid = cid + "-second"
        return first + head(sid, second_line, second_lines) + second_body, sid

    raw, sid = two("reuse-get-get", head("reuse-get-get", "GET /first HTTP/1.1"), "GET /second?q=" + s23.XSS_PLAIN + " HTTP/1.1")
    add("reuse-get-get", "conn-reuse", "two GET requests in one write, the second with the canary", raw, s23.CANARY, second_id=sid)
    raw, sid = two("reuse-get-smuggle", head("reuse-get-smuggle", "GET /first HTTP/1.1"), "POST /form HTTP/1.1",
                   ["Content-Type: text/plain", "Transfer-Encoding: chunked", "Content-Length: 5"], s23.CHUNKED_HELLO)
    add("reuse-get-smuggle", "conn-reuse", "a GET, then a request the gate refuses when sent alone (TE with CL)", raw, second_id=sid)
    raw, sid = two("reuse-post-cl", head("reuse-post-cl", "POST /form HTTP/1.1", ["Content-Type: text/plain", "Content-Length: 5"]) + b"hello",
                   "GET /second?q=" + s23.XSS_PLAIN + " HTTP/1.1")
    add("reuse-post-cl", "conn-reuse", "a POST with its 5-byte body, then a GET with the canary", raw, s23.CANARY, second_id=sid)
    raw, sid = two("reuse-keepalive", head("reuse-keepalive", "GET /first HTTP/1.1", ["Connection: keep-alive"]), "GET /second HTTP/1.1")
    add("reuse-keepalive", "conn-reuse", "two GET requests, the first asks for keep-alive", raw, second_id=sid)

    # ---- Host ----
    add("host-missing-11", "host", "HTTP/1.1 without a Host line", head("host-missing-11", "GET /x HTTP/1.1", host=False))
    add("host-dup-same", "host", "two Host lines, same value", head("host-dup-same", "GET /x HTTP/1.1", ["Host: localhost"]))
    add("host-dup-diff", "host", "two Host lines, different values", head("host-dup-diff", "GET /x HTTP/1.1", ["Host: other.example"]))
    add("host-empty", "host", "empty Host value", head("host-empty", "GET /x HTTP/1.1", ["Host:"], host=False))
    add("host-absolute-diff", "host", "absolute-form target naming another host than the Host line",
        head("host-absolute-diff", "GET http://other.example/x?q=1 HTTP/1.1"))
    add("host-absolute-canary", "host", "absolute-form target with the canary in its query (must be blocked)",
        head("host-absolute-canary", "GET http://localhost/s?q=" + s23.XSS_PLAIN + " HTTP/1.1"), s23.CANARY, control=True)

    # ---- version ----
    add("ver-10-host", "version", "HTTP/1.0 with Host", head("ver-10-host", "GET /x HTTP/1.0"))
    add("ver-10-nohost", "version", "HTTP/1.0 without Host", head("ver-10-nohost", "GET /x HTTP/1.0", host=False))
    add("ver-09", "version", "request line without a version (HTTP/0.9 style)", head("ver-09", "GET /x"))
    add("ver-12", "version", "HTTP/1.2", head("ver-12", "GET /x HTTP/1.2"))
    add("ver-20", "version", "HTTP/2.0 on a plain connection", head("ver-20", "GET /x HTTP/2.0"))
    add("ver-lower", "version", "http/1.1 in lower case", head("ver-lower", "GET /x http/1.1"))
    add("ver-10-canary", "version", "HTTP/1.0 with the canary in the query (must be blocked)",
        head("ver-10-canary", "GET /s?q=" + s23.XSS_PLAIN + " HTTP/1.0"), s23.CANARY, control=True)

    # ---- Expect ----
    add("expect-100-body", "expect", "Expect: 100-continue, body sent at once",
        head("expect-100-body", "POST /form HTTP/1.1", ["Content-Type: text/plain", "Content-Length: 5", "Expect: 100-continue"]) + b"hello")
    add("expect-other", "expect", "Expect: later", head("expect-other", "GET /x HTTP/1.1", ["Expect: later"]))

    # ---- request line ----
    add("rl-two-spaces", "request-line", "two spaces after the method", head("rl-two-spaces", "GET  /x HTTP/1.1"))
    add("rl-tab", "request-line", "a tab after the method", head("rl-tab", "GET\t/x HTTP/1.1"))
    add("rl-space-in-query", "request-line", "a raw space inside the query (the shape of the 10 unsendable requests)",
        head("rl-space-in-query", 'GET /?q=" or 1=1 HTTP/1.1'))
    add("rl-options-asterisk", "request-line", "OPTIONS *", head("rl-options-asterisk", "OPTIONS * HTTP/1.1"))
    add("rl-fragment", "request-line", "a fragment in the target", head("rl-fragment", "GET /x#frag HTTP/1.1"))
    add("rl-connect", "request-line", "CONNECT with an authority-form target", head("rl-connect", "CONNECT localhost:80 HTTP/1.1"))
    add("rl-lower-method", "request-line", "method in lower case", head("rl-lower-method", "get /x HTTP/1.1"))

    # ---- head size ----
    add("head-big", "head-size", "one header of 70,000 bytes", head("head-big", "GET /x HTTP/1.1", ["X-Pad: " + "a" * 70000]))
    add("head-many", "head-size", "600 header lines", head("head-many", "GET /x HTTP/1.1", [f"X-H{i}: {i}" for i in range(600)]))

    # ================= bodies =================
    def body(cid, family, note, content_type, payload, extra=(), control=False):
        add(cid, family, note, body_request(cid, content_type, payload, extra), CANARY, control=control, kind="body")

    FORM = "application/x-www-form-urlencoded"
    body("ue-control", "urlencoded", "q=<canary>, percent-encoded (control: must be blocked)", FORM, "q=" + CANARY_PCT, control=True)
    body("ue-dup-first", "urlencoded", "q twice, the canary first", FORM, "q=" + CANARY_PCT + "&q=safe")
    body("ue-dup-last", "urlencoded", "q twice, the canary last", FORM, "q=safe&q=" + CANARY_PCT)
    body("ue-semicolon", "urlencoded", "';' as separator before q", FORM, "a=1;q=" + CANARY_PCT)
    body("ue-key-encoded", "urlencoded", "the key written as %71", FORM, "%71=" + CANARY_PCT)
    body("ue-plus", "urlencoded", "spaces as '+' around the canary", FORM, "q=+" + CANARY_PCT + "+")
    body("ue-double", "urlencoded", "the canary double-encoded (%253C)", FORM, "q=%253Cscript%253Ealert(1)%253C%252Fscript%253E")
    body("ue-utf7", "urlencoded", "charset=utf-7 with the canary in UTF-7", FORM + "; charset=utf-7",
         "q=%2BADw-script%2BAD4-alert(1)%2BADw-/script%2BAD4-")
    body("ue-ct-upper", "urlencoded", "content type in upper case", FORM.upper(), "q=" + CANARY_PCT)
    body("ue-ct-param", "urlencoded", "content type with a boundary parameter", FORM + "; boundary=x", "q=" + CANARY_PCT)
    body("ue-ct-space", "urlencoded", "a space before the ';' of the content type", FORM + " ; charset=utf-8", "q=" + CANARY_PCT)
    body("ue-chunked", "urlencoded", "the form sent chunked", FORM, b"25\r\nq=%3Cscript%3Ealert(1)%3C%2Fscript%3E\r\n0\r\n\r\n",
         extra=["Transfer-Encoding: chunked"])

    B = "xyzBOUNDARY"
    MP = "multipart/form-data; boundary=" + B
    std = multipart([([CD_Q], CANARY)])
    body("mp-control", "multipart", "one part named q with the canary (control: must be blocked)", MP, std, control=True)
    body("mp-boundary-quoted", "multipart", "boundary in quotes", 'multipart/form-data; boundary="' + B + '"', std)
    body("mp-param-before", "multipart", "a charset parameter before the boundary", "multipart/form-data; charset=utf-8; boundary=" + B, std)
    body("mp-param-after", "multipart", "a charset parameter after the boundary", MP + "; charset=utf-8", std)
    body("mp-two-boundaries-last", "multipart", "two boundary parameters, the body uses the last",
         "multipart/form-data; boundary=fake; boundary=" + B, std)
    body("mp-two-boundaries-first", "multipart", "two boundary parameters, the body uses the first",
         "multipart/form-data; boundary=" + B + "; boundary=fake", std)
    body("mp-lf-lines", "multipart", "part lines ended by LF only", MP, multipart([([CD_Q], CANARY)], eol="\n"))
    body("mp-no-final", "multipart", "no closing boundary", MP, multipart([([CD_Q], CANARY)], final=False))
    body("mp-name-unquoted", "multipart", "name without quotes", MP, multipart([(["Content-Disposition: form-data; name=q"], CANARY)]))
    body("mp-two-names", "multipart", "two name parameters, a then q", MP,
         multipart([(['Content-Disposition: form-data; name="a"; name="q"'], CANARY)]))
    body("mp-filename", "multipart", "the canary as the content of a file part named q", MP,
         multipart([(['Content-Disposition: form-data; name="q"; filename="x.txt"', "Content-Type: text/plain"], CANARY)]))
    body("mp-filename-canary", "multipart", "the canary as the file name", MP,
         multipart([(['Content-Disposition: form-data; name="f"; filename="' + CANARY.replace('"', "") + '"'], "x")]))
    body("mp-header-fold", "multipart", "the part header folded onto a second line", MP,
         multipart([(['Content-Disposition: form-data;\r\n name="q"'], CANARY)]))
    body("mp-cd-case", "multipart", "part header name and parameters in other case", MP,
         multipart([(['content-disposition: FORM-DATA; NAME="q"'], CANARY)]))
    body("mp-preamble", "multipart", "text before the first boundary", MP, multipart([([CD_Q], CANARY)], preamble="ignore this\r\n"))
    body("mp-ct-upper", "multipart", "media type and boundary parameter name in upper case", "Multipart/Form-Data; BOUNDARY=" + B, std)
    body("mp-second-part", "multipart", "a harmless part first, the canary in the second", MP,
         multipart([(['Content-Disposition: form-data; name="a"'], "1"), ([CD_Q], CANARY)]))
    body("mp-part-utf7", "multipart", "a part declared utf-7 with the canary in UTF-7", MP,
         multipart([([CD_Q, "Content-Type: text/plain; charset=utf-7"], "+ADw-script+AD4-alert(1)+ADw-/script+AD4-")]))

    J = "application/json"
    body("json-control", "json", "the canary as a JSON string (control: must be blocked)", J, json.dumps({"q": CANARY}), control=True)
    body("json-unicode", "json", "'<' and '>' written as \\u003c and \\u003e", J,
         '{"q":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e"}')
    body("json-slash", "json", "the closing tag written with an escaped slash", J, '{"q":"<script>alert(1)<\\/script>"}')
    body("json-dup-first", "json", "key q twice, the canary first", J, '{"q":' + json.dumps(CANARY) + ',"q":"safe"}')
    body("json-dup-last", "json", "key q twice, the canary last", J, '{"q":"safe","q":' + json.dumps(CANARY) + "}")
    body("json-bom", "json", "a UTF-8 byte order mark before the document", J, b"\xef\xbb\xbf" + json.dumps({"q": CANARY}).encode())
    body("json-trailing-comma", "json", "a trailing comma", J, '{"q":' + json.dumps(CANARY) + ",}")
    body("json-comment", "json", "a comment before the key", J, '{/*c*/"q":' + json.dumps(CANARY) + "}")
    body("json-nested", "json", "the canary deep inside arrays and objects", J, json.dumps({"a": {"b": ["x", {"q": CANARY}]}}))
    body("json-key", "json", "the canary as a key", J, json.dumps({CANARY: "x"}))
    body("json-utf16", "json", "the document in UTF-16LE, charset=utf-16le", J + "; charset=utf-16le",
         json.dumps({"q": CANARY}).encode("utf-16-le"))
    body("json-utf16-bom", "json", "the document in UTF-16 with a byte order mark, no charset", J, json.dumps({"q": CANARY}).encode("utf-16"))
    body("json-ct-plus", "json", "media type application/vnd.api+json", "application/vnd.api+json", json.dumps({"q": CANARY}))
    body("json-ct-upper", "json", "media type in upper case", J.upper(), json.dumps({"q": CANARY}))
    body("json-ct-charset", "json", "charset=utf-8 parameter", J + "; charset=utf-8", json.dumps({"q": CANARY}))
    body("json-leading-ws", "json", "blank lines before the document", J, "\r\n\r\n   " + json.dumps({"q": CANARY}))

    X = "application/xml"
    esc = "&lt;script&gt;alert(1)&lt;/script&gt;"
    body("xml-control", "xml", "the canary as element text, entity-escaped (control: must be blocked)", X, f"<r><q>{esc}</q></r>", control=True)
    body("xml-cdata", "xml", "the canary in a CDATA section", X, f"<r><q><![CDATA[{CANARY}]]></q></r>")
    body("xml-char-dec", "xml", "'<' and '>' as decimal character references", X, "<r><q>&#60;script&#62;alert(1)&#60;/script&#62;</q></r>")
    body("xml-char-hex", "xml", "'<' and '>' as hexadecimal character references", X, "<r><q>&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;</q></r>")
    body("xml-attr", "xml", "the canary as an attribute value", X, f'<r q="{esc}"/>')
    body("xml-decl", "xml", "with an XML declaration", X, f'<?xml version="1.0" encoding="UTF-8"?><r><q>{esc}</q></r>')
    body("xml-utf16", "xml", "the document in UTF-16 with a declaration", X,
         f'<?xml version="1.0" encoding="UTF-16"?><r><q>{esc}</q></r>'.encode("utf-16"))
    body("xml-ct-text", "xml", "media type text/xml", "text/xml", f"<r><q>{esc}</q></r>")
    body("xml-ct-soap", "xml", "media type application/soap+xml", "application/soap+xml", f"<r><q>{esc}</q></r>")

    body("ct-missing-form", "content-type", "a form body without a Content-Type header", None, "q=" + CANARY_PCT)
    body("ct-form-as-json", "content-type", "a form body labelled application/json", J, "q=" + CANARY_PCT)
    body("ct-json-as-form", "content-type", "a JSON body labelled as a form", FORM, json.dumps({"q": CANARY}))
    body("ct-json-as-text", "content-type", "a JSON body labelled text/plain", "text/plain", json.dumps({"q": CANARY}))
    body("ct-form-as-text", "content-type", "a form body labelled text/plain", "text/plain", "q=" + CANARY_PCT)
    body("ct-multipart-as-form", "content-type", "a multipart body labelled as a form", FORM, std)
    body("ct-two-headers", "content-type", "two Content-Type headers: text/plain, then the form type", "text/plain", "q=" + CANARY_PCT,
         extra=["Content-Type: " + FORM])
    ids = [x["id"] for x in c]
    assert len(ids) == len(set(ids)), "duplicate case id"
    return c


def send(port, raw, timeout=4.0):
    """(status, body, error, number of HTTP answers on the connection)."""
    data = b""
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                s.sendall(raw)
            except OSError:
                pass  # the peer may answer and close while a large head is still being written
            while True:
                try:
                    chunk = s.recv(65536)
                except (socket.timeout, TimeoutError, ConnectionError):
                    break
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        if not data:
            return None, b"", type(exc).__name__, 0
    if not data:
        return None, b"", "no-response", 0
    answers = len(STATUS_LINE.findall(data))
    while True:  # skip interim 1xx answers
        head_, sep, rest = data.partition(b"\r\n\r\n")
        first = head_.split(b"\r\n", 1)[0].split()
        if len(first) >= 2 and first[1].isdigit() and 100 <= int(first[1]) < 200 and rest.startswith(b"HTTP/"):
            data, answers = rest, answers - 1
            continue
        break
    status = int(first[1]) if len(first) >= 2 and first[0].startswith(b"HTTP/") and first[1].isdigit() else None
    if any(line.lower().replace(b" ", b"") == b"transfer-encoding:chunked" for line in head_.split(b"\r\n")[1:]):
        rest = s23.dechunk(rest)
    return status, rest, None, answers


def observe(port, case):
    status, body, error, answers = send(port, case["raw"])
    view, decision = s23.parse_answer(status, body)
    return {"status": status, "decision": decision, "view": view, "error": error, "answers": answers}


def parser_has(view, canary, key="strings"):
    bp = (view or {}).get("body_parse") or {}
    return bool(canary) and any(canary in s for s in bp.get(key) or [])


def classify(case, eng, direct):
    out = list(s23.compare(case, eng, direct))
    if eng["forwarded"] and eng["view"] is not None:
        if parser_has(eng["view"], case["canary"]):
            out.append(("canary-reaches-parser", f"the backend's {eng['view']['body_parse']['kind']} parser yields the canary"))
        if parser_has(eng["view"], case["canary"], "file_strings"):
            out.append(("canary-in-file-part", "the canary is the content of a file part"))
    if case.get("second_id") and (eng["answers"] > 1 or eng["second_passed"]):
        out.append(("second-request-served", f"{eng['answers']} answers on the connection; pass event for the second "
                    f"request: {eng['second_passed']}"))
    return out


def engine_problem(eng):
    """A refusal without marker or without event, or no answer at all."""
    if eng["forwarded"]:
        return None
    if eng["status"] is None:
        return f"no answer ({eng['error']})"
    if not eng["decision"]:
        return f"{eng['status']} without a kortex marker"
    if not eng["events"]:
        return f"{eng['status']} {eng['decision']} without an event"
    return None


def line_count(path):
    if not os.path.exists(path):
        return 0
    with open(path, "rb") as fh:
        return sum(1 for _ in fh)


def unnamed_events(path, first, last):
    """Events without a sample id that the engine wrote while one case was sent.

    A head whose X-Kortex-Sample-Id line the engine cannot read (it is glued
    to another line by a bare CR, for instance) is logged with an empty
    sample id. Such an event belongs to the case during which it was written:
    the lines first..last-1 of the events file (one case at a time is sent).
    """
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for n, line in enumerate(fh):
            if first <= n < last and line.strip():
                ev = json.loads(line)
                if not ev.get("sample_id"):
                    out.append({"decision": ev.get("decision"), "status": ev.get("status"),
                                "reason": ev.get("reason"), "no_sample_id": True})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend", action="append", required=True, metavar="NAME=ENGINE_PORT,BACKEND_PORT,EVENTS_FILE")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    backends = collections.OrderedDict()
    for item in args.backend:
        name, _, rest = item.partition("=")
        ep, bp, ev = rest.split(",", 2)
        backends[name] = (int(ep), int(bp), ev)
    cases = build_cases()
    rows, windows = [], {}
    for case in cases:
        row = {k: case[k] for k in ("id", "family", "note", "control", "second_id", "kind")}
        row["request_bytes"], row["canary"] = len(case["raw"]), bool(case["canary"])
        row["engine"] = {}
        for b, p in backends.items():
            before = line_count(p[2])
            row["engine"][b] = observe(p[0], case)
            windows[(case["id"], b)] = (before, line_count(p[2]))
        row["direct"] = {}
        for b, p in backends.items():
            d = observe(p[1], case)
            row["direct"][b] = {"status": d["status"], "view": d["view"], "error": d["error"], "answers": d["answers"]}
        rows.append(row)
    time.sleep(0.5)
    events = {b: s23.load_events(p[2]) for b, p in backends.items()}
    for case, row in zip(cases, rows):
        row["disagreements"], row["engine_problem"] = {}, {}
        for b in backends:
            eng = row["engine"][b]
            eng["events"] = events[b].get(case["id"], []) + unnamed_events(backends[b][2], *windows[(case["id"], b)])
            eng["forwarded"] = any(e["decision"] == "pass" for e in eng["events"])
            eng["second_passed"] = bool(case["second_id"]) and any(
                e["decision"] == "pass" for e in events[b].get(case["second_id"], []))
            row["disagreements"][b] = [{"class": c, "detail": d} for c, d in classify(case, eng, row["direct"][b])]
            row["engine_problem"][b] = engine_problem(eng)
    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "results.jsonl"), "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, ensure_ascii=True, sort_keys=True) + "\n")
    print("\n".join(summary(rows, list(backends))))
    return 0


def label(eng):
    return s23.engine_label(eng)


def summary(rows, backends):
    first = backends[0]
    out = [f"== cases: {len(rows)} hand-written requests; step-23 cases {sum(1 for r in rows if r['kind'] == 'step23')}, "
           f"new head cases {sum(1 for r in rows if r['kind'] == 'head')}, body cases {sum(1 for r in rows if r['kind'] == 'body')}"]
    out.append("== engine decision per family (engine in front of the " + first + " backend)")
    for fam in sorted({r["family"] for r in rows}):
        cnt = collections.Counter(label(r["engine"][first]) for r in rows if r["family"] == fam)
        out.append(f"   {fam}: " + ", ".join(f"{k} {v}" for k, v in sorted(cnt.items())))
    same = [r for r in rows if len({label(r["engine"][b]) for b in backends}) == 1]
    out.append(f"== the engine decided the same in front of every backend in {len(same)} of {len(rows)} cases")
    for r in rows:
        if r not in same:
            out.append(f"   {r['id']}: " + "; ".join(f"{b}-backed {label(r['engine'][b])}" for b in backends))
    problems = [(r["id"], b, r["engine_problem"][b]) for r in rows for b in backends if r["engine_problem"][b]]
    out.append(f"== engine refusals without a kortex marker or without an event, and requests with no answer: "
               f"{len({p[0] for p in problems})} cases")
    for cid, b, what in problems:
        out.append(f"   {cid} [{b}-backed]: {what}")
    unnamed = sorted({r["id"] for r in rows for b in backends
                      if any(e.get("no_sample_id") for e in r["engine"][b]["events"])})
    out.append(f"== cases whose event carries no sample id (the engine could not read the id line; the event is matched "
               f"by its position in the events file): {len(unnamed)}" + (": " + ", ".join(unnamed) if unnamed else ""))
    reasons = collections.Counter(e["reason"] for r in rows for e in r["engine"][first]["events"] if e["decision"] == "framing")
    out.append("== framing events by reason (" + first + "-backed): " + (", ".join(f"{k} {v}" for k, v in sorted(reasons.items())) or "none"))
    controls = [r for r in rows if r["control"]]
    bad = [r["id"] for r in controls if any(r["engine"][b]["decision"] != "block" for b in backends)]
    out.append(f"== canary controls: {len(controls)}; blocked 403 in front of every backend: {len(controls) - len(bad)}; "
               f"not blocked: {', '.join(bad) or 'none'}")
    out.append("== each backend given the same bytes directly")
    for b in backends:
        acc = sum(1 for r in rows if r["direct"][b]["view"] is not None)
        st = collections.Counter(str(r["direct"][b]["status"]) if r["direct"][b]["status"] is not None
                                 else f"no answer ({r['direct'][b]['error']})" for r in rows)
        out.append(f"   {b}: accepts {acc} of {len(rows)}; statuses {dict(sorted(st.items()))}")
    for b in backends:
        by_class = collections.Counter(d["class"] for r in rows for d in r["disagreements"][b])
        n = sum(1 for r in rows if r["disagreements"][b])
        out.append(f"== engine vs {b} backend: {n} of {len(rows)} cases in at least one class; by class: "
                   + (", ".join(f"{k} {v}" for k, v in sorted(by_class.items())) or "none"))
        for r in rows:
            for d in r["disagreements"][b]:
                out.append(f"   {r['id']} [{r['family']}] {d['class']}: engine {label(r['engine'][b])}; {d['detail']}")
    out.append("== body cases: what the engine did and what each backend's parser got (through the engine when forwarded, else directly)")
    for r in rows:
        if r["kind"] != "body":
            continue
        cells = []
        for b in backends:
            v = r["engine"][b]["view"] if r["engine"][b]["forwarded"] else r["direct"][b]["view"]
            bp = (v or {}).get("body_parse") or {}
            got = "canary" if any(CANARY in s for s in bp.get("strings") or []) else (
                "canary in file part" if any(CANARY in s for s in bp.get("file_strings") or []) else "no canary")
            cells.append(f"{b} {bp.get('kind', 'refused') if v else 'refused'}"
                         + (f" error {bp['error']}" if bp.get("error") else "") + f": {got}")
        out.append(f"   {r['id']}: engine {label(r['engine'][first])}; " + "; ".join(cells))
    bypass = sorted({r["id"] for r in rows for b in backends for d in r["disagreements"][b] if d["class"] == "canary-reaches-parser"})
    out.append(f"== canary-reaches-parser (A3's failure condition): {len(bypass)} cases: {', '.join(bypass) or 'none'}")
    q = sorted({r["id"] for r in rows for b in backends for d in r["disagreements"][b] if d["class"] == "canary-reaches-backend"})
    out.append(f"== canary-reaches-backend (path or query): {len(q)} cases: {', '.join(q) or 'none'}")
    return out


if __name__ == "__main__":
    sys.exit(main())
