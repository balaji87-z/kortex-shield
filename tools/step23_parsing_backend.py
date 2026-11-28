#!/usr/bin/env python3
"""Step-23 T5: reference Python backend for the strict-parsing differential.

A local http.server (stdlib only) that answers every request with a JSON
description of what it saw, so the harness can compare it with what the
engine decided. It behaves like the common hand-written handler:

  - the request line and headers are parsed by http.server itself (it
    answers 400 on its own for what it cannot parse);
  - the body is `Content-Length` bytes, taking the FIRST Content-Length
    header (`self.headers.get`), exactly as most handlers do; a
    Transfer-Encoding is not decoded (http.server has no chunked reader);
    an unparsable Content-Length reads no body;
  - the path and the query are decoded the usual way: urllib.parse.unquote
    and parse_qs (undecodable bytes become U+FFFD).

After the body it waits 150 ms for bytes that are still on the connection
and reports how many there were (`leftover_len`): bytes this backend would
parse as the start of a NEXT request on a kept-alive connection.

Usage: step23_parsing_backend.py PORT     (binds 127.0.0.1 only, rule 6)
"""
import hashlib
import json
import socket
import socketserver
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote

LEFTOVER_WAIT_S = 0.15


def _json_strings(doc, out):
    if isinstance(doc, dict):
        for k, v in doc.items():
            out.append(k)
            _json_strings(v, out)
    elif isinstance(doc, list):
        for v in doc:
            _json_strings(v, out)
    elif isinstance(doc, str):
        out.append(doc)


def parse_body(content_type, body: bytes) -> dict:
    """Step-27: what this backend's standard parsers make of the body, chosen
    by the media type of the Content-Type header as a handler would: every
    key and string value the parser yields (`strings`), the content of file
    parts apart (`file_strings`), or the parser's error."""
    media = (content_type or "").split(";")[0].strip().lower()
    out = {"kind": "none", "strings": [], "file_strings": [], "error": None}
    try:
        if media == "application/x-www-form-urlencoded":
            out["kind"] = "urlencoded"
            for k, values in parse_qs(body.decode("utf-8", "replace"), keep_blank_values=True).items():
                out["strings"].append(k)
                out["strings"].extend(values)
        elif media == "multipart/form-data":
            import email.parser
            import email.policy
            out["kind"] = "multipart"
            msg = email.parser.BytesParser(policy=email.policy.HTTP).parsebytes(
                b"Content-Type: " + content_type.encode("latin-1") + b"\r\n\r\n" + body)
            if not msg.is_multipart():
                raise ValueError("not multipart")
            for part in msg.iter_parts():
                name = part.get_param("name", header="content-disposition")
                filename = part.get_filename()
                text = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
                if name is not None:
                    out["strings"].append(str(name))
                if filename is not None:
                    out["strings"].append(str(filename))
                    out["file_strings"].append(text)
                else:
                    out["strings"].append(text)
        elif media == "application/json" or media.endswith("+json"):
            import json as _json
            out["kind"] = "json"
            _json_strings(_json.loads(body), out["strings"])
        elif media in ("application/xml", "text/xml") or media.endswith("+xml"):
            import xml.etree.ElementTree as ET
            out["kind"] = "xml"
            for el in ET.fromstring(body).iter():
                out["strings"].append(el.tag)
                if el.text:
                    out["strings"].append(el.text)
                out["strings"].extend(el.attrib.values())
    except Exception as exc:  # the parser refused the body: that is the result
        out["error"] = exc.__class__.__name__
    return out


def describe(handler: BaseHTTPRequestHandler) -> dict:
    """What this backend sees of the request handler has just parsed."""
    target = handler.path
    path_raw, _, query_raw = target.partition("?")
    cl_values = handler.headers.get_all("Content-Length") or []
    te_values = handler.headers.get_all("Transfer-Encoding") or []
    body, how = b"", "none"
    first = handler.headers.get("Content-Length")
    if first is not None:
        try:
            length = int(first)
        except ValueError:
            how = "content-length-unparsable"
        else:
            if length < 0:
                how = "content-length-negative"
            else:
                how = "content-length-first"
                body = handler.rfile.read(length)
    leftover = b""
    handler.connection.settimeout(LEFTOVER_WAIT_S)
    try:
        while len(leftover) < 65536:
            chunk = handler.rfile.read1(65536)
            if not chunk:
                break
            leftover += chunk
    except (socket.timeout, TimeoutError, OSError):
        pass
    return {
        "backend": "python-http.server",
        "method": handler.command,
        "target": target,
        "path_raw": path_raw,
        "path_decoded": unquote(path_raw),
        "query_raw": query_raw,
        "query_decoded": {k: v for k, v in sorted(parse_qs(query_raw, keep_blank_values=True).items())},
        "content_length_headers": cl_values,
        "transfer_encoding_headers": te_values,
        "body_framing": how,
        "body_len": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "leftover_len": len(leftover),
        "body_parse": parse_body(handler.headers.get("Content-Type"), body),
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _answer(self):
        payload = json.dumps(describe(self), ensure_ascii=True).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = _answer


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def server_bind(self):
        # HTTPServer.server_bind looks the host name up (socket.getfqdn), which
        # can take tens of seconds on a machine without a resolver; the name is
        # not needed here
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address[:2]


def serve(port: int) -> ThreadingHTTPServer:
    return Server(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    serve(int(sys.argv[1])).serve_forever()
