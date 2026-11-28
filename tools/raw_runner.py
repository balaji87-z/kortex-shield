#!/usr/bin/env python3
"""Step-27: raw-socket runner for manifest samples the Python HTTP client cannot send.

`kortex_eval.runner` builds requests with http.client, which refuses a
target that holds a space or a control character (InvalidURL) and encodes
the request line as ASCII. This runner writes the bytes itself:

    <METHOD> <path>[?<query>] HTTP/1.1\\r\\n
    Host: <host>:<port>\\r\\n
    Accept-Encoding: identity\\r\\n
    X-Kortex-Sample-Id: <id>\\r\\n
    [the sample's own headers] [User-Agent] [Content-Type] [Content-Length]
    \\r\\n
    <body>

with path, query and body exactly as the manifest stores them (UTF-8), no
validation and no escaping, one connection per request, one request at a
time. The header set and order are those http.client sends for the same
sample, so a sample both runners can send goes out as the same bytes.

It writes responses.jsonl and run.json in the format of kortex_eval.runner,
so kortex_eval.outcome reads them unchanged. kortex_eval is not modified.
Local testbed only (rule 6): the base URL must name localhost or 127.0.0.1.

Usage: raw_runner.py --manifest M --base-url http://localhost:PORT --out DIR
           [--block-status 403] [--block-marker REGEX] [--timeout 15]
           [--default-user-agent UA] [--label k=v]...
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from kortex_eval import manifest  # noqa: E402
from kortex_eval.runner import engine_decision, validate_ids  # noqa: E402


def request_bytes(sample, host: str, port: int, default_user_agent: str | None = None) -> bytes:
    target = sample.path + ("?" + sample.query if sample.query else "")
    headers = [("Host", host if port == 80 else f"{host}:{port}"), ("Accept-Encoding", "identity"),
               ("X-Kortex-Sample-Id", sample.id)]
    for name, value in sample.headers.items():
        if name.lower() in ("host", "content-length", "x-kortex-sample-id", "accept-encoding"):
            continue
        headers.append((name, value))
    names = {n.lower() for n, _ in headers}
    if default_user_agent and "user-agent" not in names:
        headers.append(("User-Agent", default_user_agent))
    body = sample.body.encode("utf-8", "surrogatepass") if sample.body else b""
    if sample.body:
        if sample.content_type and "content-type" not in names:
            headers.append(("Content-Type", sample.content_type))
        headers.append(("Content-Length", str(len(body))))
    head = f"{sample.method.upper()} {target} HTTP/1.1\r\n" + "".join(f"{n}: {v}\r\n" for n, v in headers) + "\r\n"
    return head.encode("utf-8", "surrogatepass") + body


def dechunk(body: bytes) -> bytes:
    out, rest = b"", body
    while rest:
        line, _, rest = rest.partition(b"\r\n")
        try:
            size = int(line.split(b";")[0].strip(), 16)
        except ValueError:
            return body
        if size == 0:
            break
        out, rest = out + rest[:size], rest[size + 2:]
    return out


def parse_response(data: bytes) -> tuple[int | None, bytes]:
    """(status, body) of the final response in data; 1xx interim responses are skipped."""
    while True:
        head, sep, body = data.partition(b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].split()
        if not (len(first) >= 2 and first[0].startswith(b"HTTP/") and first[1].isdigit()):
            return None, b""
        status = int(first[1])
        if 100 <= status < 200 and body.startswith(b"HTTP/"):
            data = body
            continue
        lines = [line.lower().replace(b" ", b"") for line in head.split(b"\r\n")[1:]]
        if b"transfer-encoding:chunked" in lines:
            body = dechunk(body)
        else:
            for line in lines:
                if line.startswith(b"content-length:") and line[15:].isdigit():
                    body = body[:int(line[15:])]
        return status, body


def send_one(sample, host, port, timeout, block_status, block_marker, default_user_agent=None) -> dict:
    row = {"id": sample.id, "status": None, "elapsed_ms": None, "blocked": False,
           "body_marker": False, "engine_decision": None, "error": None, "error_class": None}
    start = time.monotonic()
    data = b""
    try:
        raw = request_bytes(sample, host, port, default_user_agent)
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(raw)
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
                status, body = parse_response(data)
                head, sep, rest = data.partition(b"\r\n\r\n")
                if status is not None and sep and b"content-length:" in head.lower():
                    want = [int(l.split(b":")[1]) for l in head.lower().split(b"\r\n")
                            if l.startswith(b"content-length:") and l.split(b":")[1].strip().isdigit()]
                    if want and len(rest) >= want[0] and not (100 <= status < 200):
                        break
    except UnicodeError as exc:
        row["error"], row["error_class"] = f"encoding: {exc.__class__.__name__}: {exc}", "encoding"
        return row
    except (socket.timeout, TimeoutError):
        if not data:
            row["error"], row["error_class"] = "timeout", "timeout"
            return row
    except (ConnectionError, OSError) as exc:
        if not data:
            row["error"], row["error_class"] = f"connection_error: {exc.__class__.__name__}", "connection_error"
            return row
    status, body = parse_response(data)
    if status is None:
        row["error"], row["error_class"] = "http_error: no status line in the answer", "http_error"
        return row
    text = body.decode("utf-8", "replace")
    row["status"] = status
    row["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
    row["body_marker"] = bool(block_marker and block_marker.search(text))
    row["engine_decision"] = engine_decision(status, text)
    row["blocked"] = status == block_status and (block_marker is None or row["body_marker"])
    return row


def run(samples, base_url, out_dir, block_status=403, block_marker=None, timeout=15.0, manifest_sha256=None,
        labels=None, default_user_agent=None) -> dict:
    validate_ids(samples)
    parts = urlsplit(base_url)
    if parts.scheme != "http" or parts.hostname not in ("localhost", "127.0.0.1"):
        raise SystemExit(f"base-url must be http://localhost:PORT or http://127.0.0.1:PORT (rule 6), got {base_url!r}")
    host, port = parts.hostname, parts.port or 80
    marker = re.compile(block_marker) if block_marker else None
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc)
    load_start = [round(x, 2) for x in os.getloadavg()]
    rows = [send_one(s, host, port, timeout, block_status, marker, default_user_agent) for s in samples]
    ended = datetime.datetime.now(datetime.timezone.utc)
    with open(out / "responses.jsonl", "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    with open(out / "predictions.jsonl", "w", encoding="utf-8") as fh:
        for row in rows:
            if row["error"] is None:
                fh.write(json.dumps({"id": row["id"], "flagged": row["blocked"]}) + "\n")
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None
    summary = {
        "runner": "tools/raw_runner.py", "base_url": base_url,
        "started_utc": started.isoformat(timespec="seconds"), "ended_utc": ended.isoformat(timespec="seconds"),
        "load_avg_start": load_start, "load_avg_end": [round(x, 2) for x in os.getloadavg()],
        "git_commit": commit, "manifest_sha256": manifest_sha256, "default_user_agent": default_user_agent,
        "labels": labels or {}, "total_samples": len(rows),
        "responses_ok": sum(1 for r in rows if r["error"] is None),
        "blocked": sum(1 for r in rows if r["blocked"]),
        "error_count": sum(1 for r in rows if r["error"] is not None),
        "block_rule": {"block_status": block_status, "block_marker": block_marker},
    }
    with open(out / "run.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    return summary


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Send manifest samples as raw bytes over a socket.")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--block-status", type=int, default=403)
    ap.add_argument("--block-marker", default=None)
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--default-user-agent", default=None)
    ap.add_argument("--label", action="append", default=[], metavar="KEY=VALUE")
    ap.add_argument("--only-ids", default=None, help="file with one sample id per line: send only these")
    args = ap.parse_args(argv)
    samples = manifest.load(args.manifest)
    if args.only_ids:
        keep = {line.strip() for line in Path(args.only_ids).read_text().splitlines() if line.strip()}
        samples = [s for s in samples if s.id in keep]
    labels = dict(item.split("=", 1) for item in args.label)
    summary = run(samples, args.base_url, args.out, args.block_status, args.block_marker, args.timeout,
                  hashlib.sha256(Path(args.manifest).read_bytes()).hexdigest(), labels, args.default_user_agent)
    print(json.dumps({k: summary[k] for k in ("total_samples", "responses_ok", "blocked", "error_count")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
