"""Request runner: replays manifest samples verbatim against a base URL.

Convention (see README): `path`, `query` and `body` in a Sample are the raw
bytes exactly as they go on the wire. `query` carries no leading "?" and is
already percent-encoded as intended. This runner sends them unmodified via
http.client, which does not re-encode the request line.

A verdict is the WAF's decision, not the target app's status: a response is
"blocked" only when the status equals --block-status AND the body matches
--block-marker (see docs/block-discriminator.md for why the marker is needed).
A timeout or connection error is recorded as an error, never as "not flagged".
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import hashlib
import http.client
import json
import re
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from . import manifest
from .manifest import Sample

SAMPLE_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
DEFAULT_BLOCK_STATUS = 403
DEFAULT_BLOCK_MARKER = r"<center>nginx</center>"


class RunnerError(ValueError):
    pass


def validate_ids(samples: list[Sample]) -> None:
    """Refuse samples whose id is not [A-Za-z0-9._:-]{1,64}. Never rewrite ids."""
    bad = [s.id for s in samples if not SAMPLE_ID_RE.match(s.id)]
    if bad:
        raise RunnerError(
            "sample ids outside [A-Za-z0-9._:-]{1,64}: " + ", ".join(repr(b) for b in bad)
        )


def _request_line(sample: Sample) -> str:
    target = sample.path
    if sample.query:
        target += "?" + sample.query
    return target


def send_one(
    sample: Sample,
    host: str,
    port: int,
    timeout: float,
    block_status: int,
    block_marker: re.Pattern[str] | None,
) -> dict:
    """Send one sample verbatim. Returns a responses.jsonl row."""
    row = {"id": sample.id, "status": None, "elapsed_ms": None, "blocked": False,
           "body_marker": False, "error": None}
    start = time.monotonic()
    conn: http.client.HTTPConnection | None = None
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        headers = {"Accept-Encoding": "identity", "X-Kortex-Sample-Id": sample.id}
        for name, value in sample.headers.items():
            if name.lower() in ("host", "content-length"):
                continue  # http.client sets Host; Content-Length comes from the body
            headers[name] = value
        body_bytes = sample.body.encode("utf-8", "surrogatepass") if sample.body else None
        if body_bytes is not None:
            if sample.content_type:
                headers["Content-Type"] = sample.content_type
            headers["Content-Length"] = str(len(body_bytes))
        # putrequest sends the target string verbatim on the request line
        # (no re-encoding); it only rejects control characters.
        conn.request(sample.method.upper(), _request_line(sample), body=body_bytes, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        row["status"] = resp.status
        row["elapsed_ms"] = round((time.monotonic() - start) * 1000, 1)
        marker_hit = bool(block_marker and block_marker.search(body.decode("utf-8", "replace")))
        row["body_marker"] = marker_hit
        if resp.status == block_status and (block_marker is None or marker_hit):
            row["blocked"] = True
    except (socket.timeout, TimeoutError):
        row["error"] = "timeout"
    except (ConnectionError, OSError) as exc:
        row["error"] = f"connection_error: {exc.__class__.__name__}"
    except http.client.HTTPException as exc:
        row["error"] = f"http_error: {exc.__class__.__name__}: {exc}"
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass
    return row


def run(
    samples: list[Sample],
    base_url: str,
    out_dir: str | Path,
    block_status: int = DEFAULT_BLOCK_STATUS,
    block_marker: str | None = DEFAULT_BLOCK_MARKER,
    workers: int = 8,
    timeout: float = 10.0,
    manifest_sha256: str | None = None,
    labels: dict[str, str] | None = None,
) -> dict:
    """Run all samples; write responses.jsonl, predictions.jsonl, run.json.

    Returns the run summary. Raises RunnerError before anything is sent if any
    sample id is invalid.
    """
    validate_ids(samples)  # refuses (and lists) bad ids before any request is sent
    parts = urlsplit(base_url)
    if parts.scheme != "http" or not parts.hostname:
        raise RunnerError(f"base-url must be an http://host:port URL, got {base_url!r}")
    host, port = parts.hostname, parts.port or 80
    marker = re.compile(block_marker) if block_marker else None

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    started = datetime.datetime.now(datetime.timezone.utc)

    rows: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(send_one, s, host, port, timeout, block_status, marker) for s in samples]
        rows = [f.result() for f in futures]

    ended = datetime.datetime.now(datetime.timezone.utc)

    with open(out / "responses.jsonl", "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")

    predictions = [
        {"id": row["id"], "flagged": row["blocked"]} for row in rows if row["error"] is None
    ]
    with open(out / "predictions.jsonl", "w", encoding="utf-8") as fh:
        for p in predictions:
            fh.write(json.dumps(p) + "\n")

    commit = None
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = None  # not a git checkout; recorded as null

    error_count = sum(1 for row in rows if row["error"] is not None)
    summary = {
        "base_url": base_url,
        "started_utc": started.isoformat(timespec="seconds"),
        "ended_utc": ended.isoformat(timespec="seconds"),
        "git_commit": commit,
        "manifest_sha256": manifest_sha256,
        "labels": labels or {},
        "total_samples": len(rows),
        "responses_ok": len(predictions),
        "blocked": sum(1 for row in rows if row["blocked"]),
        "error_count": error_count,
        "block_rule": {
            "block_status": block_status,
            "block_marker": block_marker,
        },
    }
    with open(out / "run.json", "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=2)
        fh.write("\n")
    return summary


def file_sha256(path: str | Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description="Replay manifest samples verbatim against a base URL.")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--base-url", required=True)
    ap.add_argument("--out", required=True, help="output directory, e.g. out/<run-name>/")
    ap.add_argument("--block-status", type=int, default=DEFAULT_BLOCK_STATUS)
    ap.add_argument("--block-marker", default=DEFAULT_BLOCK_MARKER,
                    help="regex matched against the response body to confirm a block "
                         "(empty string disables the marker check)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--label", action="append", default=[], metavar="KEY=VALUE",
                    help="provenance label recorded in run.json (repeatable)")
    args = ap.parse_args()

    labels: dict[str, str] = {}
    for item in args.label:
        if "=" not in item:
            print(f"runner: --label expects KEY=VALUE, got {item!r}", file=sys.stderr)
            return 2
        key, value = item.split("=", 1)
        labels[key] = value

    samples = manifest.load(args.manifest)
    try:
        summary = run(
            samples,
            args.base_url,
            args.out,
            block_status=args.block_status,
            block_marker=args.block_marker or None,
            workers=args.workers,
            timeout=args.timeout,
            manifest_sha256=file_sha256(args.manifest),
            labels=labels,
        )
    except (manifest.ManifestError, RunnerError) as exc:
        print(f"runner: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary))
    if summary["error_count"]:
        print(f"runner: {summary['error_count']} sample(s) had errors", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
