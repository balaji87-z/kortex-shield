#!/usr/bin/env python3
"""Step-22 T2 design risk (b): the single-peer-address penalty, as a demo.

Python port of tools/run_step22_t2_penalty_demo.sh for the container run
(no curl, no setsid). With no trusted proxies the client key is the peer
address, so everyone behind one address shares one penalty bucket:
  1) a budget kill caused from 127.0.0.2 (held large-lane request)
  2) an innocent POST from 127.0.0.2 (same address)      -> expect 503
  3) an innocent POST from 127.0.0.5 (different address) -> expect 200
  4) the same innocent POST from 127.0.0.2 after the penalty expired -> expect 200
Linux only (source addresses 127.0.0.x). Engine from KORTEX_T2_ENGINE, rules
from KORTEX_T2_RULES; the stub backend must listen on 13000.
Output: docs/logs/runs/s22-t2-penalty-demo/demo.txt
"""
import importlib.util
import json
import os
import subprocess
import time

spec = importlib.util.spec_from_file_location("t2", os.path.join(os.path.dirname(__file__), "run_step22_t2_attack.py"))
t2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t2)

OUT = "docs/logs/runs/s22-t2-penalty-demo"
PENALTY_MS = 3000


def main():
    os.makedirs(OUT, exist_ok=True)
    env = {
        **os.environ,
        "KORTEX_BACKEND_URL": "http://127.0.0.1:13000", "KORTEX_RULES_DIR": t2.RULES,
        "KORTEX_RULE_ENGINE": "On", "KORTEX_BLOCKING_PARANOIA": "1", "KORTEX_DETECTION_PARANOIA": "1",
        "KORTEX_MAX_BODY_BYTES": "13107200", "KORTEX_MAX_INSPECTED_BYTES": "131072",
        "KORTEX_MAX_INFLIGHT_BODY": "8", "KORTEX_MAX_INFLIGHT_BODY_LARGE": "2",
        "KORTEX_BODY_LANE_THRESHOLD": "65536",
        "KORTEX_ENGINE_TIME_BUDGET_MS": "300", "KORTEX_TEST_HOLD_BODY_MS": "5000",
        "KORTEX_CLIENT_PENALTY_MS": str(PENALTY_MS),
        "KORTEX_LISTEN_ADDR": "127.0.0.1:8098",
        "KORTEX_EVENTS_FILE": "/tmp/kx-s22demo-ev.jsonl", "KORTEX_AUDIT_LOG": "/tmp/kx-s22demo-aud.log",
        "KORTEX_WORKER_MODE": "on", "KORTEX_WORKER_POOL": "2", "KORTEX_WORKER_SPARES": "1",
    }
    proc = subprocess.Popen([t2.ENGINE], env=env, stdout=open(f"{OUT}/engine.log", "w"),
                            stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            if t2.http("http://127.0.0.1:8098/", timeout=2)[0] in (200, 403):
                break
        except Exception:
            time.sleep(0.5)
    lines = []

    def say(text):
        print(text, flush=True)
        lines.append(text)

    url = "http://127.0.0.1:8098/"
    say("rule29: " + json.dumps(t2.effective_config(url)))
    innocent = b"hello world benign note"
    hdrs = {"Content-Type": "text/plain", "User-Agent": t2.BENIGN_UA}
    st, _ = t2.raw_post(t2.BENIGN_URL, innocent, {**hdrs, "X-Kortex-Sample-Id": "demo-before"}, "127.0.0.2")
    say(f"0) innocent POST from 127.0.0.2 before any kill -> {st}")
    st, _ = t2.raw_post(url, b"a" * 131071, {"Content-Type": "text/plain", "X-Kortex-Test-Hold": "1",
                                              "X-Kortex-Sample-Id": "demo-kill"}, "127.0.0.2")
    say(f"1) held 131071-byte request from 127.0.0.2 (budget 300 ms) -> {st}")
    say("   stats: " + json.dumps(t2.stats(url)))
    st, _ = t2.raw_post(t2.BENIGN_URL, innocent, {**hdrs, "X-Kortex-Sample-Id": "demo-same-addr"}, "127.0.0.2")
    say(f"2) innocent POST from the SAME address 127.0.0.2 -> {st}")
    st, _ = t2.raw_post(t2.BENIGN_URL, innocent, {**hdrs, "X-Kortex-Sample-Id": "demo-other-addr"}, "127.0.0.5")
    say(f"3) innocent POST from a DIFFERENT address 127.0.0.5 -> {st}")
    time.sleep(PENALTY_MS / 1000 + 1)
    st, _ = t2.raw_post(t2.BENIGN_URL, innocent, {**hdrs, "X-Kortex-Sample-Id": "demo-after"}, "127.0.0.2")
    say(f"4) innocent POST from 127.0.0.2 after {PENALTY_MS} ms + 1 s -> {st}")
    say("   stats: " + json.dumps(t2.stats(url)))
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    with open(f"{OUT}/demo.txt", "w") as fh:
        fh.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
