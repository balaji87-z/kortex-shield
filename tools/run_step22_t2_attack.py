#!/usr/bin/env python3
"""Step-22 T2: worker-mode attack cells with benign traffic, stats sampling
and whole-process-tree CPU accounting.

One cell = one engine process, one attack shape, one address mode, 300 s.
Attackers loop body POSTs with the deterministic hold hook (rule 48):
X-Kortex-Test-Hold: 1 + KORTEX_TEST_HOLD_BODY_MS makes every attack request
hold its lane slot until the 2 s budget kills the worker.
Benign: 1 body-bearing POST/s + 1 GET/s from a separate loopback address.
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from collections import Counter

ENGINE = "/tmp/kortex-engine"
RULES = os.path.abspath("engine/crs")
OUT = "docs/logs/runs/s22-t2-cells"

LARGE = 131071
SMALL = 32768


def http(url, data=None, headers=None, src=None, timeout=30, method=None):
    if src is None:
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp.status, resp.read()
    import socket
    host, port = url.split("/")[2].split(":")[0], int(url.split("/")[2].split(":")[1])
    path = "/" + url.split("/", 3)[3] if url.count("/") > 3 else "/"
    body = data if data else b""
    m = method or ("POST" if data else "GET")
    hdrs = f"{m} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {len(body)}\r\n"
    for k, v in (headers or {}).items():
        hdrs += f"{k}: {v}\r\n"
    payload = (hdrs + "\r\n").encode() + body
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.bind((src, 0))
    s.connect((host, port))
    s.sendall(payload)
    buf = b""
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > 1 << 20:
                break
    except socket.timeout:
        pass
    s.close()
    head, _, rest = buf.partition(b"\r\n\r\n")
    status = int(head.split(b" ")[1]) if head else 0
    return status, rest


def raw_post(url, body, headers, src, timeout=30):
    return http(url, data=body, headers=headers, src=src, timeout=timeout, method="POST")


def raw_get(url, src, timeout=30):
    return http(url, src=src, timeout=timeout, method="GET")


def tree_cpu_ticks(pid):
    """utime+stime of pid and every descendant, in clock ticks."""
    total = 0
    try:
        with open(f"/proc/{pid}/stat") as f:
            parts = f.read().rsplit(") ", 1)[1].split()
            total += int(parts[11]) + int(parts[12])  # fields 14,15 1-indexed
    except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
        pass
    try:
        children = os.listdir("/proc")
    except OSError:
        return total
    for d in children:
        if not d.isdigit() or d == str(pid):
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                parts = f.read().rsplit(") ", 1)[1].split()
                if int(parts[1]) == pid:  # ppid
                    total += int(parts[11]) + int(parts[12])
        except (FileNotFoundError, ProcessLookupError, IndexError, ValueError):
            continue
    return total


def stats(url):
    # NOTE: url may end with "/" -> "//__kortex/stats" would be proxied to the
    # backend (mux does not clean it) and json.loads("ok") would throw, so
    # normalise here.
    try:
        st, body = http(url.rstrip("/") + "/__kortex/stats", timeout=5)
        if st == 200:
            return json.loads(body)
    except Exception:
        pass
    return None


def run_cell(name, pl, attack_size, n_attackers, duration=300, budget_ms=2000,
             hold_ms=120000, base="127.0.0.1:8098", benign_src="127.0.0.10"):
    os.makedirs(OUT, exist_ok=True)
    ev = f"/tmp/kx-s22-{name}-events.jsonl"
    aud = f"/tmp/kx-s22-{name}-audit.log"
    for p in (ev, aud):
        if os.path.exists(p):
            os.unlink(p)
    env = {
        **os.environ,
        "KORTEX_BACKEND_URL": "http://127.0.0.1:13000",
        "KORTEX_RULES_DIR": RULES,
        "KORTEX_RULE_ENGINE": "On",
        "KORTEX_BLOCKING_PARANOIA": str(pl),
        "KORTEX_DETECTION_PARANOIA": str(pl),
        "KORTEX_MAX_BODY_BYTES": "13107200",
        "KORTEX_MAX_INSPECTED_BYTES": "131072",
        "KORTEX_ENGINE_TIME_BUDGET_MS": str(budget_ms),
        "KORTEX_LISTEN_ADDR": base,
        "KORTEX_EVENTS_FILE": ev,
        "KORTEX_AUDIT_LOG": aud,
        "KORTEX_WORKER_MODE": "on",
        "KORTEX_WORKER_POOL": "3",
        "KORTEX_WORKER_SPARES": "1",
        "KORTEX_WORKER_RECYCLE_AFTER": "1000",
        "KORTEX_CLIENT_MAX_INFLIGHT": "2",
        "KORTEX_CLIENT_PENALTY_MS": "10000",
        "KORTEX_TEST_HOLD_BODY_MS": str(hold_ms),
    }
    proc = subprocess.Popen([ENGINE], env=env,
                            stdout=open(f"{OUT}/engine-{name}.log", "w"),
                            stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            if http(f"http://{base}/", timeout=2)[0] in (200, 403):
                break
        except Exception:
            time.sleep(0.5)
    url = f"http://{base}/"
    attack_body = b"x" * attack_size
    attack_hdrs = {"Content-Type": "text/plain", "X-Kortex-Test-Hold": "1",
                   "X-Kortex-Sample-Id": f"s22-{name}-atk"}
    benign_body = json.dumps({"k": "v", "n": 1}).encode()
    benign_hdrs = {"Content-Type": "application/json",
                   "X-Kortex-Sample-Id": f"s22-{name}-benign"}
    if n_attackers == 1:
        addrs = ["127.0.0.2"]
    else:
        addrs = [f"127.0.0.{i}" for i in range(2, 2 + n_attackers)]

    stop = threading.Event()
    results = {"benign_post": [], "benign_get": [], "attack_status": Counter()}

    def attacker(addr):
        next_t = time.time()
        while not stop.is_set():
            next_t += 1.0
            try:
                st, _ = raw_post(url, attack_body, attack_hdrs, addr, timeout=30)
                results["attack_status"][st] += 1
            except Exception:
                results["attack_status"][-1] += 1
            delay = next_t - time.time()
            if delay > 0:
                time.sleep(delay)

    def benign_loop():
        next_t = time.time()
        while not stop.is_set():
            next_t += 1.0
            t0 = time.time()
            try:
                st, _ = raw_post(url, benign_body, benign_hdrs, benign_src, timeout=30)
                results["benign_post"].append((st, round((time.time() - t0) * 1000, 1)))
            except Exception as e:
                results["benign_post"].append((-1, round((time.time() - t0) * 1000, 1)))
            t0 = time.time()
            try:
                st, _ = raw_get(url + "/?q=benign", benign_src, timeout=30)
                results["benign_get"].append((st, round((time.time() - t0) * 1000, 1)))
            except Exception:
                results["benign_get"].append((-1, round((time.time() - t0) * 1000, 1)))
            delay = next_t - time.time()
            if delay > 0:
                time.sleep(delay)

    samples = []
    cpu0 = tree_cpu_ticks(proc.pid)
    t_start = time.time()
    load0 = os.getloadavg()[0]

    def sampler():
        while not stop.is_set():
            s = stats(url)
            if s:
                s["t"] = round(time.time() - t_start, 1)
                samples.append(s)
            time.sleep(1.0)

    threads = [threading.Thread(target=attacker, args=(a,), daemon=True) for a in addrs]
    threads.append(threading.Thread(target=benign_loop, daemon=True))
    threads.append(threading.Thread(target=sampler, daemon=True))
    for t in threads:
        t.start()
    time.sleep(duration)
    attack_end = time.time()
    stop.set()
    for t in threads:
        t.join(timeout=35)

    # recovery phase: no attackers; watch stats + benign POST success
    rec_samples = []
    recovery = None
    conf_pool = 4
    t_rec0 = time.time()
    while time.time() - t_rec0 < 180:
        s = stats(url)
        if s:
            s["t"] = round(time.time() - attack_end, 1)
            rec_samples.append(s)
        try:
            st, _ = raw_post(url, benign_body, benign_hdrs, benign_src, timeout=15)
        except Exception:
            st = -1
        ok = (st == 200 and s and s["workers"]["pool"] >= conf_pool
              and s["penalised_clients"] == 0 and s["inflight_small"] == 0
              and s["inflight_large"] == 0)
        if ok and recovery is None:
            recovery = round(time.time() - attack_end, 1)
            break
        time.sleep(0.5)
    cpu1 = tree_cpu_ticks(proc.pid)
    load1 = os.getloadavg()[0]
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    CLK = os.sysconf("SC_CLK_TCK")
    out = {
        "cell": name, "pl": pl, "attack_size": attack_size,
        "n_attackers": n_attackers, "duration_s": duration,
        "budget_ms": budget_ms, "hold_ms": hold_ms,
        "benign_post_n": len(results["benign_post"]),
        "benign_post_ok": sum(1 for st, _ in results["benign_post"] if st == 200),
        "benign_get_n": len(results["benign_get"]),
        "benign_get_ok": sum(1 for st, _ in results["benign_get"] if st == 200),
        "benign_post_ms": sorted(m for _, m in results["benign_post"]),
        "benign_get_ms": sorted(m for _, m in results["benign_get"]),
        "attack_status": dict(results["attack_status"]),
        "kills_total": samples[-1]["kills"] if samples else None,
        "overloads_total": samples[-1]["overloads"] if samples else None,
        "min_pool": min((s["workers"]["pool"] for s in samples), default=None),
        "min_spares_idle": min((s["workers"]["spares"] for s in samples), default=None),
        "max_busy": max((s["workers"]["busy"] for s in samples), default=None),
        "penalised_max": max((s["penalised_clients"] for s in samples), default=None),
        "cpu_ticks": cpu1 - cpu0, "cpu_seconds": round((cpu1 - cpu0) / CLK, 1),
        "load_start": load0, "load_end": load1,
        "recovery_s": recovery,
        "recovery_watch_s": round(time.time() - attack_end, 1),
        "stats_samples": samples,
        "recovery_samples": rec_samples,
    }
    with open(f"{OUT}/cell-{name}.json", "w") as f:
        json.dump(out, f, indent=1)
    print(f"cell {name}: post {out['benign_post_ok']}/{out['benign_post_n']} "
          f"get {out['benign_get_ok']}/{out['benign_get_n']} kills={out['kills_total']} "
          f"overloads={out['overloads_total']} minpool={out['min_pool']} "
          f"cpu={out['cpu_seconds']}s recovery={out['recovery_s']}s", flush=True)


def run_mixed(name, pl, n_addrs, duration=300):
    """4 large-lane + 4 small-lane attackers, one or eight addresses."""
    os.makedirs(OUT, exist_ok=True)
    ev = f"/tmp/kx-s22-{name}-events.jsonl"
    aud = f"/tmp/kx-s22-{name}-audit.log"
    env = {
        **os.environ,
        "KORTEX_BACKEND_URL": "http://127.0.0.1:13000",
        "KORTEX_RULES_DIR": RULES,
        "KORTEX_RULE_ENGINE": "On",
        "KORTEX_BLOCKING_PARANOIA": str(pl),
        "KORTEX_DETECTION_PARANOIA": str(pl),
        "KORTEX_MAX_BODY_BYTES": "13107200",
        "KORTEX_MAX_INSPECTED_BYTES": "131072",
        "KORTEX_ENGINE_TIME_BUDGET_MS": "2000",
        "KORTEX_LISTEN_ADDR": "127.0.0.1:8098",
        "KORTEX_EVENTS_FILE": ev,
        "KORTEX_AUDIT_LOG": aud,
        "KORTEX_WORKER_MODE": "on",
        "KORTEX_WORKER_POOL": "3",
        "KORTEX_WORKER_SPARES": "1",
        "KORTEX_WORKER_RECYCLE_AFTER": "1000",
        "KORTEX_CLIENT_MAX_INFLIGHT": "2",
        "KORTEX_CLIENT_PENALTY_MS": "10000",
        "KORTEX_TEST_HOLD_BODY_MS": "120000",
    }
    proc = subprocess.Popen([ENGINE], env=env,
                            stdout=open(f"{OUT}/engine-{name}.log", "w"),
                            stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            if http("http://127.0.0.1:8098/", timeout=2)[0] in (200, 403):
                break
        except Exception:
            time.sleep(0.5)
    url = "http://127.0.0.1:8098/"
    benign_body = json.dumps({"k": "v", "n": 1}).encode()
    benign_hdrs = {"Content-Type": "application/json",
                   "X-Kortex-Sample-Id": f"s22-{name}-benign"}
    if n_addrs == 1:
        large_addrs = ["127.0.0.2"] * 4
        small_addrs = ["127.0.0.2"] * 4
    else:
        large_addrs = [f"127.0.0.{i}" for i in range(2, 6)]
        small_addrs = [f"127.0.0.{i}" for i in range(6, 10)]
    stop = threading.Event()
    results = {"benign_post": [], "benign_get": [], "attack_status": Counter()}

    def attacker(addr, size):
        hdrs = {"Content-Type": "text/plain", "X-Kortex-Test-Hold": "1",
                "X-Kortex-Sample-Id": f"s22-{name}-atk"}
        body = b"x" * size
        while not stop.is_set():
            try:
                st, _ = raw_post(url, body, hdrs, addr, timeout=30)
                results["attack_status"][st] += 1
            except Exception:
                results["attack_status"][-1] += 1
                time.sleep(0.05)

    def benign_loop():
        next_t = time.time()
        while not stop.is_set():
            next_t += 1.0
            t0 = time.time()
            try:
                st, _ = raw_post(url, benign_body, benign_hdrs, "127.0.0.10", timeout=30)
                results["benign_post"].append((st, round((time.time() - t0) * 1000, 1)))
            except Exception:
                results["benign_post"].append((-1, round((time.time() - t0) * 1000, 1)))
            t0 = time.time()
            try:
                st, _ = raw_get(url + "/?q=benign", "127.0.0.10", timeout=30)
                results["benign_get"].append((st, round((time.time() - t0) * 1000, 1)))
            except Exception:
                results["benign_get"].append((-1, round((time.time() - t0) * 1000, 1)))
            delay = next_t - time.time()
            if delay > 0:
                time.sleep(delay)

    samples = []
    cpu0 = tree_cpu_ticks(proc.pid)
    t_start = time.time()
    load0 = os.getloadavg()[0]

    def sampler():
        while not stop.is_set():
            s = stats(url)
            if s:
                s["t"] = round(time.time() - t_start, 1)
                samples.append(s)
            time.sleep(1.0)

    threads = [threading.Thread(target=attacker, args=(a, LARGE), daemon=True)
               for a in large_addrs]
    threads += [threading.Thread(target=attacker, args=(a, SMALL), daemon=True)
                for a in small_addrs]
    threads.append(threading.Thread(target=benign_loop, daemon=True))
    threads.append(threading.Thread(target=sampler, daemon=True))
    for t in threads:
        t.start()
    time.sleep(duration)
    attack_end = time.time()
    stop.set()
    for t in threads:
        t.join(timeout=35)
    rec_samples = []
    recovery = None
    t_rec0 = time.time()
    while time.time() - t_rec0 < 180:
        s = stats(url)
        if s:
            s["t"] = round(time.time() - attack_end, 1)
            rec_samples.append(s)
        try:
            st, _ = raw_post(url, benign_body, benign_hdrs, "127.0.0.10", timeout=15)
        except Exception:
            st = -1
        ok = (st == 200 and s and s["workers"]["pool"] >= 4
              and s["penalised_clients"] == 0 and s["inflight_small"] == 0
              and s["inflight_large"] == 0)
        if ok and recovery is None:
            recovery = round(time.time() - attack_end, 1)
            break
        time.sleep(0.5)
    cpu1 = tree_cpu_ticks(proc.pid)
    load1 = os.getloadavg()[0]
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    CLK = os.sysconf("SC_CLK_TCK")
    out = {
        "cell": name, "pl": pl, "attack": "mixed 4 large + 4 small",
        "n_addrs": n_addrs, "duration_s": duration,
        "benign_post_n": len(results["benign_post"]),
        "benign_post_ok": sum(1 for st, _ in results["benign_post"] if st == 200),
        "benign_get_n": len(results["benign_get"]),
        "benign_get_ok": sum(1 for st, _ in results["benign_get"] if st == 200),
        "benign_post_ms": sorted(m for _, m in results["benign_post"]),
        "benign_get_ms": sorted(m for _, m in results["benign_get"]),
        "attack_status": dict(results["attack_status"]),
        "kills_total": samples[-1]["kills"] if samples else None,
        "overloads_total": samples[-1]["overloads"] if samples else None,
        "min_pool": min((s["workers"]["pool"] for s in samples), default=None),
        "min_spares_idle": min((s["workers"]["spares"] for s in samples), default=None),
        "max_busy": max((s["workers"]["busy"] for s in samples), default=None),
        "penalised_max": max((s["penalised_clients"] for s in samples), default=None),
        "cpu_ticks": cpu1 - cpu0, "cpu_seconds": round((cpu1 - cpu0) / CLK, 1),
        "load_start": load0, "load_end": load1,
        "recovery_s": recovery,
        "stats_samples": samples,
        "recovery_samples": rec_samples,
    }
    with open(f"{OUT}/cell-{name}.json", "w") as f:
        json.dump(out, f, indent=1)
    print(f"cell {name}: post {out['benign_post_ok']}/{out['benign_post_n']} "
          f"get {out['benign_get_ok']}/{out['benign_get_n']} kills={out['kills_total']} "
          f"overloads={out['overloads_total']} minpool={out['min_pool']} "
          f"cpu={out['cpu_seconds']}s recovery={out['recovery_s']}s", flush=True)


def kill_storm(duration=120):
    """8 addresses, cheapest budget-exceeding request, as fast as allowed."""
    name = "killstorm"
    os.makedirs(OUT, exist_ok=True)
    ev = f"/tmp/kx-s22-{name}-events.jsonl"
    aud = f"/tmp/kx-s22-{name}-audit.log"
    env = {
        **os.environ,
        "KORTEX_BACKEND_URL": "http://127.0.0.1:13000",
        "KORTEX_RULES_DIR": RULES,
        "KORTEX_RULE_ENGINE": "On",
        "KORTEX_BLOCKING_PARANOIA": "1",
        "KORTEX_DETECTION_PARANOIA": "1",
        "KORTEX_MAX_BODY_BYTES": "13107200",
        "KORTEX_MAX_INSPECTED_BYTES": "131072",
        "KORTEX_ENGINE_TIME_BUDGET_MS": "2000",
        "KORTEX_LISTEN_ADDR": "127.0.0.1:8098",
        "KORTEX_EVENTS_FILE": ev,
        "KORTEX_AUDIT_LOG": aud,
        "KORTEX_WORKER_MODE": "on",
        "KORTEX_WORKER_POOL": "3",
        "KORTEX_WORKER_SPARES": "1",
        "KORTEX_WORKER_RECYCLE_AFTER": "1000",
        "KORTEX_CLIENT_MAX_INFLIGHT": "2",
        "KORTEX_CLIENT_PENALTY_MS": "10000",
        "KORTEX_TEST_HOLD_BODY_MS": "120000",
    }
    proc = subprocess.Popen([ENGINE], env=env,
                            stdout=open(f"{OUT}/engine-{name}.log", "w"),
                            stderr=subprocess.STDOUT)
    for _ in range(120):
        try:
            if http("http://127.0.0.1:8098/", timeout=2)[0] in (200, 403):
                break
        except Exception:
            time.sleep(0.5)
    url = "http://127.0.0.1:8098/"
    body = b"x" * 64
    hdrs = {"Content-Type": "text/plain", "X-Kortex-Test-Hold": "1",
            "X-Kortex-Sample-Id": "s22-killstorm"}
    addrs = [f"127.0.0.{i}" for i in range(2, 10)]
    stop = threading.Event()
    statuses = Counter()

    def attacker(addr):
        while not stop.is_set():
            try:
                st, _ = raw_post(url, body, hdrs, addr, timeout=10)
                statuses[st] += 1
            except Exception:
                statuses[-1] += 1

    samples = []
    cpu0 = tree_cpu_ticks(proc.pid)
    t0 = time.time()

    def sampler():
        while not stop.is_set():
            s = stats(url)
            if s:
                s["t"] = round(time.time() - t0, 1)
                samples.append(s)
            time.sleep(0.5)

    threads = [threading.Thread(target=attacker, args=(a,), daemon=True) for a in addrs]
    threads.append(threading.Thread(target=sampler, daemon=True))
    for t in threads:
        t.start()
    time.sleep(duration)
    stop.set()
    for t in threads:
        t.join(timeout=15)
    cpu1 = tree_cpu_ticks(proc.pid)
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    CLK = os.sysconf("SC_CLK_TCK")
    out = {
        "duration_s": duration, "attack_status": dict(statuses),
        "kills_total": samples[-1]["kills"] if samples else None,
        "overloads_total": samples[-1]["overloads"] if samples else None,
        "kills_per_s": round((samples[-1]["kills"] / duration), 2) if samples else None,
        "min_pool": min((s["workers"]["pool"] for s in samples), default=None),
        "min_spares_idle": min((s["workers"]["spares"] for s in samples), default=None),
        "cpu_seconds": round((cpu1 - cpu0) / CLK, 1),
        "load_end": os.getloadavg()[0],
        "stats_samples": samples,
    }
    with open(f"{OUT}/cell-{name}.json", "w") as f:
        json.dump(out, f, indent=1)
    print(f"killstorm: kills={out['kills_total']} ({out['kills_per_s']}/s) "
          f"minpool={out['min_pool']} minidle={out['min_spares_idle']} "
          f"cpu={out['cpu_seconds']}s", flush=True)


if __name__ == "__main__":
    cells = [
        ("large-one", 1, LARGE, 1),
        ("large-eight", 1, LARGE, 8),
        ("small-one", 2, SMALL, 1),
        ("small-eight", 2, SMALL, 8),
        ("mixed-one", 1, LARGE, 1),   # mixed handled below
        ("mixed-eight", 1, LARGE, 8),
    ]
    which = sys.argv[1] if len(sys.argv) > 1 else "all"
    if which == "all":
        for name, pl, size, n in cells[:4]:
            run_cell(name, pl, size, n)
        # mixed: 4 large + 4 small attackers concurrently
        run_mixed("mixed-one", 1, 1)
        run_mixed("mixed-eight", 1, 8)
        kill_storm()
    elif which == "storm":
        kill_storm()
    else:
        for name, pl, size, n in cells:
            if name == which:
                run_cell(name, pl, size, n)
