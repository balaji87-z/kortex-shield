#!/usr/bin/env python3
"""Step-22 T2: one line per recorded attack cell.

Usage: step22_t2_cells_summary.py <cells-dir>...
Reads cell-*.json written by tools/run_step22_t2_attack.py. Benign counts are
requests answered 200 over requests sent, during the attack; the statuses of
the others are listed when the cell recorded them (older cells did not).
"""
import glob
import json
import os
import sys

ORDER = ["large-one", "large-eight", "small-one", "small-eight", "mixed-one", "mixed-eight", "killstorm"]


def pct(values, q):
    values = sorted(values)
    return values[min(len(values) - 1, int(round(q * (len(values) - 1))))] if values else None


def main():
    for d in sys.argv[1:]:
        print(f"== {d}")
        files = {os.path.basename(f)[5:-5]: f for f in glob.glob(f"{d}/cell-*.json")}
        for name in ORDER + sorted(set(files) - set(ORDER)):
            if name not in files:
                print(f"   {name}: no cell file")
                continue
            c = json.load(open(files[name]))
            cfg = c.get("effective_config") or {}
            if "benign_post_n" not in c:
                print(f"   {name}: {c.get('duration_s')} s, kills={c.get('kills_total')} ({c.get('kills_per_s')}/s) "
                      f"overloads={c.get('overloads_total')} min_pool={c.get('min_pool')} "
                      f"min_spares_idle={c.get('min_spares_idle')} cpu_s={c.get('cpu_seconds')} "
                      f"attack_status={c.get('attack_status')} load_end={c.get('load_end')}")
                continue
            print(f"   {name}: pl={c.get('pl')} {c.get('duration_s')} s "
                  f"preflight={c.get('benign_preflight_post_get', 'not recorded')} "
                  f"benign POST 200: {c['benign_post_ok']}/{c['benign_post_n']} {c.get('benign_post_status', '(statuses not recorded)')} "
                  f"benign GET 200: {c['benign_get_ok']}/{c['benign_get_n']} {c.get('benign_get_status', '(statuses not recorded)')}")
            print(f"       benign POST ms p50={pct(c['benign_post_ms'], .5)} p99={pct(c['benign_post_ms'], .99)} max={max(c['benign_post_ms'])}; "
                  f"kills={c['kills_total']} overloads={c['overloads_total']} min_pool={c['min_pool']} "
                  f"max_busy={c.get('max_busy')} penalised_max={c['penalised_max']} cpu_s={c['cpu_seconds']} "
                  f"recovery_s={c['recovery_s']} load {c.get('load_start')}->{c.get('load_end')}")
            print(f"       attack_status={c['attack_status']} effective caps: client_max_inflight={cfg.get('client_max_inflight', 'not recorded')} "
                  f"small={cfg.get('client_max_inflight_small', 'not recorded')} large={cfg.get('client_max_inflight_large', 'not recorded')} "
                  f"worker_mode={cfg.get('worker_mode', 'not recorded')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
