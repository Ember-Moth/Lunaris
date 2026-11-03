#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Measure loopback plaintext goodput and separate-process RSS/CPU for SS plugins.

Requires macOS/BSD ps, Go benchmark helper, openssl, and a management-enabled node binary.
The target/client/node are distinct processes. No production source or OS tuning changes.
"""
import argparse
import base64
import contextlib
import datetime
import hashlib
import json
import os
import pathlib
import platform
import queue
import random
import signal
import socket
import statistics
import subprocess
import tempfile
import sys
import threading
import time

sys.dont_write_bytecode = True
from management_client import seed_node, managed_process

ROOT = pathlib.Path(__file__).resolve().parents[1]
COLUMNS = ["seconds", "phase", "node_rss_mib", "node_cpu_seconds", "client_rss_mib", "client_cpu_seconds", "peer_rss_mib", "peer_cpu_seconds"]


def command(*args):
    return subprocess.check_output(args, text=True).strip()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def cpu_seconds(value):
    days, _, value = value.rpartition("-") if "-" in value else ("0", "", value)
    total = 0.0
    for field in value.split(":"):
        total = total * 60 + float(field)
    return total + int(days or 0) * 86400


def resources(pids):
    present = [pid for pid in pids if pid]
    if not present:
        return {}
    output = subprocess.run(["ps", "-p", ",".join(map(str, present)), "-o", "pid=,rss=,time="], capture_output=True, text=True).stdout
    return {int(pid): (float(rss) / 1024, cpu_seconds(cpu)) for pid, rss, cpu in (line.split() for line in output.splitlines() if line.strip())}


def sample(pids, elapsed, phase):
    stats = resources(pids)
    return [round(elapsed, 4), phase, *[round(v, 4) if v is not None else None for pid in pids for v in stats.get(pid, (None, None))]]


@contextlib.contextmanager
def process(args, log, *, pipe=False):
    with log.open("w") as output:
        p = subprocess.Popen(args, stdout=subprocess.PIPE if pipe else output, stderr=output, text=True, bufsize=1)
        try:
            yield p
        finally:
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    p.kill(); p.wait()
            if p.stdout:
                p.stdout.close()


def read_events(p):
    events = queue.Queue()
    def reader():
        for line in p.stdout:
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and "event" in data:
                events.put(data)
    threading.Thread(target=reader, daemon=True).start()
    return events


def observe(pid, seconds):
    rows = []
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        values = resources([pid]).get(pid)
        if values:
            rows.append(values[0])
        time.sleep(0.2)
    return {"median_mib": statistics.median(rows), "peak_mib": max(rows)} if rows else {"median_mib": None, "peak_mib": None}


def run_client(helper, config, node_pid, peer_pid, root):
    path = root / "client.json"
    path.write_text(json.dumps(config)); path.chmod(0o600)
    with process([helper, "--config", str(path)], root / "client.log", pipe=True) as child:
        events = read_events(child)
        began = time.monotonic()
        deadline = began + config["Seconds"] + config["WarmupSeconds"] + 45
        phase, rows, result, error = "setup", [], None, None
        start, end = None, None
        while child.poll() is None or not events.empty():
            changed = False
            while not events.empty():
                event = events.get()
                kind = event["event"]
                if kind == "ready":
                    phase = "hold" if config["Direction"] == "hold" else "warmup"
                elif kind == "measure_start":
                    phase = "measure"
                    start = sample([node_pid, child.pid, peer_pid], time.monotonic() - began, phase)
                    rows.append(start)
                elif kind == "measure_end":
                    end = sample([node_pid, child.pid, peer_pid], time.monotonic() - began, phase)
                    rows.append(end); phase = "cleanup"
                elif kind == "result":
                    result = event
                elif kind == "error":
                    error = event.get("error", "client error")
                changed = True
            rows.append(sample([node_pid, child.pid, peer_pid], time.monotonic() - began, phase))
            if time.monotonic() > deadline:
                error = "benchmark client exceeded total timeout"
                child.kill(); child.wait(); break
            time.sleep(0.2)
        # The pipe reader can deliver the final JSON just after process exit.
        time.sleep(0.02)
        while not events.empty():
            event = events.get()
            if event["event"] == "result":
                result = event
            elif event["event"] == "error":
                error = event.get("error")
        if child.returncode != 0 or result is None or error:
            return {"ok": False, "error": error or f"client exit {child.returncode}", "samples": rows}
    result.pop("event", None)
    result.update(ok=True, samples=rows)
    active = [r for r in rows if r[1] in ("measure", "hold") and r[2] is not None]
    result["node_rss_peak_mib"] = max((r[2] for r in active), default=None)
    result["node_rss_median_mib"] = statistics.median([r[2] for r in active]) if active else None
    if start and end and end[0] > start[0]:
        result["cpu_percent"] = {name: round((end[i] - start[i]) / (end[0] - start[0]) * 100, 2) if end[i] is not None and start[i] is not None else None for name, i in (("node", 3), ("client", 5), ("peer", 7))}
    if "client_cpu_percent" in result:
        result.setdefault("cpu_percent", {})["client"] = result["client_cpu_percent"]
    return result


def variants(peer):
    base = "aes-128-gcm"
    return [
        ("direct", "direct", {}, {}, False, base),
        ("native-aes128", "", {}, {}, False, base),
        ("native-ss2022-aes128", "", {}, {}, False, "2022-blake3-aes-128-gcm"),
        ("obfs-http", "obfs", {"mode": "http"}, {"mode": "http", "host": "localhost"}, False, base),
        ("obfs-tls", "obfs", {"mode": "tls"}, {"mode": "tls", "host": "localhost"}, False, base),
        ("v2ray-wss-mux", "v2ray-plugin", {"mux": True}, {"mode": "websocket", "mux": True, "tls": True, "host": "localhost", "path": "/bench", "skip-cert-verify": True}, True, base),
        ("gost-wss-mux", "gost-plugin", {"mux": True}, {"mode": "websocket", "mux": True, "tls": True, "host": "localhost", "path": "/bench", "skip-cert-verify": True}, True, base),
        ("shadowtls-v3", "shadow-tls", {"version": 3, "handshake": peer["tls13"], "password_ref": "plugin", "strict-mode": True}, {"version": 3, "password": "benchmark-plugin-password", "host": "localhost", "skip-cert-verify": True}, False, base),
        ("restls-tls13", "restls", {"dest": peer["tls13"], "password_ref": "plugin"}, {"host": "localhost", "password": "benchmark-plugin-password", "version-hint": "tls13", "skip-cert-verify": True}, False, base),
        ("kcptun-aes-nocomp", "kcptun", {"key_ref": "plugin", "crypt": "aes", "nocomp": True, "smuxver": 1, "datashard": 10, "parityshard": 3}, {"key": "benchmark-plugin-password", "crypt": "aes", "nocomp": True, "smuxver": 1, "datashard": 10, "parityshard": 3}, False, base),
        ("kcptun-aes-comp", "kcptun", {"key_ref": "plugin", "crypt": "aes", "nocomp": False, "smuxver": 1, "datashard": 10, "parityshard": 3}, {"key": "benchmark-plugin-password", "crypt": "aes", "nocomp": False, "smuxver": 1, "datashard": 10, "parityshard": 3}, False, base),
    ]


def summary(case):
    out = {"name": case["name"], "runs": {}}
    for direction in ("download", "upload"):
        for connections in (1, 8):
            runs = [r for r in case["throughput"] if r.get("ok") and r.get("direction") == direction and r.get("connections") == connections]
            if runs:
                rates = [r["gbps"] for r in runs]
                out["runs"][f"{direction}_{connections}"] = {"median_gbps": statistics.median(rates), "min_gbps": min(rates), "max_gbps": max(rates), "node_rss_peak_mib": max((r["node_rss_peak_mib"] for r in runs if r["node_rss_peak_mib"] is not None), default=None), "median_cpu_percent": {name: statistics.median([r["cpu_percent"][name] for r in runs if r.get("cpu_percent", {}).get(name) is not None]) for name in ("node", "client", "peer") if any(r.get("cpu_percent", {}).get(name) is not None for r in runs)}}
    out["memory"] = case.get("memory", {})
    out["failures"] = [r["error"] for r in case["throughput"] if not r.get("ok")]
    return out


def save(output, report):
    output.parent.mkdir(parents=True, exist_ok=True)
    report["summary"] = [summary(c) for c in report["cases"]]
    temporary = output.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, separators=(",", ":")))
    temporary.replace(output)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server", type=pathlib.Path, default=ROOT / "bin/lunaris-web")
    p.add_argument("--client", type=pathlib.Path, default=ROOT / "bin/ssplugins-bench")
    p.add_argument("--output", type=pathlib.Path, required=True)
    p.add_argument("--filter", default="")
    p.add_argument("--seconds", type=float, default=4)
    p.add_argument("--warmup", type=float, default=1)
    p.add_argument("--repeats", type=int, default=3)
    p.add_argument("--skip-memory", action="store_true")
    args = p.parse_args()
    def terminate(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, terminate)
    if args.repeats < 1 or args.repeats > 10:
        p.error("repeats must be 1 to 10")
    helper, server = str(args.client.resolve()), str(args.server.resolve())
    rng = random.Random(20261101)
    power = command("pmset", "-g", "batt").splitlines()[0]
    node_build = [line.strip() for line in command("go", "version", "-m", server).splitlines()[1:] if line.strip().startswith("build") ]
    report = {"started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "source_commit": command("git", "-C", str(ROOT), "rev-parse", "HEAD"), "node_mode": "managed", "provisioning": "json-api", "server_sha256": hashlib.sha256(pathlib.Path(server).read_bytes()).hexdigest(), "go": command("go", "version"), "power_source":power, "server_build":node_build, "os": platform.platform(), "cpu": command("sysctl", "-n", "machdep.cpu.brand_string"), "cpus": int(command("sysctl", "-n", "hw.ncpu")), "ram_bytes": int(command("sysctl", "-n", "hw.memsize")), "runtime_env": {k: os.environ.get(k, "default") for k in ("GOMAXPROCS", "GOGC", "GOMEMLIMIT")}, "seconds": args.seconds, "warmup_seconds": args.warmup, "repeats": args.repeats, "sample_columns": COLUMNS, "cases": []}
    with tempfile.TemporaryDirectory(prefix="lunaris-throughput-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem"), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        peer = stack.enter_context(process([helper, "--mode", "peer", "--cert", str(root / "cert.pem"), "--key", str(root / "key.pem")], root / "peer.log", pipe=True))
        peer_events = read_events(peer)
        addresses = peer_events.get(timeout=15)
        if addresses["event"] != "ready":
            raise RuntimeError(addresses)
        selected = [v for v in variants(addresses) if args.filter in v[0]]
        if not selected:
            p.error("no matching variants")
        rng.shuffle(selected)
        for name, kind, options, client_options, secure, method in selected:
            port = free_port()
            secret = base64.b64encode(os.urandom(16)).decode() if method.startswith("2022-") else "benchmark-ss-password"
            listener = {"id": "benchmark", "protocol": "shadowsocks", "address": "127.0.0.1", "port": port, "network": ["udp" if kind == "kcptun" else "tcp"], "credential_refs": ["user"], "options": {"method": method}}
            if kind and kind != "direct":
                listener["transport"] = {"type": kind, "plugin": options}
                if kind in ("v2ray-plugin", "gost-plugin"):
                    listener["transport"].update(path="/bench", host="localhost")
            if secure:
                listener["certificate_ref"] = "tls"
            state = None
            if kind != "direct":
                state = seed_node(server, root / f"case-{len(report['cases'])}", listeners=[listener], credentials={"user": secret, "plugin": "benchmark-plugin-password"}, certificates={"tls": (root / "cert.pem", root / "key.pem")})
            common = {"Server": f"127.0.0.1:{port}", "Method": method, "Password": secret, "Plugin": kind, "PluginOpts": client_options, "Target": addresses["data"], "WarmupSeconds": args.warmup, "Seconds": args.seconds}
            case = {"name": name, "method": method, "power_source":command("pmset", "-g", "batt").splitlines()[0], "throughput": []}
            report["cases"].append(case)
            with contextlib.ExitStack() as scope:
                node = None
                if kind != "direct":
                    log = root / "node.log"
                    node = scope.enter_context(managed_process(server, state, log))
                    case["idle_rss"] = observe(node.pid, 1)
                for repeat in range(args.repeats):
                    schedule = [(d, n) for d in ("download", "upload") for n in (1, 8)]
                    rng.shuffle(schedule)
                    for direction, count in schedule:
                        print(f"RUN {name} {direction} c={count} repeat={repeat + 1}", flush=True)
                        result = run_client(helper, {**common, "Direction": direction, "Connections": count}, node.pid if node else None, peer.pid, root)
                        result.update(direction=direction, connections=count, repeat=repeat + 1)
                        case["throughput"].append(result)
                        save(args.output, report)
                        print(f"RESULT {name} {direction} c={count}: " + (f"{result['gbps']:.3f} Gbit/s, RSS {result['node_rss_peak_mib']} MiB" if result["ok"] else "FAIL " + result["error"]), flush=True)
                        if node and node.poll() is not None:
                            raise RuntimeError("node exited during load: " + log.read_text()[-1200:])
            if kind != "direct" and not args.skip_memory:
                print(f"MEMORY {name}", flush=True)
                with managed_process(server, state, root / "node-memory.log") as node:
                    memory = {"idle": observe(node.pid, 1)}
                    case["memory"] = memory
                    for count in (32, 128):
                        held = run_client(helper, {**common, "Direction": "hold", "Connections": count, "WarmupSeconds": 0, "Seconds": 4}, node.pid, peer.pid, root)
                        memory[str(count)] = held
                        memory[f"after_{count}"] = observe(node.pid, 3 if count == 32 else 10)
                        save(args.output, report)
                        print(f"MEMORY RESULT {name} n={count}: {held.get('node_rss_median_mib')} MiB; after close {memory[f'after_{count}']['median_mib']} MiB", flush=True)
            save(args.output, report)
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        report["final_power_source"] = command("pmset", "-g", "batt").splitlines()[0]
        save(args.output, report)
        print(f"Saved {args.output}", flush=True)


if __name__ == "__main__":
    main()
