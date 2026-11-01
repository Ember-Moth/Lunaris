#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Loopback Naive and SS2022 interop with a supplied official sing-box binary."""
import argparse
import base64
import contextlib
import importlib.util
import json
import pathlib
import socketserver
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("extensions", pathlib.Path(__file__).with_name("test-extensions.py"))
ext = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ext)
base = ext.base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=pathlib.Path, required=True)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris"))
    parser.add_argument("--skip-naive-quic", action="store_true", help="Explicitly skip the released-client HTTP/3 case when its UDP socket path is unavailable")
    args = parser.parse_args()
    client, server = str(args.client.resolve()), str(args.server.resolve())
    subprocess.run([client, "version"], check=True)
    with tempfile.TemporaryDirectory(prefix="lunaris-naive-ss2022-") as tmp, contextlib.ExitStack() as stack:
        root = pathlib.Path(tmp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTCP)
        udp = socketserver.UDPServer(("127.0.0.1", 0), base.EchoUDP)
        for echo in (tcp, udp):
            echo.daemon_threads = True
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            stack.callback(echo.server_close)
            stack.callback(echo.shutdown)
        used = set()
        def port():
            value = base.free_port()
            while value in used:
                value = base.free_port()
            used.add(value)
            return value
        credentials = [{"id": "password", "secret": base.PASSWORD}]
        listeners, cases = [], []
        for quic in (False, True):
            if quic and args.skip_naive_quic:
                print("SKIP naive/h3: explicitly requested; Go HTTP/3 integration tests are separate.", flush=True)
                continue
            endpoint = port()
            listeners.append({"id": f"naive-{quic}", "protocol": "naive", "address": "127.0.0.1", "port": endpoint, "credential_refs": ["password"], "certificate_ref": "tls", "transport": {"type": "quic" if quic else "http"}, "options": {"users": [{"username": "alice", "credential_ref": "password"}]}})
            outbound = {"type": "naive", "server": "127.0.0.1", "server_port": endpoint, "username": "alice", "password": base.PASSWORD, "quic": quic, "udp_over_tcp": {"enabled": True, "version": 2}, "tls": {"enabled": True, "server_name": "localhost", "certificate_path": str(cert)}}
            cases.append((f"naive/{'h3' if quic else 'h2'}", outbound))
        for method in ("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"):
            size = 16 if "aes-128" in method else 32
            keys = [base64.b64encode(bytes([b]) * size).decode() for b in (1, 2, 3)]
            ids = [f"{method}-{i}" for i in range(3)]
            credentials += [{"id": ref, "secret": secret} for ref, secret in zip(ids, keys)]
            for multi in (False, True):
                if multi and "chacha20" in method:
                    continue
                endpoint = port()
                options = {"method": method}
                refs = ids[:1]
                if multi:
                    options["server_key_ref"] = ids[2]
                    refs = ids[:2]
                listeners.append({"id": f"{method}-{multi}", "protocol": "shadowsocks", "address": "127.0.0.1", "port": endpoint, "credential_refs": refs, "options": options, "udp_over_tcp": True, "multiplex": {"enabled": True, "padding": True}})
                for user in range(len(refs)):
                    password = keys[user] if not multi else f"{keys[2]}:{keys[user]}"
                    for mode in ("native", "uot-v1", "uot-v2", "smux", "yamux", "h2mux"):
                        outbound = {"type": "shadowsocks", "server": "127.0.0.1", "server_port": endpoint, "method": method, "password": password}
                        if mode.startswith("uot"):
                            outbound["udp_over_tcp"] = {"enabled": True, "version": int(mode[-1])}
                        elif mode != "native":
                            outbound["multiplex"] = {"enabled": True, "protocol": mode, "padding": True}
                        cases.append((f"{method}/multi={multi}/user={user}/{mode}", outbound))
        node = root / "node.yaml"
        # JSON is also valid YAML; configuration remains strict and portable.
        node.write_text(json.dumps({"schema_version": 1, "credentials": credentials, "certificates": [{"id": "tls", "certificate_file": "cert.pem", "private_key_file": "key.pem"}], "listeners": listeners}))
        node.chmod(0o600)
        subprocess.run([server, "check", "--config", str(node)], check=True)
        node_process = stack.enter_context(base.process([server, "run", "--config", str(node)], root / "node.log"))
        base.ready(node_process, listeners[0]["port"])
        for name, outbound in cases:
            inbound = port()
            path = root / "client.json"
            path.write_text(json.dumps({"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": inbound}], "outbounds": [outbound]}))
            with base.process([client, "run", "-c", str(path)], root / "client.log") as child:
                base.ready(child, inbound)
                ext.verify_proxy(inbound, tcp.server_address[1], udp.server_address[1])
                print(f"PASS {name}: TCP + UDP", flush=True)
        print(f"Passed {len(cases)} Naive/SS2022 combinations on loopback.")


if __name__ == "__main__":
    main()
