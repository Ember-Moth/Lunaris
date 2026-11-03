#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Released sing-box client checks for same-port classic AEAD and VMess users."""
import argparse
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
spec = importlib.util.spec_from_file_location("interop", pathlib.Path(__file__).with_name("test-snell-mieru-ssr.py"))
interop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(interop)
base = interop.base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=pathlib.Path, required=True)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris-web"))
    args = parser.parse_args()
    client, server = str(args.client.resolve()), str(args.server.resolve())
    subprocess.run([client, "version"], check=True)
    with tempfile.TemporaryDirectory(prefix="lunaris-authscan-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTCP)
        udp = socketserver.UDPServer(("127.0.0.1", 0), base.EchoUDP)
        tcp.daemon_threads = True
        for echo in (tcp, udp):
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
        listeners, cases = [], []
        credentials = {"password-1": base.PASSWORD, "password-2": "another-authscan-password",
                       "uuid-1": base.UUID, "uuid-2": "ab20e8ef-131d-448d-a58d-b6d81e25073b"}
        for method in ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"):
            endpoint = port()
            listeners.append({"id": method, "protocol": "shadowsocks", "address": "127.0.0.1", "port": endpoint,
                              "credential_refs": ["password-1", "password-2"], "options": {"method": method}})
            for user in (1, 2):
                cases.append((f"shadowsocks/{method}/user={user}", {"type": "shadowsocks", "server": "127.0.0.1",
                              "server_port": endpoint, "method": method, "password": credentials[f"password-{user}"]}))
        for carrier in ("tcp", "ws", "httpupgrade"):
            endpoint = port()
            transport = {"type": carrier}
            if carrier != "tcp":
                transport.update(path="/proxy", host="localhost")
            listeners.append({"id": f"vmess-{carrier}", "protocol": "vmess", "address": "127.0.0.1", "port": endpoint,
                              "credential_refs": ["uuid-1", "uuid-2"], "options": {}, "transport": transport})
            for user in (1, 2):
                outbound = {"type": "vmess", "server": "127.0.0.1", "server_port": endpoint,
                            "uuid": credentials[f"uuid-{user}"], "security": "aes-128-gcm", "alter_id": 0, "packet_encoding": ""}
                if carrier != "tcp":
                    outbound["transport"] = {"type": carrier, "path": "/proxy"}
                    if carrier == "ws":
                        outbound["transport"]["headers"] = {"Host": "localhost"}
                    else:
                        outbound["transport"]["host"] = "localhost"
                cases.append((f"vmess/{carrier}/user={user}", outbound))
        stack.enter_context(base.managed_node(server, root, listeners=listeners, credentials=credentials))
        for name, outbound in cases:
            inbound = port()
            path = root / "client.json"
            path.write_text(json.dumps({"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": inbound}], "outbounds": [outbound]}))
            path.chmod(0o600)
            with base.process([client, "run", "-c", str(path)], root / "client.log") as child:
                base.ready(child, inbound)
                interop.verify_proxy(inbound, tcp.server_address[1], udp.server_address[1])
            print("PASS", name, "TCP + UDP; repeated TCP authentication", flush=True)
        print(f"Passed {len(cases)} released-client multi-user cases.")


if __name__ == "__main__":
    main()
