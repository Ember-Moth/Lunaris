#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Check actual TCP/UDP egress source IP with independent Mieru/SSR/KCP clients.

All targets are local loopback peers. --source-ip must be an assigned non-loopback
IPv4 address on this machine; no system interfaces, routes or proxy settings change.
"""
import argparse
import contextlib
import ipaddress
import json
import pathlib
import queue
import socketserver
import subprocess
import sys
import tempfile
import threading

sys.dont_write_bytecode = True
from management_client import free_port, managed_node


class TCPPeer(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.sources.put(self.client_address[0])
        self.request.settimeout(5)
        try:
            while data := self.request.recv(65535):
                self.request.sendall(data)
        except OSError:
            pass


class UDPPeer(socketserver.BaseRequestHandler):
    def handle(self):
        self.server.sources.put(self.client_address[0])
        data, connection = self.request
        connection.sendto(data, self.client_address)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris-web"))
    parser.add_argument("--mieru-client", type=pathlib.Path, default=pathlib.Path("bin/test-mieru-client"))
    parser.add_argument("--ssr-client", type=pathlib.Path, default=pathlib.Path("bin/test-ssr-client"))
    parser.add_argument("--ssplugins-client", type=pathlib.Path, default=pathlib.Path("bin/test-ssplugins-client"))
    args = parser.parse_args()
    source = ipaddress.ip_address(args.source_ip)
    if source.version != 4 or source.is_loopback or source.is_unspecified or source.is_multicast or source.is_link_local:
        parser.error("source-ip must be an assigned non-loopback IPv4 address")
    binary = str(args.server.resolve())
    with tempfile.TemporaryDirectory(prefix="lunaris-origin-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        peers = [socketserver.ThreadingTCPServer(("127.0.0.1", 0), TCPPeer), socketserver.UDPServer(("127.0.0.1", 0), UDPPeer)]
        for peer in peers:
            peer.daemon_threads = True
            peer.sources = queue.Queue()
            threading.Thread(target=peer.serve_forever, daemon=True).start()
            stack.callback(peer.server_close)
            stack.callback(peer.shutdown)
        ports = set()
        while len(ports) < 3:
            ports.add(free_port())
        mieru, ssr, kcp = sorted(ports)
        listeners = [
            {"id": "mieru", "enabled": True, "protocol": "mieru", "address": "0.0.0.0", "port": mieru, "credential_refs": ["password"], "options": {"users": [{"username": "alice", "credential_ref": "password"}]}},
            {"id": "ssr", "enabled": True, "protocol": "shadowsocksr", "address": "0.0.0.0", "port": ssr, "credential_refs": ["password"], "options": {"method": "aes-128-cfb", "protocol": "origin", "obfs": "plain"}},
            {"id": "kcp", "enabled": True, "protocol": "shadowsocks", "address": "0.0.0.0", "port": kcp, "network": ["udp"], "credential_refs": ["password"], "options": {"method": "aes-128-gcm"}, "udp_over_tcp": True, "transport": {"type": "kcptun", "plugin": {"crypt": "aes", "nocomp": True, "smuxver": 1, "key_ref": "key"}}},
        ]
        password, key = "disposable-origin-password", "disposable-origin-kcp-key"
        stack.enter_context(managed_node(binary, root, listeners=listeners, credentials={"password": password, "key": key}))
        common = {"TCPTarget": f"127.0.0.1:{peers[0].server_address[1]}", "UDPTarget": f"127.0.0.1:{peers[1].server_address[1]}"}
        cases = [(f"mieru-{network}", args.mieru_client, {**common, "Server": f"{source}:{mieru}", "Transport": network, "Username": "alice", "Password": password, "Connections": 4}) for network in ("tcp", "udp")]
        cases += [
            ("shadowsocksr", args.ssr_client, {**common, "Server": f"{source}:{ssr}", "Method": "aes-128-cfb", "Password": password, "Protocol": "origin", "Obfs": "plain"}),
            ("kcptun", args.ssplugins_client, {**common, "Server": f"{source}:{kcp}", "Method": "aes-128-gcm", "Password": password, "Plugin": "kcptun", "PluginOpts": {"key": key, "crypt": "aes", "nocomp": True, "smuxver": 1}}),
        ]
        for name, client, config in cases:
            path = root / "client.json"
            path.write_text(json.dumps(config)); path.chmod(0o600)
            subprocess.run([str(client.resolve()), "--config", str(path)], check=True, timeout=45)
            for peer in peers:
                observed = []
                while not peer.sources.empty():
                    observed.append(peer.sources.get_nowait())
                assert observed and set(observed) == {str(source)}, (name, "incorrect egress source", observed)
            print(f"PASS {name}: TCP and UDP targets observed the ingress IP", flush=True)


if __name__ == "__main__":
    main()
