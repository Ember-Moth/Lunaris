#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Loopback interop using supplied sing-box, Mihomo and an official Mieru API client."""
import argparse
import contextlib
import importlib.util
import json
import pathlib
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("base", pathlib.Path(__file__).with_name("test-interop.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def verify_proxy(port, tcp_port, udp_port):
    for _ in range(3):
        c, _ = base.socks(port, 1, tcp_port)
        with c:
            payload = b"protocol interop tcp" * 3000
            c.sendall(payload)
            assert base.exact(c, len(payload)) == payload
    control, destination = base.socks(port, 3, 0)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
        udp.settimeout(5)
        payload = b"udp" * 300
        header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_port)
        udp.sendto(header + payload, ("127.0.0.1", destination[1]))
        response, _ = udp.recvfrom(65535)
        assert response[10:] == payload, (len(response), response[:32].hex())


def ready_mihomo(child, port, controller):
    base.ready(child, port)
    end = time.monotonic() + 5
    while time.monotonic() < end:
        if child.poll() is not None:
            raise RuntimeError("Mihomo exited before its proxy/rules were ready")
        try:
            def read(path):
                request = urllib.request.Request(f"http://127.0.0.1:{controller}{path}", headers={"Authorization": "Bearer lunaris-interop"})
                with urllib.request.urlopen(request, timeout=0.2) as response:
                    return json.load(response)
            proxy, rules = read("/proxies/node"), read("/rules")
            if proxy.get("name") == "node" and any(rule.get("proxy") == "node" for rule in rules.get("rules", [])):
                return
        except (OSError, ValueError):
            pass
        time.sleep(0.02)
    raise RuntimeError("Mihomo proxy/rules readiness timeout")


class LossyUDP:
    """Loopback-only datagram relay dropping every seventh packet each way."""
    def __init__(self, target):
        self.target = target
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.settimeout(0.1)
        self.address = self.listener.getsockname()
        self.closed = threading.Event()
        self.peers = {}
        self.threads = []
        self.uploads = self.downloads = self.dropped = 0
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.receive, daemon=True)
        self.thread.start()

    def drop(self, direction):
        with self.lock:
            value = getattr(self, direction) + 1
            setattr(self, direction, value)
            if value % 7 == 0:
                self.dropped += 1
                return True
            return False

    def receive(self):
        while not self.closed.is_set():
            try:
                data, peer = self.listener.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            if peer not in self.peers:
                upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                upstream.connect(self.target)
                upstream.settimeout(0.1)
                self.peers[peer] = upstream
                worker = threading.Thread(target=self.respond, args=(upstream, peer), daemon=True)
                self.threads.append(worker)
                worker.start()
            if not self.drop("uploads"):
                self.peers[peer].send(data)

    def respond(self, upstream, peer):
        while not self.closed.is_set():
            try:
                data = upstream.recv(65535)
                if not self.drop("downloads"):
                    self.listener.sendto(data, peer)
            except socket.timeout:
                continue
            except OSError:
                return

    def close(self):
        self.closed.set()
        self.listener.close()
        self.thread.join(timeout=1)
        for peer in self.peers.values():
            peer.close()
        for worker in self.threads:
            worker.join(timeout=1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sing-box", type=pathlib.Path, required=True)
    parser.add_argument("--mihomo", type=pathlib.Path, required=True)
    parser.add_argument("--ssr-client", type=pathlib.Path, required=True)
    parser.add_argument("--mieru-client", type=pathlib.Path, required=True)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris"))
    parser.add_argument("--only", choices=["snell", "mieru", "shadowsocksr"])
    args = parser.parse_args()
    sing, mihomo, mieru, server = (str(x.resolve()) for x in (args.sing_box, args.mihomo, args.mieru_client, args.server))
    ssr = str(args.ssr_client.resolve())
    subprocess.run([sing, "version"], check=True)
    subprocess.run([mihomo, "-v"], check=True)
    with tempfile.TemporaryDirectory(prefix="lunaris-protocols-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTCP)
        udp = socketserver.UDPServer(("127.0.0.1", 0), base.EchoUDP)
        for echo in (tcp, udp):
            echo.daemon_threads = True
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            stack.callback(echo.server_close)
            stack.callback(echo.shutdown)
        used = set()
        def port():
            p = base.free_port()
            while p in used:
                p = base.free_port()
            used.add(p)
            return p
        listeners, cases = [], []
        for version, obfs, mode in [(5, "none", ""), (5, "http", ""), (5, "tls", ""), (6, "", "default"), (6, "", "unshaped"), (6, "", "unsafe-raw")]:
            endpoint = port()
            listeners.append({"id": f"snell-{version}-{obfs}-{mode}", "protocol": "snell", "port": endpoint, "credential_refs": ["one"], "options": {"version": version, "obfs": obfs, "mode": mode}})
            outbound = {"type": "snell", "server": "127.0.0.1", "server_port": endpoint, "version": 4 if version == 5 else 6, "psk": base.PASSWORD, "reuse": True}
            if version == 5 and obfs != "none":
                outbound["obfs_mode"] = obfs
            if version == 6:
                outbound["mode"] = mode
            cases.append(("sing", f"snell/{version}/{obfs or mode}", outbound))
        protocols = ["origin", "auth_sha1_v4", "auth_aes128_md5", "auth_aes128_sha1", "auth_chain_a", "auth_chain_b"]
        ssr_modes = [("aes-128-cfb", protocol, obfs) for protocol in protocols for obfs in ("plain", "http_simple", "http_post", "tls1.2_ticket_auth")]
        ssr_modes += [(cipher, "origin", "plain") for cipher in ("none", "aes-192-cfb", "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "rc4-md5", "chacha20", "chacha20-ietf")]
        ssr_modes.append(("none", "auth_chain_a", "plain"))
        for i, (cipher, protocol, obfs) in enumerate(ssr_modes):
            endpoint = port()
            multi = protocol.startswith(("auth_aes128", "auth_chain"))
            options = {"method": cipher, "protocol": protocol, "obfs": obfs}
            refs = ["one"]
            if multi:
                refs = ["one", "two"]
                options.update(server_key_ref="server", users=[{"id": 1, "credential_ref": "one"}, {"id": 2, "credential_ref": "two"}])
            listeners.append({"id": f"ssr-{i}", "protocol": "shadowsocksr", "port": endpoint, "credential_refs": refs, "options": options})
            for user in range(len(refs)):
                proxy = {"name": "node", "type": "ssr", "server": "127.0.0.1", "port": endpoint, "cipher": cipher, "password": "shared-ssr-server-password" if multi else base.PASSWORD, "protocol": protocol, "obfs": obfs, "udp": True}
                if multi:
                    proxy["protocol-param"] = f"{user+1}:" + (base.PASSWORD if user == 0 else "second-user-password")
                cases.append(("mihomo", f"ssr/{cipher}/{protocol}/{obfs}/user={user+1}", proxy))
        mieru_port = port()
        listeners.append({"id": "mieru", "protocol": "mieru", "port": mieru_port, "credential_refs": ["one", "two"], "options": {"user_hint_is_mandatory": True, "users": [{"username": "alice", "credential_ref": "one"}, {"username": "bob", "credential_ref": "two"}]}})
        for network in ("tcp", "udp"):
            cases.append(("mihomo", f"mieru/{network}", {"name": "node", "type": "mieru", "server": "127.0.0.1", "port": mieru_port, "username": "alice", "password": base.PASSWORD, "transport": network.upper(), "multiplexing": "MULTIPLEXING_HIGH", "udp": True}))
        for item in listeners:
            item["address"] = "127.0.0.1"
        node = root / "node.yaml"
        node.write_text(json.dumps({"schema_version": 1, "credentials": [{"id": "one", "secret": base.PASSWORD}, {"id": "two", "secret": "second-user-password"}, {"id": "server", "secret": "shared-ssr-server-password"}], "listeners": listeners}))
        node.chmod(0o600)
        subprocess.run([server, "check", "--config", str(node)], check=True)
        process = stack.enter_context(base.process([server, "run", "--config", str(node)], root / "node.log"))
        base.ready(process, listeners[0]["port"])
        if args.only:
            prefix = "ssr/" if args.only == "shadowsocksr" else args.only + "/"
            cases = [case for case in cases if case[1].startswith(prefix)]
        for kind, name, outbound in cases:
            print("RUN", name, flush=True)
            if kind == "mihomo" and outbound["type"] == "ssr":
                path = root / "ssr-api.json"
                path.write_text(json.dumps({"Server": f"127.0.0.1:{outbound['port']}", "Method": outbound["cipher"], "Password": outbound["password"], "Protocol": outbound["protocol"], "ProtocolParam": outbound.get("protocol-param", ""), "Obfs": outbound["obfs"], "TCPTarget": f"127.0.0.1:{tcp.server_address[1]}", "UDPTarget": f"127.0.0.1:{udp.server_address[1]}"}))
                path.chmod(0o600)
                subprocess.run([ssr, "--config", str(path)], check=True, timeout=20)
                continue
            inbound = port()
            if kind == "sing":
                config = {"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": inbound}], "outbounds": [outbound]}
                command = [sing, "run", "-c"]
            else:
                controller = port()
                config = {"external-controller": f"127.0.0.1:{controller}", "secret": "lunaris-interop", "socks-port": inbound, "bind-address": "127.0.0.1", "allow-lan": False, "mode": "rule", "log-level": "debug", "ipv6": False, "find-process-mode": "off", "geo-auto-update": False, "dns": {"enable": False}, "proxies": [outbound], "rules": ["MATCH,node"]}
                command = [mihomo, "-d", str(root / "mihomo-state"), "-f"]
            path = root / "client.json"
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            with base.process(command + [str(path)], root / "client.log") as child:
                if kind == "mihomo":
                    ready_mihomo(child, inbound, controller)
                else:
                    base.ready(child, inbound)
                verify_proxy(inbound, tcp.server_address[1], udp.server_address[1])
                print("PASS", name, "TCP + UDP", flush=True)
        for network in (("tcp", "udp") if args.only in (None, "mieru") else ()):
            for username, password in (("alice", base.PASSWORD), ("bob", "second-user-password")):
                path = root / "mieru-client.json"
                path.write_text(json.dumps({"Server": f"127.0.0.1:{mieru_port}", "Transport": network, "Username": username, "Password": password, "TCPTarget": f"127.0.0.1:{tcp.server_address[1]}", "UDPTarget": f"127.0.0.1:{udp.server_address[1]}", "Connections": 4}))
                subprocess.run([mieru, "--config", str(path)], check=True, timeout=40)
        if args.only in (None, "mieru"):
            with contextlib.closing(LossyUDP(("127.0.0.1", mieru_port))) as lossy:
                path = root / "mieru-loss.json"
                path.write_text(json.dumps({"Server": f"127.0.0.1:{lossy.address[1]}", "Transport": "udp", "Username": "alice", "Password": base.PASSWORD, "TCPTarget": f"127.0.0.1:{tcp.server_address[1]}", "UDPTarget": f"127.0.0.1:{udp.server_address[1]}", "Connections": 4}))
                subprocess.run([mieru, "--config", str(path)], check=True, timeout=40)
                assert lossy.dropped > 0
                print(f"PASS Mieru UDP loss recovery: {lossy.dropped} datagrams deliberately dropped", flush=True)
        print(f"Passed {len(cases)} proxy-client cases and {5 if args.only in (None, 'mieru') else 0} official Mieru API cases.")


if __name__ == "__main__":
    main()
