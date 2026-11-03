#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise Lunaris proxy outbounds against an independent sing-box executable.

Uses disposable API-managed SQLite state and loopback peers; changes no system
DNS, proxy, route or production configuration. Requires sing-box >= 1.12.
"""
import argparse
import base64
import contextlib
import copy
import json
import pathlib
import runpy
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from management_client import API, free_port, running

helpers = runpy.run_path(str(pathlib.Path(__file__).with_name("test-interop.py")))
process, ready, exact, address = (helpers[name] for name in ("process", "ready", "exact", "address"))


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(4)
        try:
            while data := self.request.recv(65535):
                self.request.sendall(data)
        except OSError:
            pass


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        connection.sendto(data, self.client_address)


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        data, connection = self.request
        offset, labels = 12, []
        while offset < len(data) and data[offset]:
            size = data[offset]
            labels.append(data[offset + 1:offset + 1 + size].decode("ascii"))
            offset += size + 1
        if offset + 5 > len(data):
            return
        name = ".".join(labels)
        kind = struct.unpack("!H", data[offset + 1:offset + 3])[0]
        self.server.queries.append(name)
        permitted = not self.server.local_only or name == "direct.test"
        answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", 60, 4) + b"\x7f\x00\x00\x01" if permitted and kind == 1 else b""
        response = data[:2] + (b"\x81\x80" if permitted else b"\x81\x83") + b"\x00\x01" + struct.pack("!H", int(bool(answer))) + b"\x00\x00\x00\x00" + data[12:offset + 5] + answer
        connection.sendto(response, self.client_address)


def encoded(host, port):
    try:
        raw = b"\x01" + socket.inet_aton(host)
    except OSError:
        raw = b"\x03" + bytes([len(host)]) + host.encode()
    return raw + struct.pack("!H", port)


def socks(port, command, host, target):
    connection = socket.create_connection(("127.0.0.1", port), 4)
    try:
        connection.sendall(b"\x05\x01\x00")
        assert exact(connection, 2) == b"\x05\x00"
        connection.sendall(bytes([5, command, 0]) + encoded(host, target))
        reply = exact(connection, 4)
        assert reply[:2] == b"\x05\x00", reply
        return connection, address(connection, reply[3])
    except BaseException:
        connection.close()
        raise


def udp_payload(data):
    assert data[:3] == b"\x00\x00\x00", data[:4]
    offset = {1: 8, 4: 20}.get(data[3])
    if offset is None:
        assert data[3] == 3
        offset = 5 + data[4]
    return data[offset + 2:]


def apply(api, revision, base, key):
    plan, _ = api.call("POST", "/api/v1/config/plans", {"draft_revision": revision, "base_revision": base})
    accepted, _ = api.call("POST", "/api/v1/config/apply", {"plan_id": plan["plan_id"], "acknowledge_disconnects": True}, status=202, headers={"Idempotency-Key": key})
    end = time.monotonic() + 15
    while True:
        operation, _ = api.call("GET", "/api/v1/operations/" + accepted["operation_id"])
        if operation["status"] != "running":
            assert operation["status"] == "succeeded", operation
            return
        assert time.monotonic() < end
        time.sleep(0.02)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--peer", type=pathlib.Path, required=True)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris-web"))
    args = parser.parse_args()
    binary, peer = str(args.server.resolve()), str(args.peer.resolve())
    subprocess.run([peer, "version"], check=True)
    with tempfile.TemporaryDirectory(prefix="lunaris-outbound-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), TCP)
        udp = socketserver.UDPServer(("127.0.0.1", 0), UDP)
        local_dns = socketserver.UDPServer(("127.0.0.1", 0), DNS)
        remote_dns = socketserver.UDPServer(("127.0.0.1", 0), DNS)
        for server in (local_dns, remote_dns):
            server.queries = []
            server.local_only = server is local_dns
        for server in (tcp, udp, local_dns, remote_dns):
            server.daemon_threads = True
            threading.Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.server_close)
            stack.callback(server.shutdown)
        used = set()
        def port():
            while (value := free_port()) in used:
                pass
            used.add(value)
            return value
        management, inbound, client_port = port(), port(), port()
        password = "outbound-fixture-password"
        methods = ["aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"]
        cases = [("socks5", None), ("http", None)] + [("shadowsocks", method) for method in methods]
        outbounds, upstream_inbounds, secrets = [], [], {}
        for index, (protocol, method) in enumerate(cases):
            identifier, endpoint = f"p{index}", port()
            secret = password
            if method and method.startswith("2022"):
                secret = base64.b64encode(bytes([index + 1]) * (16 if "aes-128" in method else 32)).decode()
            secrets[identifier] = secret
            options = {"method": method} if method else {"username": "alice"}
            outbounds.append({"id": identifier, "protocol": protocol, "address": "127.0.0.1", "port": endpoint, "credential_ref": identifier, "options": options})
            upstream = {"type": "socks" if protocol == "socks5" else protocol, "tag": identifier, "listen": "127.0.0.1", "listen_port": endpoint}
            upstream.update({"method": method, "password": secret} if method else {"users": [{"username": "alice", "password": secret}]})
            upstream_inbounds.append(upstream)
        upstream_config = {"log": {"level": "error"}, "dns": {"servers": [{"type": "udp", "tag": "fixture", "server": "127.0.0.1", "server_port": remote_dns.server_address[1]}], "strategy": "ipv4_only"}, "inbounds": upstream_inbounds, "outbounds": [{"type": "direct", "tag": "direct"}], "route": {"final": "direct", "default_domain_resolver": "fixture"}}
        upstream_path = root / "upstream.json"
        upstream_path.write_text(json.dumps(upstream_config)); upstream_path.chmod(0o600)
        upstream_process = stack.enter_context(process([peer, "run", "-c", str(upstream_path)], root / "upstream.log"))
        ready(upstream_process, upstream_inbounds[0]["listen_port"])
        client_path = root / "client.json"
        client_path.write_text(json.dumps({"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": client_port}], "outbounds": [{"type": "shadowsocks", "server": "127.0.0.1", "server_port": inbound, "method": "aes-128-gcm", "password": password}]})); client_path.chmod(0o600)
        client_process = stack.enter_context(process([peer, "run", "-c", str(client_path)], root / "client.log"))
        ready(client_process, client_port)
        api, state = API(management), root / "state"

        def verify():
            for index, (protocol, method) in enumerate(cases):
                connection, _ = socks(client_port, 1, f"p{index}.test", tcp.server_address[1])
                with connection:
                    payload = (f"TCP via {protocol}/{method}".encode()) * 2000
                    connection.sendall(payload)
                    assert exact(connection, len(payload)) == payload
                print(f"PASS {protocol}/{method or 'connect'} TCP with remote DNS", flush=True)
            control, relay = socks(client_port, 3, "0.0.0.0", 0)
            with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                datagram.settimeout(3)
                relay = ("127.0.0.1" if relay[0] == "0.0.0.0" else relay[0], relay[1])
                for index, (protocol, _) in enumerate(cases):
                    if protocol == "http":
                        continue
                    payload = f"same association, outbound {index}".encode()
                    datagram.sendto(b"\0\0\0" + encoded(f"p{index}.test", udp.server_address[1]) + payload, relay)
                    response, _ = datagram.recvfrom(65535)
                    assert udp_payload(response) == payload
                payload = b"same association, direct"
                datagram.sendto(b"\0\0\0" + encoded("direct.test", udp.server_address[1]) + payload, relay)
                assert udp_payload(datagram.recvfrom(65535)[0]) == payload
                datagram.settimeout(0.4)
                datagram.sendto(b"\0\0\0" + encoded("p1.test", udp.server_address[1]) + b"http must reject udp", relay)
                try:
                    datagram.recvfrom(65535)
                    raise AssertionError("HTTP route forwarded UDP")
                except socket.timeout:
                    pass
            assert all(name == "direct.test" for name in local_dns.queries), local_dns.queries
            print("PASS one UDP association across SOCKS5, six Shadowsocks methods and direct; HTTP UDP rejected", flush=True)

        with running(binary, root, state, management):
            api.call("POST", "/api/v1/setup", {"token": (state / "setup-token").read_text().strip(), "username": "admin", "password": password}, status=201)
            api.call("POST", "/api/v1/auth/login", {"username": "admin", "password": password})
            assets = {}
            for name, secret in {"inbound": password, **secrets}.items():
                asset, _ = api.call("POST", "/api/v1/credentials", {"kind": "password", "secret": secret}, status=201)
                assets[name] = asset["id"]
            document = {"config": {"schema_version": 1, "listeners": [{"id": "ss", "enabled": True, "protocol": "shadowsocks", "address": "127.0.0.1", "port": inbound, "network": ["tcp", "udp"], "credential_refs": ["inbound"], "options": {"method": "aes-128-gcm"}}], "outbounds": outbounds, "route": {"final": "p0", "rules": [{"action": "direct", "match": ["full:direct.test"]}] + [{"action": "route", "outbound": f"p{index}", "match": [f"full:p{index}.test"]} for index in range(len(cases))]}, "dns": {"servers": [{"protocol": "udp", "address": f"127.0.0.1:{local_dns.server_address[1]}"}], "strategy": "only_ipv4"}}, "credential_assets": assets, "certificate_assets": {}}
            capabilities, _ = api.call("GET", "/api/v1/capabilities")
            assert {item["protocol"] for item in capabilities["outbound_protocols"]} == {"http", "socks5", "shadowsocks"}
            invalid = copy.deepcopy(document); invalid["config"]["route"]["final"] = "missing"
            api.call("POST", "/api/v1/config/validate", invalid, status=422)
            draft, _ = api.call("PUT", "/api/v1/config/draft", document, headers={"If-Match": '"r0"'})
            revision = draft["id"]
            assert password not in json.dumps(draft)
            apply(api, revision, "r0", "outbound-first")
            verify()
            active, _ = socks(client_port, 1, "p0.test", tcp.server_address[1])
            with active:
                active.sendall(b"live"); assert exact(active, 4) == b"live"
                rotated, _ = api.call("POST", "/api/v1/credentials", {"kind": "password", "secret": "deliberately-wrong-outbound-password"}, status=201)
                candidate = copy.deepcopy(document)
                candidate["credential_assets"]["p0"] = rotated["id"]
                draft, _ = api.call("PUT", "/api/v1/config/draft", candidate, headers={"If-Match": '"' + revision + '"'})
                plan, _ = api.call("POST", "/api/v1/config/plans", {"draft_revision": draft["id"], "base_revision": revision})
                assert any(change["closes_connections"] for change in plan["changes"])
                api.call("POST", "/api/v1/config/apply", {"plan_id": plan["plan_id"]}, status=409, headers={"Idempotency-Key": "rotation-no-ack"})
                active.sendall(b"live"); assert exact(active, 4) == b"live"
                apply(api, draft["id"], revision, "rotation-ack")
                revision = draft["id"]
                try:
                    active.sendall(b"closed")
                    assert active.recv(16) == b"", "rotation preserved the old session"
                except OSError:
                    pass
            rejected = None
            try:
                rejected, _ = socks(client_port, 1, "p0.test", tcp.server_address[1])
                rejected.sendall(b"must not bypass proxy")
                assert rejected.recv(64) == b"", "failed authentication fell back to direct"
            except (OSError, RuntimeError):
                pass
            finally:
                if rejected is not None:
                    rejected.close()
            restored_draft, _ = api.call("PUT", "/api/v1/config/draft", document, headers={"If-Match": '"' + revision + '"'})
            apply(api, restored_draft["id"], revision, "restore-credentials")
            revision = restored_draft["id"]
            print("PASS outbound credential rotation requires acknowledgement, closes old streams and fails closed", flush=True)
            api.call("DELETE", "/api/v1/credentials/" + assets["p0"], status=409)
        with running(binary, root, state, management):
            status, _ = api.call("GET", "/api/v1/status")
            assert status["heads"]["committed_revision"] == revision
            verify()
        backup, restored = root / "backup.db", root / "restored"
        subprocess.run([binary, "backup", "--data-dir", str(state), "--output", str(backup)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([binary, "restore", "--data-dir", str(restored), "--input", str(backup)], check=True, stdout=subprocess.DEVNULL)
        with running(binary, root, restored, management):
            api.call("GET", "/api/v1/auth/session", status=401)
            api.call("POST", "/api/v1/auth/login", {"username": "admin", "password": password})
            verify()
        print("PASS JSON API, credential reference protection, restart and complete backup/restore", flush=True)


if __name__ == "__main__":
    main()
