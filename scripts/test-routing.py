#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise routing/DNS/GeoData through a real managed process and Mihomo client.

All DNS and forwarding targets are local fixtures. No system DNS or route changes.
"""
import argparse
import contextlib
import json
import pathlib
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from management_client import API, free_port, running


class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            while data := self.request.recv(65535):
                self.request.sendall(data)
        except OSError:
            pass


class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, conn = self.request
        conn.sendto(data, self.client_address)


class DNS(socketserver.BaseRequestHandler):
    def handle(self):
        query, conn = self.request
        offset = 12
        while offset < len(query) and query[offset]:
            offset += query[offset] + 1
        if offset + 5 > len(query):
            return
        end = offset + 5
        kind = struct.unpack("!H", query[offset + 1:offset + 3])[0]
        answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!IH", 60, 4) + b"\x7f\x00\x00\x01" if kind == 1 else b""
        response = query[:2] + b"\x81\x80\x00\x01" + struct.pack("!H", int(bool(answer))) + b"\x00\x00\x00\x00" + query[12:end] + answer
        conn.sendto(response, self.client_address)


def varint(value):
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def field(number, payload):
    return varint(number << 3 | 2) + varint(len(payload)) + payload


def geosite():
    domain = b"\x08\x03" + field(2, b"blocked.test")
    return field(1, field(1, b"TEST") + field(2, domain))


def apply(api, revision, base, key):
    plan, _ = api.call("POST", "/api/v1/config/plans", {"draft_revision": revision, "base_revision": base})
    accepted, _ = api.call("POST", "/api/v1/config/apply", {"plan_id": plan["plan_id"], "acknowledge_disconnects": True}, status=202, headers={"Idempotency-Key": key})
    deadline = time.monotonic() + 10
    while True:
        operation, _ = api.call("GET", "/api/v1/operations/" + accepted["operation_id"])
        if operation["status"] != "running":
            assert operation["status"] == "succeeded", operation["status"]
            return
        assert time.monotonic() < deadline
        time.sleep(0.02)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris-web"))
    parser.add_argument("--client", type=pathlib.Path, default=pathlib.Path("bin/test-ssplugins-client"))
    args = parser.parse_args()
    binary, client = str(args.server.resolve()), str(args.client.resolve())
    with tempfile.TemporaryDirectory(prefix="lunaris-routing-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        peers = [socketserver.ThreadingTCPServer(("127.0.0.1", 0), TCP), socketserver.UDPServer(("127.0.0.1", 0), UDP), socketserver.UDPServer(("127.0.0.1", 0), DNS)]
        for peer in peers:
            peer.daemon_threads = True
            threading.Thread(target=peer.serve_forever, daemon=True).start()
            stack.callback(peer.server_close)
            stack.callback(peer.shutdown)
        management, proxy = free_port(), free_port()
        state, restored = root / "state", root / "restored"
        api = API(management)
        password, secret = "routing-management-password", "routing-proxy-password"
        def verify(host, rejected=False):
            path = root / "client.json"
            path.write_text(json.dumps({"Server": f"127.0.0.1:{proxy}", "Method": "aes-128-gcm", "Password": secret, "TCPTarget": f"{host}:{peers[0].server_address[1]}", "UDPTarget": f"127.0.0.1:{peers[1].server_address[1]}", "ExpectFailure": rejected}))
            path.chmod(0o600)
            subprocess.run([client, "--config", str(path)], check=True, timeout=30)
        with running(binary, root, state, management):
            token = (state / "setup-token").read_text().strip()
            api.call("POST", "/api/v1/setup", {"token": token, "username": "admin", "password": password}, status=201)
            api.call("POST", "/api/v1/auth/login", {"username": "admin", "password": password})
            credential, _ = api.call("POST", "/api/v1/credentials", {"kind": "password", "secret": secret}, status=201)
            geo, _ = api.call("POST", "/api/v1/geodata?kind=geosite&label=test", raw_body=geosite(), status=201)
            request = {"config": {"schema_version": 1, "listeners": [{"id": "ss", "enabled": True, "protocol": "shadowsocks", "address": "127.0.0.1", "port": proxy, "network": ["tcp", "udp"], "udp_over_tcp": True, "credential_refs": ["device"], "options": {"method": "aes-128-gcm"}}], "route": {"block": ["geosite:test"]}, "dns": {"servers": [{"protocol": "udp", "address": f"127.0.0.1:{peers[2].server_address[1]}"}], "strategy": "only_ipv4", "hijack_udp53": True}, "geodata": {"geosite": geo["id"]}}, "credential_assets": {"device": credential["id"]}, "certificate_assets": {}}
            draft, _ = api.call("PUT", "/api/v1/config/draft", request, headers={"If-Match": '"r0"'})
            revision = draft["id"]
            apply(api, revision, "r0", "first-routing")
            verify("allowed.test")
            verify("blocked.test", True)
            api.call("DELETE", "/api/v1/geodata/" + geo["id"], status=409)
        print("PASS JSON API routing, configured DNS, GeoSite blocking and reference protection", flush=True)
        with running(binary, root, state, management):
            api.call("GET", "/api/v1/auth/session")
            status, _ = api.call("GET", "/api/v1/status")
            assert status["heads"]["committed_revision"] == revision
            verify("allowed.test")
            verify("blocked.test", True)
        print("PASS committed routing/DNS recovery after restart", flush=True)
        backup = root / "snapshot.db"
        subprocess.run([binary, "backup", "--data-dir", str(state), "--output", str(backup)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([binary, "restore", "--data-dir", str(restored), "--input", str(backup)], check=True, stdout=subprocess.DEVNULL)
        with running(binary, root, restored, management):
            api.call("GET", "/api/v1/auth/session", status=401)
            api.call("POST", "/api/v1/auth/login", {"username": "admin", "password": password})
            assets, _ = api.call("GET", "/api/v1/geodata")
            assert assets["items"][0]["sha256"] == geo["sha256"]
            verify("allowed.test")
            verify("blocked.test", True)
        print("PASS backup/restore includes immutable GeoData and policy configuration", flush=True)


if __name__ == "__main__":
    main()
