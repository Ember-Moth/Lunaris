#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Test UoT, sing-mux and REALITY against a supplied sing-box release on loopback."""
import argparse
import contextlib
import importlib.util
import json
import os
import pathlib
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import sys
sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location("interop", pathlib.Path(__file__).with_name("test-interop.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)



def verify_proxy(inbound, tcp_port, udp_target_port):
    first, _ = base.socks(inbound, 1, tcp_port)
    with first:
        for _ in range(2):
            second, _ = base.socks(inbound, 1, tcp_port)
            with second:
                payload = b"extension tcp" * 2000
                second.sendall(payload)
                assert base.exact(second, len(payload)) == payload
        first.sendall(b"still open")
        assert base.exact(first, 10) == b"still open"
    control, destination = base.socks(inbound, 3, 0)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
        datagram.settimeout(4)
        host, udp_port = destination
        if host == "0.0.0.0":
            host = "127.0.0.1"
        payload = b"extension udp" * 100
        header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp_target_port)
        datagram.sendto(header + payload, (host, udp_port))
        response, _ = datagram.recvfrom(65535)
        assert response[10:] == payload

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=pathlib.Path, required=True)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris"))
    parser.add_argument("--xray-client", type=pathlib.Path)
    args = parser.parse_args()
    client, server = str(args.client.resolve()), str(args.server.resolve())
    subprocess.run([client, "version"], check=True)
    cases = []
    for kind in ("shadowsocks", "vless", "vmess", "trojan"):
        for mode in ("smux", "yamux", "h2mux"):
            cases.append((kind, mode, False, 0))
    cases += [("shadowsocks", "", False, 1), ("shadowsocks", "", False, 2), ("anytls", "", False, 2)]
    cases += [(kind, "", True, 0) for kind in ("vless", "vmess", "trojan", "anytls")]
    cases += [("vless", "h2mux", True, 0)]
    with tempfile.TemporaryDirectory(prefix="lunaris-extensions-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        reality_keys = json.loads(subprocess.check_output([server, "keygen", "reality"], text=True))
        tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTCP)
        udp = socketserver.UDPServer(("127.0.0.1", 0), base.EchoUDP)
        target = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTCP)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(cert, key)
        tls.set_alpn_protocols(["h2", "http/1.1"])
        target.socket = tls.wrap_socket(target.socket, server_side=True)
        target.handle_error = lambda request, address: None
        for echo in (tcp, udp, target):
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
        scenarios = [(*case, port()) for case in cases]
        text = f"schema_version: 1\ncertificates:\n  - id: tls\n    certificate_file: cert.pem\n    private_key_file: key.pem\ncredentials:\n  - id: uuid\n    secret: {base.UUID}\n  - id: password\n    secret: {base.PASSWORD}\n  - id: reality-key\n    secret: {reality_keys['private_key']}\nlisteners:\n"
        for index, (kind, mode, reality, uot, endpoint) in enumerate(scenarios):
            ref = "uuid" if kind in ("vless", "vmess") else "password"
            text += f"  - id: test-{index}\n    protocol: {kind}\n    address: 127.0.0.1\n    port: {endpoint}\n    credential_refs: [{ref}]\n"
            if kind == "shadowsocks":
                text += "    options: {method: aes-128-gcm}\n"
            if uot and kind != "anytls":
                text += "    udp_over_tcp: true\n"
            if mode:
                text += "    multiplex: {enabled: true, padding: true}\n"
            if reality:
                transport = {"type": "reality", "reality": {"target": f"127.0.0.1:{target.server_address[1]}", "server_names": ["localhost"], "private_key_ref": "reality-key", "short_ids": ["0102030405060708"], "allow_legacy_clients": True}}
                text += f"    transport: {json.dumps(transport)}\n"
            elif kind != "shadowsocks":
                text += "    certificate_ref: tls\n    transport: {type: tcp}\n"
        shared_ss_port = port()
        text += f"  - id: ss-all-modes\n    protocol: shadowsocks\n    address: 127.0.0.1\n    port: {shared_ss_port}\n    network: [tcp, udp]\n    credential_refs: [password]\n    options: {{method: aes-128-gcm}}\n    udp_over_tcp: true\n    multiplex: {{enabled: true, padding: true}}\n"
        node = root / "node.yaml"
        node.write_text(text)
        node.chmod(0o600)
        subprocess.run([server, "check", "--config", str(node)], check=True)
        node_log = root / "node.log"
        node_process = stack.enter_context(base.process([server, "run", "--config", str(node)], node_log))
        deadline = time.monotonic() + 25
        while "Node listeners started" not in node_log.read_text():
            if node_process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError("node failed to prepare REALITY listeners")
            time.sleep(0.03)
        for kind, mode, reality, uot, endpoint in scenarios:
            outbound = {"type": kind, "tag": "proxy", "server": "127.0.0.1", "server_port": endpoint}
            if kind in ("vless", "vmess"):
                outbound.update(uuid=base.UUID, packet_encoding="")
            else:
                outbound["password"] = base.PASSWORD
            if kind == "shadowsocks":
                outbound["method"] = "aes-128-gcm"
                if uot:
                    outbound["udp_over_tcp"] = {"enabled": True, "version": uot}
            elif kind == "vmess":
                outbound.update(security="aes-128-gcm", alter_id=0)
            if mode:
                outbound["multiplex"] = {"enabled": True, "protocol": mode, "padding": True, "max_connections": 1, "max_streams": 8}
            if reality:
                outbound["tls"] = {"enabled": True, "server_name": "localhost", "utls": {"enabled": True, "fingerprint": "chrome"}, "reality": {"enabled": True, "public_key": reality_keys["public_key"], "short_id": "0102030405060708"}}
            elif kind != "shadowsocks":
                outbound["tls"] = {"enabled": True, "server_name": "localhost", "certificate_path": str(cert)}
            inbound = port()
            config = {"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": inbound}], "outbounds": [outbound]}
            client_config = root / "client.json"
            client_config.write_text(json.dumps(config))
            client_config.chmod(0o600)
            with base.process([client, "run", "-c", str(client_config)], root / "client.log") as child:
                base.ready(child, inbound)
                verify_proxy(inbound, tcp.server_address[1], udp.server_address[1])
                print(f"PASS {kind}: mux={mode or 'off'}, reality={reality}, uot={uot}: TCP + UDP", flush=True)
        # One server endpoint accepts each client mode concurrently. The last
        # case deliberately requests non-padded mux plus UoT: if sing-box used
        # mux, this padding-required server would reject it. Success verifies
        # the upstream client's UoT priority without imposing it on the server.
        shared_modes = [("native", {})]
        shared_modes += [(f"uot-v{v}", {"udp_over_tcp": {"enabled": True, "version": v}}) for v in (1, 2)]
        shared_modes += [(mode, {"multiplex": {"enabled": True, "protocol": mode, "padding": True}}) for mode in ("smux", "yamux", "h2mux")]
        shared_modes += [("uot-and-mux-selects-uot", {"udp_over_tcp": {"enabled": True, "version": 2}, "multiplex": {"enabled": True, "protocol": "smux", "padding": False}})]
        with contextlib.ExitStack() as shared_clients:
            endpoints = []
            for index, (mode, options) in enumerate(shared_modes):
                inbound = port()
                outbound = {"type": "shadowsocks", "tag": "proxy", "server": "127.0.0.1", "server_port": shared_ss_port, "method": "aes-128-gcm", "password": base.PASSWORD, **options}
                config = {"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": inbound}], "outbounds": [outbound]}
                path = root / f"ss-shared-{index}.json"
                path.write_text(json.dumps(config))
                path.chmod(0o600)
                child = shared_clients.enter_context(base.process([client, "run", "-c", str(path)], root / f"ss-shared-{index}.log"))
                base.ready(child, inbound)
                endpoints.append((mode, inbound))
            for mode, inbound in endpoints:
                verify_proxy(inbound, tcp.server_address[1], udp.server_address[1])
                print(f"PASS shared Shadowsocks/{mode}: TCP + UDP", flush=True)
        if args.xray_client:
            xray = str(args.xray_client.resolve())
            subprocess.run([xray, "version"], check=True)
            for kind, mode, reality, uot, endpoint in scenarios:
                if not reality or mode or kind == "anytls":
                    continue
                inbound = port()
                if kind in ("vless", "vmess"):
                    user = {"id": base.UUID, "encryption": "none"} if kind == "vless" else {"id": base.UUID, "security": "aes-128-gcm", "alterId": 0}
                    settings = {"vnext": [{"address": "127.0.0.1", "port": endpoint, "users": [user]}]}
                else:
                    settings = {"servers": [{"address": "127.0.0.1", "port": endpoint, "password": base.PASSWORD}]}
                outbound = {"protocol": kind, "settings": settings, "streamSettings": {"network": "raw", "security": "reality", "realitySettings": {"serverName": "localhost", "fingerprint": "chrome", "password": reality_keys["public_key"], "shortId": "0102030405060708"}}}
                config = {"log": {"loglevel": "error"}, "inbounds": [{"listen": "127.0.0.1", "port": inbound, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}], "outbounds": [outbound]}
                path = root / "xray.json"
                path.write_text(json.dumps(config))
                path.chmod(0o600)
                # Verify native UDP framing; XUDP is outside this feature set.
                env = os.environ.copy()
                env["XRAY_CONE_DISABLED"] = "true"
                with base.process([xray, "run", "-c", str(path)], root / "xray.log", env=env) as child:
                    base.ready(child, inbound)
                    verify_proxy(inbound, tcp.server_address[1], udp.server_address[1])
                    print(f"PASS Xray {kind}/REALITY: TCP + UDP", flush=True)
        print(f"Passed {len(scenarios)} extension combinations and {len(shared_modes)} shared-port Shadowsocks modes on loopback.")


if __name__ == "__main__":
    main()
