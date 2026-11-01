#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Loopback VLESS/VMess/Trojan XHTTP interop with a supplied Xray binary."""
import argparse
import hashlib
import ssl
import contextlib
import importlib.util
import json
import os
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
    args = parser.parse_args()
    client, server = str(args.client.resolve()), str(args.server.resolve())
    subprocess.run([client, "version"], check=True)
    with tempfile.TemporaryDirectory(prefix="lunaris-xhttp-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
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
        cases = [(kind, version, mode, secure, port(), {}) for kind in ("vless", "vmess", "trojan") for version, secure in (("h1", False), ("h1", True), ("h2", True), ("h3", True)) if secure or kind != "trojan" for mode in ("packet-up", "stream-up", "stream-one", "auto")]
        for extra in [
            {"sessionIDPlacement": "query", "seqPlacement": "header", "uplinkDataPlacement": "header", "xPaddingObfsMode": True, "xPaddingPlacement": "cookie", "xPaddingMethod": "tokenish"},
            {"sessionIDPlacement": "header", "seqPlacement": "cookie", "uplinkDataPlacement": "cookie", "xPaddingObfsMode": True, "xPaddingPlacement": "query"},
            {"sessionIDPlacement": "cookie", "seqPlacement": "query", "uplinkDataPlacement": "body", "xPaddingObfsMode": True, "xPaddingPlacement": "header"},
        ]:
            extra["scMaxEachPostBytes"] = 512
            cases.append(("vless", "h2", "packet-up", True, port(), extra))
        listeners = []
        for i, (kind, version, mode, secure, endpoint, extra) in enumerate(cases):
            item = {"id": f"test-{i}", "protocol": kind, "address": "127.0.0.1", "port": endpoint, "credential_refs": ["uuid" if kind in ("vless", "vmess") else "password"], "transport": {"type": "xhttp", "path": "/proxy", "host": "localhost", "xhttp": {"mode": mode, "http_version": version}}}
            if extra:
                item["transport"]["xhttp"]["extra"] = extra
            if secure:
                item["certificate_ref"] = "tls"
            listeners.append(item)
        node = root / "node.yaml"
        node.write_text(json.dumps({"schema_version": 1, "credentials": [{"id": "uuid", "secret": base.UUID}, {"id": "password", "secret": base.PASSWORD}], "certificates": [{"id": "tls", "certificate_file": "cert.pem", "private_key_file": "key.pem"}], "listeners": listeners}))
        node.chmod(0o600)
        subprocess.run([server, "check", "--config", str(node)], check=True)
        proc = stack.enter_context(base.process([server, "run", "--config", str(node)], root / "node.log"))
        base.ready(proc, cases[0][4])
        for kind, version, mode, secure, endpoint, extra in cases:
            inbound = port()
            if kind in ("vless", "vmess"):
                user = {"id": base.UUID, "encryption": "none"} if kind == "vless" else {"id": base.UUID, "security": "aes-128-gcm", "alterId": 0}
                settings = {"vnext": [{"address": "127.0.0.1", "port": endpoint, "users": [user]}]}
            else:
                settings = {"servers": [{"address": "127.0.0.1", "port": endpoint, "password": base.PASSWORD}]}
            stream = {"network": "xhttp", "security": "tls" if secure else "none", "xhttpSettings": {"host": "localhost", "path": "/proxy", "mode": mode}}
            if extra:
                stream["xhttpSettings"]["extra"] = {**extra, "uplinkChunkSize": 128, "scMinPostsIntervalMs": 1}
            if secure:
                # Disposable loopback certificate only; no system trust changes.
                stream["tlsSettings"] = {"serverName": "localhost", "pinnedPeerCertSha256": pin, "alpn": ["http/1.1" if version == "h1" else version]}
            config = {"log": {"loglevel": "error"}, "inbounds": [{"listen": "127.0.0.1", "port": inbound, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}], "outbounds": [{"protocol": kind, "settings": settings, "streamSettings": stream}]}
            path = root / "client.json"
            path.write_text(json.dumps(config))
            path.chmod(0o600)
            env = os.environ.copy()
            env["XRAY_CONE_DISABLED"] = "true"  # Native protocol UDP framing.
            with base.process([client, "run", "-c", str(path)], root / "client.log", env=env) as child:
                base.ready(child, inbound)
                print(f"RUN {kind}/{version}/{mode}/tls={secure}/custom={bool(extra)}",flush=True)
                ext.verify_proxy(inbound, tcp.server_address[1], udp.server_address[1])
                print(f"PASS {kind}/{version}/{mode}/tls={secure}/custom={bool(extra)}: TCP + UDP", flush=True)
        print(f"Passed {len(cases)} XHTTP protocol/mode/HTTP combinations on loopback.")


if __name__ == "__main__":
    main()
