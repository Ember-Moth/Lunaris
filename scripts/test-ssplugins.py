#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Loopback Shadowsocks plugins using the independent Mihomo helper client."""
import argparse
import base64
import contextlib
import importlib.util
import json
import os
import pathlib
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("interop", pathlib.Path(__file__).with_name("test-interop.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=pathlib.Path, default=pathlib.Path("bin/test-ssplugins-client"))
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris-web"))
    parser.add_argument("--filter", default="", help="run cases whose label contains this text")
    args = parser.parse_args()
    server, client = str(args.server.resolve()), str(args.client.resolve())
    with tempfile.TemporaryDirectory(prefix="lunaris-ssplugins-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTCP)
        udp = socketserver.UDPServer(("127.0.0.1", 0), base.EchoUDP)
        targets = []
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            target = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTLS)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = tls.maximum_version = version
            tls.load_cert_chain(cert, key)
            target.tls_context = tls
            target.handle_error = lambda request, address: None
            targets.append(target)
        for echo in (tcp, udp, *targets):
            echo.daemon_threads = True
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            stack.callback(echo.server_close)
            stack.callback(echo.shutdown)
        plugin_password = "disposable-plugin-secret"
        variants = []
        def add(label, kind, options, client_options, secure=False, path="", host=""):
            variants.append((label, kind, options, client_options, secure, path, host))
        for mode in ("http", "tls"):
            add("obfs-" + mode, "obfs", {"mode": mode}, {"mode": mode, "host": "localhost"})
        for kind in ("v2ray-plugin", "gost-plugin"):
            for mux in (False, True):
                for secure in (False, True):
                    client_opts = {"mode": "websocket", "mux": mux, "tls": secure, "host": "localhost", "path": "/proxy", "skip-cert-verify": True}
                    add(f"{kind}-mux={mux}-tls={secure}", kind, {"mux": mux}, client_opts, secure, "/proxy", "localhost")
                    if kind == "v2ray-plugin":
                        add(f"{kind}-upgrade-mux={mux}-tls={secure}", kind, {"mux": mux, "v2ray-http-upgrade": True}, {**client_opts, "v2ray-http-upgrade": True}, secure, "/proxy", "localhost")
                        add(f"{kind}-early-mux={mux}-tls={secure}", kind, {"mux": mux}, {**client_opts, "path": "/proxy?ed=2048"}, secure, "/proxy?ed=2048", "localhost")
        for version in (1, 2, 3):
            target = targets[0 if version < 3 else 1]
            options = {"version": version, "handshake": f"127.0.0.1:{target.server_address[1]}"}
            if version > 1:
                options["password_ref"] = "plugin"
            if version == 3:
                options["strict-mode"] = True
            add(f"shadow-tls-v{version}", "shadow-tls", options, {"version": version, "password": plugin_password, "host": "localhost", "skip-cert-verify": True})
        for hint, target in zip(("tls12", "tls13"), targets):
            add("restls-" + hint, "restls", {"password_ref": "plugin", "dest": f"127.0.0.1:{target.server_address[1]}"}, {"password": plugin_password, "host": "localhost", "version-hint": hint, "skip-cert-verify": True})
        for crypt in ("aes", "aes-128-gcm"):
            for compressed in (True, False):
                opts = {"crypt": crypt, "nocomp": not compressed, "smuxver": 2 if compressed else 1, "datashard": 10, "parityshard": 3}
                add(f"kcptun-{crypt}-comp={compressed}", "kcptun", {**opts, "key_ref": "plugin"}, {**opts, "key": plugin_password})
        methods = ("aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305")
        credentials = [{"id": "plugin", "secret": plugin_password}]
        secrets = {}
        for i, method in enumerate(methods):
            secret = "disposable-ss-password" if not method.startswith("2022-") else base64.b64encode(os.urandom(16 if "aes-128" in method else 32)).decode()
            secrets[method] = secret
            credentials.append({"id": f"key-{i}", "secret": secret})
        used = set()
        def port():
            value = base.free_port()
            while value in used:
                value = base.free_port()
            used.add(value)
            return value
        cases, listeners = [], []
        for i, method in enumerate(methods):
            for label, kind, options, client_options, secure, path, host in variants:
                name = method + "/" + label
                if args.filter and args.filter not in name:
                    continue
                endpoint = port()
                transport = {"type": kind, "plugin": options}
                if path:
                    transport["path"] = path
                if host:
                    transport["host"] = host
                listener = {"id": f"case-{len(cases)}", "protocol": "shadowsocks", "address": "127.0.0.1", "port": endpoint, "credential_refs": [f"key-{i}"], "options": {"method": method}, "transport": transport, "udp_over_tcp": True}
                if secure:
                    listener["certificate_ref"] = "tls"
                listeners.append(listener)
                cases.append((name, kind, method, endpoint, client_options))
        if not cases:
            raise ValueError("no matching cases")
        proc = stack.enter_context(base.managed_node(server, root, listeners=listeners, credentials={item["id"]: item["secret"] for item in credentials}, certificates={"tls": (cert, key)}))
        negative = []
        for name, kind, method, endpoint, opts in cases:
            config = {"Server": f"127.0.0.1:{endpoint}", "Method": method, "Password": secrets[method], "Plugin": kind, "PluginOpts": opts, "TCPTarget": f"127.0.0.1:{tcp.server_address[1]}", "UDPTarget": f"127.0.0.1:{udp.server_address[1]}"}
            path = root / "client.json"
            path.write_text(json.dumps(config)); path.chmod(0o600)
            print("RUN " + name, flush=True)
            subprocess.run([client, "--config", str(path)], check=True, timeout=40)
            if method == "aes-128-gcm" and name.split("/", 1)[1] in ("shadow-tls-v2", "shadow-tls-v3", "restls-tls13", "kcptun-aes-comp=False"):
                invalid = {**config, "PluginOpts": {**opts}, "ExpectFailure": True}
                invalid["PluginOpts"]["key" if kind == "kcptun" else "password"] = "wrong-plugin-secret"
                negative.append((name, invalid, config))
        if not args.filter:
            assert len(negative) == 4
        for name, config, valid in negative:
            path = root / "invalid-client.json"
            path.write_text(json.dumps(config)); path.chmod(0o600)
            print("RUN wrong secret: " + name, flush=True)
            subprocess.run([client, "--config", str(path)], check=True, timeout=40)
            if proc.poll() is not None:
                raise RuntimeError("node exited while rejecting a credential")
            path.write_text(json.dumps(valid))
            subprocess.run([client, "--config", str(path)], check=True, timeout=40)
        print(f"Passed {len(cases)} Shadowsocks plugin/method combinations and {len(negative)} credential rejections on loopback.")


if __name__ == "__main__":
    main()
