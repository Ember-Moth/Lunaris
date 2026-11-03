#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Loopback VLESS Encryption / Vision interoperability with an independent Xray client."""
import argparse
import contextlib
import hashlib
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
spec = importlib.util.spec_from_file_location("extensions", pathlib.Path(__file__).with_name("test-extensions.py"))
ext = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ext)
base = ext.base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=pathlib.Path, required=True)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris-web"))
    args = parser.parse_args()
    client, server = str(args.client.resolve()), str(args.server.resolve())
    subprocess.run([client, "version"], check=True)
    with tempfile.TemporaryDirectory(prefix="lunaris-vless-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        reality = json.loads(subprocess.check_output([server, "keygen", "reality"], text=True))
        encryption = json.loads(subprocess.check_output([server, "keygen", "reality"], text=True))
        pq = dict(line.split(": ", 1) for line in subprocess.check_output([client, "mlkem768"], text=True).splitlines() if ": " in line)
        key_pairs = {"native": encryption, "xorpub": encryption, "random": encryption,
                     "mlkem": {"private_key": pq["Seed"], "public_key": pq["Client"]},
                     "chain": {"private_key": encryption["private_key"] + "." + pq["Seed"], "public_key": encryption["public_key"] + "." + pq["Client"]}}
        tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTCP)
        udp = socketserver.UDPServer(("127.0.0.1", 0), base.EchoUDP)
        targets = []
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            target = socketserver.ThreadingTCPServer(("127.0.0.1", 0), base.EchoTLS)
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.minimum_version = tls.maximum_version = version
            tls.load_cert_chain(cert, key)
            tls.set_alpn_protocols(["h2", "http/1.1"])
            target.tls_context = tls
            target.handle_error = lambda request, address: None
            targets.append(target)
        for echo in (tcp, udp, *targets):
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
        cases = [(carrier, mode, rtt, vision, port()) for carrier in ("tcp", "tls", "reality", "ws", "httpupgrade", "xhttp-h2", "xhttp-h3") for mode in ("native", "xorpub", "random") for rtt in ("1rtt", "0rtt") for vision in (False, True)]
        cases += [(f"xhttp-{version}-{upload}", "random", "0rtt", True, port()) for version in ("h1", "h2", "h3") for upload in ("packet-up", "stream-up")]
        cases += [("tcp", mode, rtt, True, port()) for mode in ("mlkem", "chain") for rtt in ("1rtt", "0rtt")]
        cases += [(carrier, "none", "1rtt", True, port()) for carrier in ("tls", "reality")]
        credentials = [{"id": "uuid", "secret": base.UUID}, {"id": "reality", "secret": reality["private_key"]}]
        for mode, pair in key_pairs.items():
            wire_mode = mode if mode in ("native", "xorpub", "random") else "native"
            credentials.append({"id": mode, "secret": f"mlkem768x25519plus.{wire_mode}.600s.100-35-35.{pair['private_key']}"})
        listeners = []
        for i, (carrier, mode, rtt, vision, endpoint) in enumerate(cases):
            item = {"id": f"case-{i}", "protocol": "vless", "address": "127.0.0.1", "port": endpoint, "credential_refs": ["uuid"], "options": {}}
            if mode != "none":
                item["options"]["decryption_ref"] = mode
            if vision:
                item["options"]["flow"] = "xtls-rprx-vision"
            if carrier in ("tls", "ws", "httpupgrade") or carrier.startswith("xhttp"):
                item["certificate_ref"] = "tls"
            if carrier in ("tls", "tcp"):
                item["transport"] = {"type": "tcp"}
            elif carrier == "reality":
                item["transport"] = {"type": "reality", "reality": {"target": f"127.0.0.1:{targets[1].server_address[1]}", "server_names": ["localhost"], "private_key_ref": "reality", "short_ids": ["0102030405060708"]}}
            elif carrier.startswith("xhttp"):
                item["transport"] = {"type": "xhttp", "path": "/proxy", "xhttp": {"http_version": carrier.split("-")[1], "mode": carrier.split("-", 2)[2] if carrier.count("-") > 1 else "stream-one"}}
            else:
                item["transport"] = {"type": carrier, "path": "/proxy"}
            listeners.append(item)
        proc = stack.enter_context(base.managed_node(server, root, listeners=listeners, credentials={item["id"]: item["secret"] for item in credentials}, certificates={"tls": (cert, key)}))
        for carrier, mode, rtt, vision, endpoint in cases:
            inbound = port()
            user = {"id": base.UUID, "encryption": "none" if mode == "none" else f"mlkem768x25519plus.{mode if mode in ('native', 'xorpub', 'random') else 'native'}.{rtt}.100-35-35.{key_pairs[mode]['public_key']}"}
            if vision:
                user["flow"] = "xtls-rprx-vision"
            stream = {"network": "tcp", "security": "none"}
            if carrier == "reality":
                stream.update(security="reality", realitySettings={"serverName": "localhost", "fingerprint": "chrome", "password": reality["public_key"], "shortId": "0102030405060708"})
            elif carrier != "tcp":
                stream.update(security="tls", tlsSettings={"serverName": "localhost", "pinnedPeerCertSha256": pin, "alpn": [("http/1.1" if carrier.split("-")[1] == "h1" else carrier.split("-")[1]) if carrier.startswith("xhttp") else "http/1.1"]})
            if carrier in ("ws", "httpupgrade"):
                stream.update(network=carrier)
                stream[carrier + "Settings"] = {"path": "/proxy"}
            elif carrier.startswith("xhttp"):
                stream.update(network="xhttp", xhttpSettings={"path": "/proxy", "mode": carrier.split("-", 2)[2] if carrier.count("-") > 1 else "stream-one"})
            config = {"log": {"loglevel": "error"}, "inbounds": [{"listen": "127.0.0.1", "port": inbound, "protocol": "socks", "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"}}], "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "127.0.0.1", "port": endpoint, "users": [user]}]}, "streamSettings": stream}]}
            path = root / "client.json"
            path.write_text(json.dumps(config)); path.chmod(0o600)
            name = f"{carrier}/{mode}/{rtt}/vision={vision}"
            with base.process([client, "run", "-c", str(path)], root / "client.log") as child:
                base.ready(child, inbound)
                print("RUN " + name, flush=True)
                ext.verify_proxy(inbound, tcp.server_address[1], udp.server_address[1])
                # Reuse this Xray process so 0-RTT cases actually resume a cached ticket.
                for version, target in zip((ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3), targets):
                    raw, _ = base.socks(inbound, 1, target.server_address[1])
                    ctx = ssl.create_default_context(cafile=cert)
                    ctx.minimum_version = ctx.maximum_version = version
                    with ctx.wrap_socket(raw, server_hostname="localhost") as secure:
                        for size in (37, 131072, 19):
                            payload = os.urandom(size)
                            secure.sendall(payload)
                            assert base.exact(secure, size) == payload
                print("PASS " + name + ": TCP + XUDP + inner TLS 1.2/1.3", flush=True)
        print(f"Passed {len(cases)} VLESS combinations on loopback.")


if __name__ == "__main__":
    main()
