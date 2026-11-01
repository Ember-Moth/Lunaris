#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Loopback interop with an independently supplied sing-box release binary.

Requires Python 3 and openssl; never downloads software or changes system routing.
Usage: python3 scripts/test-interop.py --client /path/to/sing-box --server bin/lunaris
"""
import argparse
import contextlib
import json
import pathlib
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time

UUID = "c8820ed3-e4ee-47ad-a5bd-ece70763e32c"
PASSWORD = "lunaris-disposable-interop-password"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def exact(sock, size):
    result = b""
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise RuntimeError("unexpected EOF")
        result += part
    return result


def address(sock, kind):
    if kind == 1:
        host = socket.inet_ntop(socket.AF_INET, exact(sock, 4))
    elif kind == 4:
        host = socket.inet_ntop(socket.AF_INET6, exact(sock, 16))
    elif kind == 3:
        host = exact(sock, exact(sock, 1)[0]).decode()
    else:
        raise RuntimeError("unknown SOCKS address type")
    return host, struct.unpack("!H", exact(sock, 2))[0]


def socks(port, command, destination):
    sock = socket.create_connection(("127.0.0.1", port), 3)
    try:
        sock.sendall(b"\x05\x01\x00")
        assert exact(sock, 2) == b"\x05\x00"
        sock.sendall(bytes([5, command, 0, 1]) + socket.inet_aton("127.0.0.1") + struct.pack("!H", destination))
        reply = exact(sock, 4)
        assert reply[:2] == b"\x05\x00", reply
        return sock, address(sock, reply[3])
    except BaseException:
        sock.close()
        raise


class EchoTCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        while data := self.request.recv(65535):
            self.request.sendall(data)


class EchoUDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        sock.sendto(data, self.client_address)


@contextlib.contextmanager
def process(command, log):
    with log.open("w") as output:
        child = subprocess.Popen(command, stdout=output, stderr=output)
        try:
            yield child
        except BaseException:
            print(log.read_text()[-5000:])
            raise
        finally:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def ready(child, port):
    end = time.monotonic() + 5
    while time.monotonic() < end:
        if child.poll() is not None:
            raise RuntimeError("process exited before readiness")
        try:
            with socket.create_connection(("127.0.0.1", port), 0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError("listener readiness timeout")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=pathlib.Path, required=True)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris"))
    args = parser.parse_args()
    client, server = str(args.client.resolve()), str(args.server.resolve())
    subprocess.run([client, "version"], check=True)
    matrix = []
    for kind in ("vless", "vmess", "trojan"):
        for carrier in ("tcp", "ws", "httpupgrade"):
            for secure in ((True,) if kind == "trojan" else (False, True)):
                matrix.append((kind, carrier, secure))
    matrix += [("anytls", "tcp", True), ("hysteria2", "quic", True), ("tuic", "quic", True)]
    with tempfile.TemporaryDirectory(prefix="lunaris-interop-") as temp, contextlib.ExitStack() as stack:
        root = pathlib.Path(temp)
        cert, key = root / "cert.pem", root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ports = set()
        def port():
            value = free_port()
            while value in ports:
                value = free_port()
            ports.add(value)
            return value
        scenarios = [(kind, carrier, secure, port()) for kind, carrier, secure in matrix]
        node = root / "node.yaml"
        text = f"schema_version: 1\ncertificates:\n  - id: tls\n    certificate_file: cert.pem\n    private_key_file: key.pem\ncredentials:\n  - id: uuid\n    secret: {UUID}\n  - id: password\n    secret: {PASSWORD}\nlisteners:\n"
        for index, (kind, carrier, secure, endpoint) in enumerate(scenarios):
            ref = "uuid" if kind in ("vless", "vmess") else "password"
            transport = {"type": carrier}
            if carrier in ("ws", "httpupgrade"):
                transport.update(path="/proxy", host="localhost")
            options = {"users": [{"uuid": UUID, "credential_ref": ref}]} if kind == "tuic" else {}
            text += f"  - id: test-{index}\n    protocol: {kind}\n    address: 127.0.0.1\n    port: {endpoint}\n    credential_refs: [{ref}]\n    transport: {json.dumps(transport)}\n    options: {json.dumps(options)}\n"
            if secure:
                text += "    certificate_ref: tls\n"
        node.write_text(text)
        node.chmod(0o600)
        subprocess.run([server, "check", "--config", str(node)], check=True)
        tcp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), EchoTCP)
        tcp.daemon_threads = True
        udp = socketserver.UDPServer(("127.0.0.1", 0), EchoUDP)
        for echo in (tcp, udp):
            threading.Thread(target=echo.serve_forever, daemon=True).start()
            stack.callback(echo.server_close)
            stack.callback(echo.shutdown)
        node_process = stack.enter_context(process([server, "run", "--config", str(node)], root / "node.log"))
        ready(node_process, scenarios[0][3])
        for kind, carrier, secure, endpoint in scenarios:
            outbound = {"type": kind, "tag": "proxy", "server": "127.0.0.1", "server_port": endpoint}
            if kind in ("vless", "vmess", "tuic"):
                outbound["uuid"] = UUID
            if kind in ("trojan", "anytls", "hysteria2", "tuic"):
                outbound["password"] = PASSWORD
            if kind == "vmess":
                outbound.update(security="aes-128-gcm", alter_id=0)
            if kind in ("vless", "vmess"):
                outbound["packet_encoding"] = ""  # Native protocol UDP framing.
            if secure:
                outbound["tls"] = {"enabled": True, "server_name": "localhost", "certificate_path": str(cert)}
            if kind == "tuic":
                outbound["tls"]["alpn"] = ["h3"]
            if carrier in ("ws", "httpupgrade"):
                outbound["transport"] = {"type": carrier, "path": "/proxy"}
                if carrier == "ws":
                    outbound["transport"]["headers"] = {"Host": "localhost"}
                else:
                    outbound["transport"]["host"] = "localhost"
            inbound = port()
            config = {"log": {"level": "error"}, "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": inbound}], "outbounds": [outbound]}
            path = root / "client.json"
            path.write_text(json.dumps(config))
            with process([client, "run", "-c", str(path)], root / "client.log") as client_process:
                ready(client_process, inbound)
                conn, _ = socks(inbound, 1, tcp.server_address[1])
                with conn:
                    payload = b"TCP through released client" * 3000
                    conn.sendall(payload)
                    assert exact(conn, len(payload)) == payload
                if kind != "anytls":
                    control, destination = socks(inbound, 3, 0)
                    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as datagram:
                        datagram.settimeout(3)
                        host, udp_port = destination
                        if host == "0.0.0.0":
                            host = "127.0.0.1"
                        payload = b"UDP through released client" * 100
                        header = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", udp.server_address[1])
                        datagram.sendto(header + payload, (host, udp_port))
                        response, _ = datagram.recvfrom(65535)
                        assert response[:4] == header[:4] and response[10:] == payload
                print(f"PASS {kind}/{carrier}/tls={secure}: TCP" + (" + UDP" if kind != "anytls" else ""), flush=True)
        print(f"Passed {len(scenarios)} protocol/transport combinations on loopback.")


if __name__ == "__main__":
    main()
