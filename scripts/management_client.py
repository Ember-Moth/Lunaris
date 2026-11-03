# SPDX-License-Identifier: GPL-3.0-only
"""Test-only JSON API provisioning and SQLite-backed node process helpers.

Fixtures are passed as in-memory objects. No node configuration file is parsed
or imported, and no SQLite tables are written outside the public management API.
"""
import contextlib
import copy
import http.client
import http.cookies
import json
import pathlib
import socket
import subprocess
import time


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class API:
    def __init__(self, port):
        self.port = port
        self.origin = f"http://127.0.0.1:{port}"
        self.cookie = ""
        self.csrf = ""

    def call(self, method, path, value=None, *, status=200, headers=None):
        body = json.dumps(value) if value is not None else None
        h = {"Origin": self.origin}
        if body is not None:
            h["Content-Type"] = "application/json"
        if self.cookie:
            h["Cookie"] = self.cookie
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        h.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=h)
            response = conn.getresponse()
            raw = response.read()
            data = json.loads(raw)
            assert response.status == status, (method, path, response.status, data.get("code"), data.get("msg"))
            assert set(data) == {"code", "msg", "data"}
            assert response.getheader("Cache-Control") == "no-store"
            if status < 300:
                assert data["code"] == 0
            if value and path.endswith("/auth/login") and status == 200:
                cookies = http.cookies.SimpleCookie(response.getheader("Set-Cookie"))
                item = cookies["lunaris_session"]
                assert item["httponly"] and item["samesite"].lower() == "strict" and item["path"] == "/"
                self.cookie = f"lunaris_session={item.value}"
                self.csrf = data["data"]["csrf_token"]
            return data["data"], dict(response.getheaders())
        finally:
            conn.close()


@contextlib.contextmanager
def running(binary, root, data_dir, port):
    log = root / "server.log"
    with log.open("a") as output:
        p = subprocess.Popen([binary, "serve", "--data-dir", str(data_dir), "--listen", f"127.0.0.1:{port}"], stdout=output, stderr=output)
        try:
            end = time.monotonic() + 15
            while True:
                if p.poll() is not None:
                    raise RuntimeError("management process exited before readiness")
                try:
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=0.3)
                    conn.request("GET", "/healthz")
                    response = conn.getresponse(); response.read(); conn.close()
                    if response.status == 200:
                        break
                except OSError:
                    pass
                if time.monotonic() > end:
                    raise TimeoutError("management readiness")
                time.sleep(0.03)
            yield p
        finally:
            p.terminate()
            try:
                code = p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill(); p.wait(); raise RuntimeError("management shutdown timed out")
            if code != 0:
                raise RuntimeError(f"management process exit {code}")


def seed_node(binary, root, *, listeners, credentials=None, certificates=None, limits=None):
    """Create a disposable installation through the API, commit, then stop it."""
    root = pathlib.Path(root)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    state = root / "state"
    if state.exists():
        raise ValueError("fixture data directory already exists")
    port = free_port()
    while port in {item["port"] for item in listeners}:
        port = free_port()
    password = "disposable-management-fixture-password"
    api = API(port)
    with running(binary, root, state, port):
        token = (state / "setup-token").read_text().strip()
        api.call("POST", "/api/v1/setup", {"token": token, "username": "fixture", "password": password}, status=201)
        api.call("POST", "/api/v1/auth/login", {"username": "fixture", "password": password})
        credential_assets, certificate_assets = {}, {}
        for logical, secret in (credentials or {}).items():
            asset, _ = api.call("POST", "/api/v1/credentials", {"kind": "generic", "label": logical, "secret": secret}, status=201)
            credential_assets[logical] = asset["id"]
        for logical, (certificate, private_key) in (certificates or {}).items():
            asset, _ = api.call("POST", "/api/v1/certificates", {"label": logical, "certificate": pathlib.Path(certificate).read_text(), "private_key": pathlib.Path(private_key).read_text()}, status=201)
            certificate_assets[logical] = asset["id"]
        configured = copy.deepcopy(listeners)
        for listener in configured:
            listener.setdefault("enabled", True)
            listener.setdefault("options", {})
        config = {"schema_version": 1, "listeners": configured}
        if limits is not None:
            config["limits"] = limits
        document = {"config": config, "credential_assets": credential_assets, "certificate_assets": certificate_assets}
        api.call("POST", "/api/v1/config/validate", document)
        draft, _ = api.call("PUT", "/api/v1/config/draft", document, headers={"If-Match": '"r0"'})
        plan, _ = api.call("POST", "/api/v1/config/plans", {"draft_revision": draft["id"], "base_revision": "r0"})
        accepted, _ = api.call("POST", "/api/v1/config/apply", {"plan_id": plan["plan_id"]}, status=202, headers={"Idempotency-Key": "fixture-apply"})
        deadline = time.monotonic() + 120
        while True:
            operation, _ = api.call("GET", "/api/v1/operations/" + accepted["operation_id"])
            if operation["status"] != "running":
                if operation["status"] != "succeeded":
                    raise RuntimeError("fixture application failed: " + operation["status"])
                break
            if time.monotonic() >= deadline:
                raise TimeoutError("fixture application")
            time.sleep(0.03)
    return state


@contextlib.contextmanager
def managed_process(binary, state, log):
    """Run only the committed proxy runtime; the provisioning HTTP service is off."""
    with pathlib.Path(log).open("w") as output:
        child = subprocess.Popen([binary, "managed", "--data-dir", str(state)], stdout=output, stderr=output)
        failed = False
        try:
            deadline = time.monotonic() + 45
            while "Managed node started" not in pathlib.Path(log).read_text():
                if child.poll() is not None:
                    raise RuntimeError("managed fixture exited before readiness: " + pathlib.Path(log).read_text()[-5000:])
                if time.monotonic() >= deadline:
                    raise TimeoutError("managed fixture startup")
                time.sleep(0.03)
            yield child
        except BaseException:
            failed = True
            raise
        finally:
            child.terminate()
            try:
                code = child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                child.kill(); child.wait()
                raise RuntimeError("managed fixture shutdown timed out")
            if code != 0 and not failed:
                raise RuntimeError(f"managed fixture exit {code}")


@contextlib.contextmanager
def managed_node(binary, root, *, listeners, credentials=None, certificates=None, limits=None):
    state = seed_node(binary, root, listeners=listeners, credentials=credentials, certificates=certificates, limits=limits)
    with managed_process(binary, state, pathlib.Path(root) / "node.log") as child:
        yield child
