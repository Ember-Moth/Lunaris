#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Exercise the real management binary, restart, credentials and offline recovery."""
import argparse
import json
import pathlib
import socket
import subprocess
import tempfile
import sys
import time


sys.dont_write_bytecode = True
from management_client import API, free_port, running


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=pathlib.Path, default=pathlib.Path("bin/lunaris-web"))
    args = parser.parse_args(); binary = str(args.server.resolve())
    with tempfile.TemporaryDirectory(prefix="lunaris-management-") as temp:
        root = pathlib.Path(temp); state = root / "state"; restored = root / "restored"
        port, proxy_port = free_port(), free_port()
        api = API(port)
        first_password = "management-process-test-password"
        second_password = "changed-management-process-password"
        recovered_password = "locally-recovered-management-password"
        proxy_secret = "private-process-proxy-secret"
        with running(binary, root, state, port):
            setup = (state / "setup-token").read_text().strip()
            needed, _ = api.call("GET", "/api/v1/setup/status")
            assert needed == {"needs_setup": True}
            api.call("POST", "/api/v1/setup", {"token": setup, "username": "admin", "password": first_password}, status=201)
            assert not (state / "setup-token").exists()
            api.call("POST", "/api/v1/auth/login", {"username": "admin", "password": first_password})
            asset, _ = api.call("POST", "/api/v1/credentials", {"kind": "password", "label": "process-test", "secret": proxy_secret}, status=201)
            draft, response = api.call("PUT", "/api/v1/config/draft", {"config": {"schema_version": 1, "listeners": [{"id": "ss", "enabled": True, "protocol": "shadowsocks", "address": "127.0.0.1", "port": proxy_port, "network": ["tcp"], "credential_refs": ["device"], "options": {"method": "aes-128-gcm"}}]}, "credential_assets": {"device": asset["id"]}, "certificate_assets": {}}, headers={"If-Match": '"r0"'})
            revision = draft["id"]
            assert {k.lower(): v for k, v in response.items()}["etag"] == f'"{revision}"'
            plan, _ = api.call("POST", "/api/v1/config/plans", {"draft_revision": revision, "base_revision": "r0"})
            accepted, _ = api.call("POST", "/api/v1/config/apply", {"plan_id": plan["plan_id"], "acknowledge_disconnects": False}, status=202, headers={"Idempotency-Key": "process-apply"})
            deadline = time.monotonic() + 10
            while True:
                operation, _ = api.call("GET", "/api/v1/operations/" + accepted["operation_id"])
                if operation["status"] != "running":
                    assert operation["status"] == "succeeded", operation["status"]
                    break
                assert time.monotonic() < deadline
                time.sleep(0.02)
            with socket.create_connection(("127.0.0.1", proxy_port), 1):
                pass
            api.call("POST", "/api/v1/auth/reauth", {"password": first_password})
            connection, _ = api.call("POST", "/api/v1/listeners/ss/connection-info", {"committed_revision": revision, "host": "127.0.0.1", "credential_ref": "device"})
            assert connection["authentication"]["password"] == proxy_secret
            public, _ = api.call("GET", "/api/v1/config/draft")
            assert proxy_secret not in json.dumps(public)
            api.call("GET", "/api/v1/config/template", status=404)
            api.call("POST", "/api/v1/config/import", {"content": "listeners: []"}, status=404)
        print("PASS process setup, authentication, asset, draft, plan, apply and sensitive export")
        with running(binary, root, state, port):
            api.call("GET", "/api/v1/auth/session")
            status, _ = api.call("GET", "/api/v1/status")
            assert status["heads"]["committed_revision"] == revision and not status["provisional"]
            replay, _ = api.call("POST", "/api/v1/config/apply", {"plan_id": plan["plan_id"], "acknowledge_disconnects": False}, status=202, headers={"Idempotency-Key": "process-apply"})
            assert replay["operation_id"] == accepted["operation_id"]
            api.call("PUT", "/api/v1/auth/password", {"current_password": first_password, "new_password": second_password})
            api.call("GET", "/api/v1/auth/session", status=401)
            api.call("POST", "/api/v1/auth/login", {"username": "admin", "password": second_password})
        print("PASS committed restart, durable idempotency and password revocation")
        backup = root / "snapshot.db"
        subprocess.run([binary, "backup", "--data-dir", str(state), "--output", str(backup)], check=True, stdout=subprocess.DEVNULL)
        subprocess.run([binary, "restore", "--data-dir", str(restored), "--input", str(backup)], check=True, stdout=subprocess.DEVNULL)
        with running(binary, root, restored, port):
            api.call("GET", "/api/v1/auth/session", status=401)
            api.call("POST", "/api/v1/auth/login", {"username": "admin", "password": second_password})
            status, _ = api.call("GET", "/api/v1/status")
            assert status["heads"]["committed_revision"] == revision
        print("PASS backup/restore retains committed node and revokes copied sessions")
        password_file = root / "new-password"
        password_file.write_text(recovered_password + "\n"); password_file.chmod(0o600)
        subprocess.run([binary, "admin", "reset-password", "--data-dir", str(restored), "--password-file", str(password_file)], check=True, stdout=subprocess.DEVNULL)
        with running(binary, root, restored, port):
            api.call("GET", "/api/v1/auth/session", status=401)
            api.call("POST", "/api/v1/auth/login", {"username": "admin", "password": recovered_password})
        log = (root / "server.log").read_text()
        for sensitive in (setup, first_password, second_password, recovered_password, proxy_secret):
            assert sensitive not in log, "secret leaked into server log"
        print("PASS offline administrator recovery and log redaction")


if __name__ == "__main__":
    main()
