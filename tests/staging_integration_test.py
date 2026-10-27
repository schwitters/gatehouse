"""Opt-in integration against disposable LDAP/Kerberos/SMTP/Guacamole staging services.

The JSON configuration must explicitly mark the user as disposable. Credentials
are never printed. An unconfigured invocation returns CTest's skip code.
"""
import base64
import hashlib
import http.client
import http.cookies
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request


def run(binary, source, config):
    assert config.get("disposable_user") is True, "Use a dedicated disposable LDAP user"
    password = "Gh-test-" + secrets.token_urlsafe(24)
    next_password = "Gh-next-" + secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="gatehouse-staging-") as directory:
        database = str(Path(directory) / "gatehouse.db")
        endpoint = str(Path(directory) / "server.sock")
        environment = dict(os.environ, GATEHOUSE_MASTER_KEY_HEX=secrets.token_hex(32))
        environment.update(config["environment"])
        arguments = [binary, "--db", database, "--unix-socket", endpoint, "--threads", "4"]
        arguments.extend(config["arguments"])
        with open(Path(directory) / "server.log", "w+") as log:
            process = subprocess.Popen(arguments, cwd=source, env=environment,
                                       stdout=log, stderr=log)
            try:
                def request(method, path, values=None, cookies=None, csrf=None, as_json=False):
                    connection = http.client.HTTPConnection("localhost", timeout=45)
                    connection.sock = socket.socket(socket.AF_UNIX)
                    connection.sock.settimeout(45)
                    connection.sock.connect(endpoint)
                    headers = {"Content-Type": "application/json" if as_json else
                               "application/x-www-form-urlencoded"}
                    if cookies:
                        headers["Cookie"] = "; ".join(f"{key}={value}" for key, value in cookies.items())
                    if csrf:
                        headers["X-CSRF-Token"] = csrf
                    body = None if values is None else (
                        json.dumps(values) if as_json else urllib.parse.urlencode(values))
                    connection.request(method, path, body, headers)
                    response = connection.getresponse()
                    jar = http.cookies.SimpleCookie()
                    for key, value in response.getheaders():
                        if key.lower() == "set-cookie":
                            jar.load(value)
                    result = response.status, {k: v.value for k, v in jar.items()}, response.read()
                    connection.close()
                    return result

                for _ in range(200):
                    assert process.poll() is None, "Staging server exited; inspect local configuration"
                    if Path(endpoint).exists():
                        break
                    time.sleep(0.05)
                now = int(time.time())
                token = secrets.token_hex(32)
                with sqlite3.connect(database) as db:
                    db.execute("""INSERT INTO invite
                        (invite_id, tenant_id, invited_uid, invited_email, token_hash,
                         status, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)""",
                        ("staging-invite", config["tenant"], config["uid"], config["email"],
                         hashlib.sha256(bytes.fromhex(token)).digest(), now, now + 3600))
                status, invitation_cookie, _ = request("GET", "/invite/accept?token=" + token)
                assert status == 302
                sid = invitation_cookie["gh_inv_sid"]
                with urllib.request.urlopen(config["mailpit_api"] + "/api/v1/messages", timeout=5) as response:
                    previous_messages = {item["ID"] for item in json.load(response)["messages"]}
                status, _, _ = request("POST", "/invite/otp/send", {"_csrf": sid}, invitation_cookie)
                assert status == 302, "SMTP or LDAP mail lookup failed"
                # Read only the disposable inbox through the staging Mailpit API.
                code = None
                for _ in range(50):
                    with urllib.request.urlopen(config["mailpit_api"] + "/api/v1/messages", timeout=5) as response:
                        messages = json.load(response)["messages"]
                    for message in messages:
                        if message["ID"] in previous_messages:
                            continue
                        if not any(item["Address"] == config["email"] for item in message["To"]):
                            continue
                        with urllib.request.urlopen(config["mailpit_api"] + "/api/v1/message/" + message["ID"], timeout=5) as response:
                            text = json.load(response)["Text"]
                        match = re.search(r"\b([1-9][0-9]{5})\b", text)
                        if match:
                            code = match[1]
                            break
                    if code:
                        break
                    time.sleep(0.1)
                assert code is not None, "No OTP received in the disposable inbox"
                wrong_code = "100000" if code != "100000" else "100001"
                status, _, _ = request("POST", "/invite/otp/verify",
                                       {"_csrf": sid, "code": wrong_code}, invitation_cookie)
                assert status == 302
                with sqlite3.connect(database) as db:
                    assert db.execute("SELECT attempts FROM invite_otp WHERE sid=?", (sid,)).fetchone()[0] == 1
                status, _, _ = request("POST", "/invite/otp/verify", {"_csrf": sid, "code": code}, invitation_cookie)
                assert status == 302
                status, _, _ = request("POST", "/invite/complete", {
                    "_csrf": sid, "password": password, "password_confirm": password,
                    "display_name": "Disposable staging user"}, invitation_cookie)
                assert status == 200, "Kerberos/LDAP provisioning failed; inspect the provisioning journal"
                with sqlite3.connect(database) as db:
                    assert db.execute("SELECT stage FROM provisioning_job").fetchone()[0] == 5
                def login(uid, credential):
                    return request("POST", "/api/auth/login", {"username": uid, "password": credential}, as_json=True)
                status, user_cookie, _ = login(config["uid"], password)
                assert status == 200, "Kerberos login failed after provisioning"
                status, _, _ = request("POST", "/portal/changepw", {
                    "_csrf": user_cookie["gh_csrf"], "old_password": password,
                    "new_password": next_password, "new_password_confirm": next_password}, user_cookie)
                assert status == 302
                assert login(config["uid"], password)[0] == 401
                status, user_cookie, _ = login(config["uid"], next_password)
                assert status == 200
                # Exercise the real Guacamole JSON auth extension and credential-fetch callback.
                status, _, payload = request("POST", "/api/me/guacamole-session", {
                    "hostname": config["hostname"], "protocol": "ssh"}, user_cookie,
                    user_cookie["gh_csrf"], as_json=True)
                assert status == 200
                guac_url = json.loads(payload)["url"]
                data = urllib.parse.parse_qs(urllib.parse.urlsplit(guac_url).fragment.split("?", 1)[1])["data"][0]
                guac_base = config["guacamole_url"].rstrip("/")
                with urllib.request.urlopen(urllib.request.Request(guac_base + "/api/tokens",
                        data=urllib.parse.urlencode({"data": data}).encode()), timeout=15) as response:
                    auth = json.load(response)
                auth_query = urllib.parse.urlencode({"token": auth["authToken"]})
                api = guac_base + "/api/session/data/" + urllib.parse.quote(auth["dataSource"], safe="")
                with urllib.request.urlopen(api + "/connections?" + auth_query, timeout=15) as response:
                    connections = json.load(response)
                identifier = next(iter(connections))
                with urllib.request.urlopen(api + "/connections/" + urllib.parse.quote(identifier, safe="") +
                                            "/parameters?" + auth_query, timeout=15) as response:
                    parameters = json.load(response)
                query = urllib.parse.urlencode({"token": parameters["password"], "uid": config["uid"],
                                                "host": config["hostname"]})
                status, _, payload = request("GET", "/api/cred-fetch/ticket?" + query)
                assert status == 200
                cache = Path(directory) / "fetched.ccache"
                cache.write_bytes(base64.b64decode(json.loads(payload)["ccache_b64"]))
                cache.chmod(0o600)
                assert subprocess.run(["klist", "-c", str(cache)], env=environment,
                                      capture_output=True).returncode == 0, "Invalid Kerberos cache"
                assert request("GET", "/api/cred-fetch/ticket?" + query)[0] == 401
                status, admin_cookie, _ = login(config["admin_uid"], config["admin_password"])
                assert status == 200
                status, _, _ = request("POST", "/api/admin/invites/revoke", {"invite_id": "staging-invite"},
                                       admin_cookie, admin_cookie["gh_csrf"], as_json=True)
                assert status == 200
                assert request("GET", "/invite/accept?token=" + token)[0] == 410
                assert login(config["uid"], next_password)[0] == 401
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    path = os.environ.get("GATEHOUSE_STAGING_CONFIG")
    if not path:
        print("Skipped: GATEHOUSE_STAGING_CONFIG is not configured")
        raise SystemExit(77)
    with open(path) as stream:
        configuration = json.load(stream)
    run(sys.argv[1], sys.argv[2], configuration)
