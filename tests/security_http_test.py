"""Exercise security boundaries against an isolated local server and database."""
import hashlib
import http.client
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.parse

with tempfile.TemporaryDirectory(prefix="gatehouse-http-") as directory:
    database = str(Path(directory) / "test.db")
    endpoint = str(Path(directory) / "server.sock")
    environment = dict(os.environ, GATEHOUSE_MASTER_KEY_HEX="11" * 32)
    with open(Path(directory) / "server.log", "w+") as log:
        process = subprocess.Popen(
            [sys.argv[1], "--db", database, "--unix-socket", endpoint,
             "--realm", "LOCAL.INVALID", "--secure-cookies", "--threads", "4"],
            cwd=sys.argv[2], env=environment, stdout=log, stderr=log)
        try:
            def request(method, path, body=None, cookie=None):
                connection = http.client.HTTPConnection("localhost", timeout=5)
                connection.sock = socket.socket(socket.AF_UNIX)
                connection.sock.settimeout(5)
                connection.sock.connect(endpoint)
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                if cookie:
                    headers["Cookie"] = cookie
                connection.request(method, path, body, headers)
                response = connection.getresponse()
                result = response.status, dict(response.getheaders()), response.read().decode()
                connection.close()
                return result

            for attempt in range(100):
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError(log.read())
                if Path(endpoint).exists():
                    break
                time.sleep(0.05)
            status, headers, body = request("GET", "/login?err=" + urllib.parse.quote("<script>alert(1)</script>"))
            assert status == 200 and "<script>alert(1)</script>" not in body
            assert "&lt;script&gt;" in body

            now = int(time.time())
            token = "22" * 32
            with sqlite3.connect(database) as db:
                db.execute("""INSERT INTO invite
                    (invite_id, tenant_id, invited_email, invited_uid, token_hash,
                     status, created_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    ("test-invite", "default", "user@example.invalid", "user",
                     hashlib.sha256(bytes.fromhex(token)).digest(), 0, now, now + 3600))
            status, headers, body = request("GET", "/invite/accept?token=" + token)
            assert status == 302 and "; Secure" in headers["Set-Cookie"]
            cookie = headers["Set-Cookie"].split(";", 1)[0]
            accepted_sid = cookie.split("=", 1)[1]
            with sqlite3.connect(database) as db:
                db.execute("""INSERT INTO invite_otp
                    (otp_id, sid, otp_hash, issued_at, expires_at, consumed_at)
                    VALUES (?, ?, ?, ?, ?, ?)""",
                    ("verified", accepted_sid, b"hash", now, now + 600, now))
                db.execute("UPDATE invite SET status=6, revoked_at=?", (now,))
            status, _, _ = request("POST", "/invite/complete", urllib.parse.urlencode(
                {"_csrf": accepted_sid, "password": "password1", "password_confirm": "password1"}), cookie)
            assert status == 401
            with sqlite3.connect(database) as db:
                assert db.execute("SELECT status FROM invite").fetchone()[0] == 6
            # Missing provisioning configuration must never report a completed account.
            with sqlite3.connect(database) as db:
                db.execute("UPDATE invite SET status=3, revoked_at=NULL")
            status, _, _ = request("POST", "/invite/complete", urllib.parse.urlencode(
                {"_csrf": accepted_sid, "password": "password1", "password_confirm": "password1"}), cookie)
            assert status == 503
            with sqlite3.connect(database) as db:
                assert db.execute("SELECT status FROM invite").fetchone()[0] == 3
                assert db.execute("SELECT stage FROM provisioning_job").fetchone()[0] == 0
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=8) as pool:
                statuses = list(pool.map(lambda _: request("GET", "/login")[0], range(40)))
            assert all(status == 200 for status in statuses)
            assert request("GET", "/assets/portal.js")[0] == 200
            # Accounts behind the same peer must have independent budgets.
            for attempt in range(11):
                status, _, _ = request("POST", "/auth/login", "username=a%40FOREIGN.INVALID&password=p")
            assert status == 429
            status, _, _ = request("POST", "/auth/login", "username=b%40FOREIGN.INVALID&password=p")
            assert status == 302
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
