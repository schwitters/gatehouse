"""Exercise reconciliation preconditions and advisory error handling."""
import importlib.util
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("audit", ROOT / "scripts/check-dependencies.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class ToolingTest(unittest.TestCase):
    def test_advisory_ranges(self):
        self.assertTrue(audit.affected("1.3.3", ">= 1.3.0, <= 1.3.3"))
        self.assertFalse(audit.affected("1.3.4", ">= 1.3.0, <= 1.3.3"))
        self.assertTrue(audit.affected("1.3.4", "1.3.4"))
        with self.assertRaises(ValueError):
            audit.affected("1.3.4", "unknown")

    def test_reconciliation_requires_stopped_service_and_matching_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            database = str(Path(directory) / "test.db")
            with sqlite3.connect(database) as db:
                db.executescript("""CREATE TABLE provisioning_job(invite_id TEXT, tenant_id TEXT,
                    uid TEXT, stage INTEGER, updated_at INTEGER);
                    CREATE TABLE provisioning_event(invite_id TEXT, stage INTEGER, actor TEXT,
                    created_at INTEGER);
                    INSERT INTO provisioning_job VALUES('invite', 'tenant', 'user', 1, 0);""")
            command = [sys.executable, str(ROOT / "scripts/reconcile-provisioning.py"), database, "invite"]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            self.assertNotEqual(subprocess.run(command + ["--confirmed", "principal-created"],
                                               capture_output=True).returncode, 0)
            self.assertEqual(subprocess.run(command + ["--service-stopped", "--confirmed", "principal-created"],
                                            capture_output=True).returncode, 0)
            self.assertNotEqual(subprocess.run(command + ["--service-stopped", "--confirmed", "principal-absent"],
                                               capture_output=True).returncode, 0)
            with sqlite3.connect(database) as db:
                self.assertEqual(db.execute("SELECT stage FROM provisioning_job").fetchone()[0], 2)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM provisioning_event").fetchone()[0], 1)

    @mock.patch.object(audit.subprocess, "check_output", return_value="a" * 40)
    @mock.patch.object(audit, "fetch_json")
    def test_dependency_audit_fails_on_active_advisories(self, fetch_json, check_output):
        fetch_json.side_effect = lambda url, *args: {"vulns": [{"id": "TEST-1"}]} if "osv.dev" in url else []
        with mock.patch("builtins.print"):
            self.assertTrue(audit.audit("build"))

    @mock.patch.object(audit.subprocess, "check_output", return_value="a" * 40)
    @mock.patch.object(audit, "fetch_json")
    def test_dependency_audit_does_not_hide_network_failures(self, fetch_json, check_output):
        fetch_json.side_effect = OSError("offline")
        with self.assertRaises(OSError):
            audit.audit("build")


if __name__ == "__main__":
    unittest.main()
