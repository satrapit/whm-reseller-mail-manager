"""Unit tests for the read-only live acceptance diagnostic."""
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
MODULE=ROOT/"scripts"/"verify_live_readonly.py"
spec=importlib.util.spec_from_file_location("verify_live_readonly",MODULE)
live=importlib.util.module_from_spec(spec)
spec.loader.exec_module(live)

class ReadonlyAcceptanceTests(unittest.TestCase):
    def test_secure_file_and_directory_reject_symlinks_and_weak_modes(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            root.chmod(0o700)
            file=root/"csrf.key"
            file.write_text("dummy-for-test")
            file.chmod(0o600)
            uid=os.geteuid()
            self.assertTrue(live.secure_directory(root,0o700,uid))
            self.assertTrue(live.secure_file(file,0o600,uid))
            root.chmod(0o755)
            self.assertFalse(live.secure_directory(root,0o700,uid))
            file.chmod(0o644)
            self.assertFalse(live.secure_file(file,0o600,uid))
            file.chmod(0o600)
            link=root/"alias.key"
            link.symlink_to(file)
            self.assertFalse(live.secure_file(link,0o600,uid))

    def test_database_diagnostic_is_read_only_and_does_not_disclose_secrets(self):
        with tempfile.TemporaryDirectory() as t:
            path=Path(t)/"state.sqlite3"
            secret="rsm-verification-"+("a"*48)
            with sqlite3.connect(path) as db:
                db.executescript("""
                CREATE TABLE settings (key TEXT PRIMARY KEY,value TEXT);
                CREATE TABLE reseller_config
                (reseller TEXT,enabled INTEGER,verified INTEGER,email TEXT,token TEXT);
                """)
                db.executemany("INSERT INTO settings VALUES (?,?)",
                               [("enabled","1"),("default_sender_verified","0")])
                db.execute("INSERT INTO reseller_config VALUES (?,?,?,?,?)",
                           ("example",1,1,"sender@example.test",secret))
            before=path.read_bytes()
            healthy,settings,rows=live.database_report(path)
            self.assertTrue(healthy)
            self.assertEqual(settings["enabled"],"1")
            self.assertEqual(rows[0]["reseller"],"example")
            self.assertTrue(rows[0]["challenge_present"])
            self.assertNotIn(secret,repr(rows))
            self.assertNotIn("sender@example.test",repr(rows))
            self.assertEqual(before,path.read_bytes())

    def test_source_comparison_only_reads(self):
        with tempfile.TemporaryDirectory() as t:
            a,b=Path(t)/"source",Path(t)/"installed"
            a.write_bytes(b"safe")
            b.write_bytes(b"safe")
            self.assertTrue(live.same_bytes(a,b))
            b.write_bytes(b"changed")
            self.assertFalse(live.same_bytes(a,b))
            self.assertFalse(live.same_bytes(a,Path(t)/"missing"))

    def test_safe_result_status(self):
        checks=[]
        live.result(checks,"one",True,"good")
        live.result(checks,"two",False,"broken")
        self.assertEqual([i["result"] for i in checks],["PASS","FAIL"])

if __name__=="__main__":
    unittest.main()
