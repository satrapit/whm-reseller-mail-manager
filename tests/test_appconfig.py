"""Regression coverage for WHM AppConfig navigation URLs.

WHM renders entries under /cgi/; entryurl must not repeat that prefix.
"""
import unittest
from pathlib import Path


class WHMAppConfigPaths(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parents[1]
        cls.config = dict(
            line.split("=", 1)
            for line in (root / "plugin" / "rsm.conf").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#") and "=" in line
        )
        cls.cgi = root / "cgi" / "index.cgi"

    def test_root_only_whm_registration(self):
        self.assertEqual(self.config["service"], "whostmgr")
        self.assertEqual(self.config["user"], "root")
        self.assertEqual(self.config["acls"], "all")

    def test_navigation_url_matches_registered_cgi_route(self):
        self.assertEqual(self.config["url"], "/cgi/rsm/index.cgi")
        self.assertEqual(self.config["entryurl"], "rsm/index.cgi")
        self.assertEqual("/cgi/" + self.config["entryurl"], self.config["url"])
        self.assertTrue(self.cgi.is_file())


if __name__ == "__main__":
    unittest.main()
