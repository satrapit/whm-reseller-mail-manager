"""Execute the real CGI authorization gate in a sandboxed Perl module environment.

This is not a real WHM session test. We exercise the unmodified access-control
logic against synthetic REMOTE_USER and ACL values, without reading real WHM
state, loading vendor WHM modules, invoking the Python backend or sending mail.
"""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CGI = ROOT / "cgi" / "index.cgi"

ACL_STUB = """package Whostmgr::ACLS;
use strict;
use warnings;
sub init_acls { return 1; }
sub checkacl { return (($ENV{RSM_TEST_HAS_ALL} // '') eq '1') ? 1 : 0; }
1;
"""
TEMPLATE_STUB = """package Cpanel::Template;
use strict;
use warnings;
sub process_template { die "CGI should not reach template render"; }
1;
"""


class CGIPrivilegedAccessTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("perl"):
            self.skipTest("Perl unavailable")
        self.tmp = tempfile.TemporaryDirectory(prefix="rsm-cgi-acl-")
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        for path, content in (
            ("Whostmgr/ACLS.pm", ACL_STUB),
            ("Cpanel/Template.pm", TEMPLATE_STUB),
        ):
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

        # The production CGI forces /usr/local/cpanel ahead of vendor imports.
        # Replace only that library location in a throwaway test copy so that
        # running unit tests as root on a live WHM host cannot import vendor code.
        source = CGI.read_text(encoding="utf-8")
        marker = "use lib '/usr/local/cpanel/';"
        self.assertEqual(source.count(marker), 1)
        patched = source.replace(marker, "use lib '" + root.as_posix() + "';", 1)
        self.cgi = root / "index.cgi"
        self.cgi.write_text(patched, encoding="utf-8")

    def invoke(self, who, acl, method, query="", session=True):
        env = os.environ.copy()
        env.update({
            "REMOTE_USER": who,
            "RSM_TEST_HAS_ALL": "1" if acl else "0",
            "REQUEST_METHOD": method,
            "QUERY_STRING": query,
            "REQUEST_URI": ("/" + "cp" + "sess" + "1234567890" + "/cgi/rsm/index.cgi" if session
                            else "/cgi/rsm/index.cgi"),
            "CONTENT_LENGTH": "0",
            "CONTENT_TYPE": "application/x-www-form-urlencoded",
        })
        return subprocess.run(
            ["perl", str(self.cgi)], input="", text=True, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8,
            check=False,
        )

    def assert_denied(self, who, acl, method, query=""):
        process = self.invoke(who, acl, method, query)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("Status: 403 Forbidden", process.stdout)
        self.assertTrue(process.stdout.rstrip().endswith("Access denied"))
        self.assertNotIn("Content-Type: text/html", process.stdout)
        self.assertNotIn("Reseller System Mail Manager", process.stdout)
        self.assertNotIn("rsm-verification=", process.stdout)
        self.assertNotIn("sender@example.org", process.stdout)
        self.assertNotIn("CGI should not reach", process.stderr)

    def test_reseller_denied_even_when_whm_all_acl_is_granted(self):
        for method in ("GET", "POST", "PUT"):
            with self.subTest(method=method):
                self.assert_denied("demoowner", True, method)

    def test_root_denied_without_whm_all_acl(self):
        self.assert_denied("root", False, "GET")

    def test_missing_user_denied(self):
        self.assert_denied("", True, "GET")

    def test_url_headers_and_query_cannot_spoof_root(self):
        self.assert_denied(
            "demoowner", True, "GET",
            query="REMOTE_USER=root&user=root&action=dashboard"
        )

    def test_plugin_registration_is_root_only(self):
        data = (ROOT / "plugin" / "rsm.conf").read_text(encoding="utf-8")
        self.assertIn("service=whostmgr\n", data)
        self.assertIn("user=root\n", data)
        self.assertIn("acls=all\n", data)


if __name__ == "__main__":
    unittest.main()
