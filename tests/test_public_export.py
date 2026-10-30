"""Safety gates for a stand-alone, clean-history public source snapshot."""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"scripts"/"audit_public_release.py"
spec=importlib.util.spec_from_file_location("public_audit",SCRIPT)
audit=importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

class PublicSnapshotTests(unittest.TestCase):
    def test_neutral_emails_and_documentation_ips(self):
        self.assertTrue(audit.is_sample_email("release@example.invalid"))
        self.assertTrue(audit.is_sample_email("sender@dept.example.org"))
        self.assertFalse(audit.is_sample_email("person@"+"provider.com"))
        self.assertEqual(audit.public_findings("safe",b"mail@example.org 192.0.2.14"),[])
        real_mail=b"recipient@company"+b".com"
        real_ip=b"8.8."+b"8.8"
        self.assertIn("non-example email",str(audit.public_findings("sample",real_mail)))
        self.assertIn("public IPv4",str(audit.public_findings("sample",real_ip)))

    def test_release_source_version_and_current_changelog(self):
        self.assertEqual((ROOT / "VERSION").read_text(encoding="utf-8").strip(),
                         "1.0.0")
        log = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        import re
        headings = re.findall(r"^## (\d+\.\d+\.\d+[^\n]*)", log, re.M)
        self.assertEqual(len(headings), 1, headings)
        self.assertTrue(headings[0].startswith("1.0.0"), headings)
        self.assertTrue((ROOT / "docs/RELEASE_ACCEPTANCE.md").is_file())
        self.assertNotIn("arsamnet", (ROOT / "tests/test_whm.py").read_text())

    def test_release_acceptance_public_ipv4_screen(self):
        # A four-field WHM maintenance version resembles an IPv4 address.
        # Keep the strict scanner enabled; public release prose should not
        # accidentally include a routable four-octet value.
        acceptance = (ROOT / "docs/RELEASE_ACCEPTANCE.md").read_bytes()
        self.assertEqual(audit.public_findings("release acceptance", acceptance), [])

    def test_private_legacy_dummy_session_exemption_is_sha_scoped(self):
        fixture = b"cp" + b"sess" + b"1234567890"
        real_looking = b"cp" + b"sess" + b"9876543210"
        legacy = audit.PRIVATE_TEST_FIXTURE_BLOB
        self.assertEqual(audit.scan(legacy, fixture), [])
        self.assertIn("whm-session", str(audit.scan("tests/current.py", fixture)))
        self.assertIn("whm-session", str(audit.scan(legacy, real_looking)))
        self.assertIn("whm-session", str(audit.scan(legacy, fixture + real_looking)))

    def test_clean_export_does_not_inherit_personal_commit_history(self):
        if not (shutil.which("git") and shutil.which("tar")):
            self.skipTest("git/tar missing")
        with tempfile.TemporaryDirectory() as base:
            source=Path(base)/"private"
            target=Path(base)/"public"
            source.mkdir()
            (source/"scripts").mkdir()
            shutil.copy2(ROOT/"scripts"/"audit_public_release.py",
                         source/"scripts"/"audit_public_release.py")
            shutil.copy2(ROOT/"scripts"/"export_public_snapshot.sh",
                         source/"scripts"/"export_public_snapshot.sh")
            (source/"VERSION").write_text("1.0.0\n")
            (source/".gitignore").write_text("secret.txt\n")
            (source/"README.md").write_text("Example recipient: recipient@example.org\n")
            (source/"secret.txt").write_text("DO NOT COPY")
            subprocess.run(["git","init","-q",str(source)],check=True)
            subprocess.run(["git","-C",str(source),"add","."],check=True)
            original_author="Example Private User"
            original_email="private"+"@"+"provider.com"
            subprocess.run(["git","-C",str(source),"-c",f"user.name={original_author}",
                            "-c",f"user.email={original_email}","-c","commit.gpgsign=false",
                            "commit","-q","-m","Private history"],check=True)
            proc=subprocess.run(["bash","scripts/export_public_snapshot.sh",str(target)],
                                cwd=source,capture_output=True,text=True)
            self.assertEqual(proc.returncode,0,proc.stdout+"\n"+proc.stderr)
            self.assertFalse((target/"secret.txt").exists())
            self.assertEqual(subprocess.check_output(
                ["git","-C",str(target),"rev-list","--count","HEAD"],text=True).strip(),"1")
            author=subprocess.check_output(["git","-C",str(target),"log","-1","--format=%ae"],
                                           text=True).strip()
            self.assertEqual(author,"release@example.invalid")
            self.assertEqual(subprocess.check_output(
                ["git","-C",str(target),"remote"],text=True).strip(),"")
            self.assertNotIn(original_email,subprocess.check_output(
                ["git","-C",str(target),"log","--format=%ae"],text=True))

    def test_source_tree_contains_no_known_private_production_samples(self):
        needles=["websitex"+".net","195.211."+"44.218","78.110."+"120.15",
                 "satrapit"+"@gmail.com", "Arsamnet"+"/whm-reseller-mail-manager"]
        tracked=subprocess.check_output(["git","ls-files","-z"],cwd=ROOT)
        for name in filter(None,tracked.split(b"\x00")):
            p=ROOT/os.fsdecode(name)
            if not p.is_file() or p.stat().st_size>2_000_000:
                continue
            if b"\x00" in p.read_bytes()[:8192]:
                continue
            content=p.read_text(encoding="utf-8",errors="ignore").lower()
            for needle in needles:
                self.assertNotIn(needle.lower(),content,str(p.relative_to(ROOT)))

if __name__=="__main__":
    unittest.main()
