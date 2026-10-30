"""Minimal end-to-end RSM DKIM signer checks, no privileged server needed."""
import base64
import hashlib
import re
import subprocess
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import dkim_signing


class DKIMSignerTests(unittest.TestCase):
    def test_no_key_preserves_unsigned_message(self):
        raw = b"From: a@example.com\r\n\r\nHello\r\n"
        with tempfile.TemporaryDirectory() as t, patch.object(dkim_signing, "ROOT", Path(t)):
            self.assertEqual(dkim_signing.sign_message(raw, "example.com"), raw)

    def test_key_directory_and_file_permissions_enforced(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            root.chmod(0o700)
            key = root / "example.com.pem"
            key.write_text("not-a-real-private-key")
            key.chmod(0o644)
            with patch.object(dkim_signing,"ROOT",root), self.assertRaises(dkim_signing.DKIMError):
                dkim_signing._safe_key("example.com")
            key.chmod(0o600)
            with patch.object(dkim_signing,"ROOT",root):
                self.assertEqual(dkim_signing._safe_key("example.com"),key)
            root.chmod(0o755)
            with patch.object(dkim_signing,"ROOT",root), self.assertRaises(dkim_signing.DKIMError):
                dkim_signing._safe_key("example.com")

    def test_dns_key_matching_rejects_duplicate_records(self):
        record={"name":"rsm2026._domainkey.example.com","value":"v=DKIM1; k=rsa; p=QUJD"}
        with patch.object(dkim_signing,"public_record",return_value=record), \
             patch.object(dkim_signing,"lookup",return_value=[record["value"],record["value"]]):
            self.assertFalse(dkim_signing.dns_matches("example.com"))

    def test_canonicalization_normalizes_wsp_and_empty_body(self):
        self.assertEqual(dkim_signing._canon_body(b"hello \t world\t\r\n\r\n\r\n"),
                         b"hello world\r\n")
        self.assertEqual(dkim_signing._canon_body(b""), b"\r\n")

    def test_refuses_dkim_mismatch_without_downgrading(self):
        with patch.object(dkim_signing, "_safe_key", return_value=Path("/fake/private.pem")), \
             patch.object(dkim_signing, "dns_matches", return_value=False):
            with self.assertRaises(dkim_signing.DKIMError):
                dkim_signing.sign_message(b"From: a@example.com\r\n\r\nx", "example.com")

    @unittest.skipUnless(Path("/usr/bin/openssl").exists(), "OpenSSL is required")
    def test_real_rsa_signature_verifies_against_exported_public_key(self):
        raw = (b"From: Hosting Service <sender@example.com>\r\n"
               b"To: receiver@example.net\r\n"
               b"Subject: Notice\r\n"
               b"Date: Tue, 27 Oct 2026 13:00:00 +0000\r\n"
               b"Message-ID: <rsm-test@example.com>\r\n"
               b"\r\nHello  world \r\n")
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            root.chmod(0o700)
            key = root / "example.com.pem"
            subprocess.run(["/usr/bin/openssl", "genpkey", "-algorithm", "RSA",
                            "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=True, timeout=25)
            key.chmod(0o600)
            pub = root / "public.pem"
            subprocess.run(["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout",
                            "-out", str(pub)], check=True, capture_output=True)
            with patch.object(dkim_signing, "ROOT", root), \
                 patch.object(dkim_signing, "dns_matches", return_value=True):
                signed = dkim_signing.sign_message(raw, "example.com")
            sigline = signed.split(b"\r\n", 1)[0]
            signature = base64.b64decode(sigline.rsplit(b"b=", 1)[1])
            sig_file = root / "sig.bin"
            sig_file.write_bytes(signature)
            signed_headers = raw.split(b"\r\n\r\n", 1)[0].split(b"\r\n")
            values = dict(line.split(b":", 1) for line in signed_headers)
            normalized = {name.lower():value for name,value in values.items()}
            data = b"".join(dkim_signing._canon_header(name.encode("ascii"), normalized[name.encode("ascii")])
                            for name in dkim_signing.SIGNED_HEADERS)
            # RFC 6376 §3.7: unlike h= headers, the DKIM-Signature
            # canonicalization has NO final CRLF in the signed byte stream.
            # This deliberately independently checks the wire-level contract.
            self.assertTrue(sigline.startswith(b"DKIM-Signature: v=1;"))
            canonical_sig_header = dkim_signing._canon_header(
                b"DKIM-Signature", sigline.split(b":", 1)[1].rsplit(b"b=", 1)[0] + b"b="
            )
            self.assertTrue(canonical_sig_header.endswith(b"\r\n"))
            data += canonical_sig_header[:-2]
            result = subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-verify",
                                     str(pub), "-signature", str(sig_file)],
                                    input=data, capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
            self.assertIn(b"Verified OK", result.stdout)
            # Regression for the exact defect observed at Gmail: the earlier
            # signer incorrectly hashed a CRLF after DKIM-Signature.
            invalid = subprocess.run(["/usr/bin/openssl", "dgst", "-sha256", "-verify",
                                      str(pub), "-signature", str(sig_file)],
                                     input=data + b"\r\n", capture_output=True, check=False)
            self.assertNotEqual(invalid.returncode, 0,
                                "A trailing CRLF must invalidate the RFC 6376 header signature")
            self.assertEqual(base64.b64decode(re.search(rb"bh=([^;]+)", sigline).group(1)),
                             hashlib.sha256(dkim_signing._canon_body(raw.split(b"\r\n\r\n",1)[1])).digest())

    def test_invalid_domain_cannot_escape_private_storage(self):
        for domain in ("../../etc/passwd", "example.local", "host.invalid"):
            with self.assertRaises(dkim_signing.DKIMError):
                dkim_signing._path(domain)


if __name__ == "__main__":
    unittest.main()
