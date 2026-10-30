"""Read-only audit contract and DNS proposal regression tests."""
import base64
import ipaddress
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from auth_audit import audit_domain
from dns_inspector import DNSError


class _PositiveFixtureIPv4(ipaddress.IPv4Address):
    """Test-only RFC documentation IP with simulated public-egress attribute."""

    @property
    def is_global(self):
        return True


class AuthenticationAuditTests(unittest.TestCase):
    def resolve(self, data):
        return lambda name, typ="TXT": data.get((name, typ), [])

    def base(self):
        domain = "example.org"
        key = base64.b64encode(b"sample-rsa-key" * 12).decode("ascii")
        data = {
            ("_rsm." + domain, "TXT"): ["rsm-verification=approved"],
            (domain, "TXT"): ["v=spf1 a mx ip4:203.0.113.15 ip4:198.51.100.10 ~all",
                             "other-service-verification=yes"],
            ("default._domainkey." + domain, "TXT"): ["v=DKIM1; k=rsa; p=" + key],
            ("_dmarc." + domain, "TXT"): ["v=DMARC1; p=none; rua=mailto:dmarc@" + domain],
        }
        return data

    def audit(self, data, ip="198.51.100.10", selector="default", proof="rsm-verification=approved"):
        # TEST ONLY: RFC 5737 addresses are intentionally not globally routable.
        # Mock the public-egress validation for the normal positive fixture while
        # preserving the real production validator and all negative-path tests.
        if ip == "198.51.100.10":
            with patch("auth_audit.ipaddress") as mocked_ip:
                mocked_ip.ip_address.side_effect = _PositiveFixtureIPv4
                mocked_ip.ip_network.side_effect = ipaddress.ip_network
                return audit_domain("example.org", ip, selector, proof, self.resolve(data))
        return audit_domain("example.org", ip, selector, proof, self.resolve(data))

    def test_existing_good_records_do_not_trigger_destructive_proposals(self):
        data = self.base()
        a = self.audit(data)
        self.assertEqual(a["ownership"]["status"], "verified_dns")
        self.assertEqual(a["spf"]["status"], "verified_dns")
        self.assertEqual(a["dkim"]["status"], "verified_dns")
        self.assertEqual(a["dkim"]["signing"], "not_verified")
        self.assertEqual(a["dmarc"]["status"], "verified_dns")
        self.assertEqual(a["summary"], "dns_records_verified_live_signing_unverified")
        self.assertIsNone(a["spf"]["proposal"])
        self.assertNotIn("approved", str(a))
        self.assertIsNone(a["dmarc"]["proposal"])

    def test_missing_spf_proposes_only_reviewable_single_new_record(self):
        data = self.base()
        data[("example.org", "TXT")] = ["google-verification=xxx"]
        a = self.audit(data)
        self.assertEqual(a["spf"]["status"], "needs_action")
        self.assertEqual(a["spf"]["proposal"]["action"], "create_after_review")
        self.assertIn("198.51.100.10", a["spf"]["proposal"]["value"])

    def test_spf_add_ip_preserves_existing_tokens(self):
        data = self.base()
        data[("example.org", "TXT")] = ["v=spf1 a mx ip4:203.0.113.15 ~all"]
        a = self.audit(data)
        self.assertIn("ip4:203.0.113.15 ip4:198.51.100.10 ~all",
                      a["spf"]["proposal"]["value"])
        self.assertEqual(a["spf"]["proposal"]["action"], "replace_existing")

    def test_multiple_spf_or_dmarc_never_automerge(self):
        data = self.base()
        data[("example.org", "TXT")].append("v=spf1 -all")
        data[("_dmarc.example.org", "TXT")].append("v=DMARC1; p=reject")
        a = self.audit(data)
        self.assertEqual(a["spf"]["status"], "needs_action")
        self.assertIsNone(a["spf"]["proposal"])
        self.assertIsNone(a["dmarc"]["proposal"])

    def test_redirect_macros_no_edit(self):
        data = self.base()
        data[("example.org", "TXT")] = ["v=spf1 redirect=_spf.example.org"]
        a = self.audit(data)
        self.assertEqual(a["spf"]["status"], "review")
        self.assertIsNone(a["spf"]["proposal"])

    def test_missing_dkim_no_fake_public_key_or_signing_success(self):
        data = self.base()
        data.pop(("default._domainkey.example.org", "TXT"))
        a = self.audit(data)
        self.assertEqual(a["dkim"]["status"], "needs_action")
        self.assertIsNone(a["dkim"]["proposal"])
        self.assertEqual(a["dkim"]["signing"], "not_verified")

    def test_dmarc_record_candidate_only_if_absent(self):
        data = self.base()
        data.pop(("_dmarc.example.org", "TXT"))
        a = self.audit(data)
        self.assertEqual(a["dmarc"]["proposal"]["value"], "v=DMARC1; p=none")

    def test_ownership_removed_does_not_appear_verified(self):
        data = self.base()
        data.pop(("_rsm.example.org", "TXT"))
        a = self.audit(data)
        self.assertEqual(a["ownership"]["status"], "needs_action")
        self.assertEqual(a["summary"], "attention_or_further_evidence_required")

    def test_spf_negative_all_prevents_false_positive(self):
        data = self.base()
        data[("example.org", "TXT")] = ["v=spf1 -all ip4:198.51.100.10"]
        a = self.audit(data)
        self.assertEqual(a["spf"]["status"], "needs_action")

    def test_real_egress_validator_still_rejects_documentation_ip(self):
        with self.assertRaises(DNSError):
            audit_domain("example.org", "198.51.100.10",
                         resolver=self.resolve(self.base()))

    def test_ip_unknown_does_not_mark_spf_pass(self):
        data = self.base()
        a = self.audit(data, ip="")
        self.assertEqual(a["spf"]["status"], "not_checked")

    def test_invalid_untrusted_inputs_fail_closed(self):
        data = self.base()
        for ip in ("127.0.0.1", "192.168.0.1", "192.0.2.1", "bad-ip"):
            with self.subTest(ip=ip), self.assertRaises(DNSError):
                self.audit(data, ip=ip)
        with self.assertRaises(DNSError):
            audit_domain("example.invalid", "198.51.100.10", resolver=self.resolve(data))
        with self.assertRaises(DNSError):
            self.audit(data, selector="bad/selector")


if __name__ == "__main__":
    unittest.main()
