import sys
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dns_inspector import lookup,diagnostics,DNSError,suggested_spf

class DNSRecords(unittest.TestCase):
    def test_service_labels_supported(self):
        class Result:
            stdout='"rsm-verification=token"\n'
        with patch('dns_inspector.subprocess.run',return_value=Result()) as run:
            self.assertEqual(lookup('_rsm.example.org'),['rsm-verification=token'])
            self.assertEqual(lookup('_dmarc.example.org'),['rsm-verification=token'])
            self.assertEqual(lookup('default._domainkey.example.org'),['rsm-verification=token'])
            self.assertEqual(run.call_count,3)
    def test_reject_arbitrary_service_name(self):
        # Mock the resolver so a missing dig binary cannot cause a false pass.
        cases = [
            '-bad.example.com', '_evil.example.com', 'example.com\nInjected',
            'foo.localhost', 'foo.local', 'foo.test', 'foo.invalid',
            'foo.example', 'foo.internal', 'foo.home.arpa',
            '_rsm.foo.localhost', '_dmarc.foo.localhost',
            'default._domainkey.foo.localhost',
        ]
        with patch('dns_inspector.subprocess.run') as resolver:
            for name in cases:
                with self.subTest(name=name):
                    with self.assertRaises(DNSError):
                        lookup(name)
            resolver.assert_not_called()
    def test_spf_softfail_cidr_not_permitted(self):
        s='v=spf1 ~ip4:192.0.2.0/24 -all'
        self.assertNotEqual(suggested_spf(s,'192.0.2.1')[0],s)
    def test_dkim_selector_and_dmarc_policy(self):
        def fake(name,typ='TXT'):
            if name=='_dmarc.example.com':return ['v=DMARC1; p=quarantine; rua=mailto:x@example.com']
            if name=='s1._domainkey.example.com':return ['v=DKIM1; p=PUBKEY']
            return ['v=spf1 -all']
        with patch('dns_inspector.lookup',side_effect=fake):
            result=diagnostics('example.com',selector='s1')
            self.assertEqual(result['dmarc_policy'],'quarantine')
            self.assertIn('p=PUBKEY',result['dkim_dns'][0])

if __name__=='__main__':unittest.main()
