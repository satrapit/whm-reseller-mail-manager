import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import rsm
from dns_inspector import lookup_cost,suggested_spf,diagnostics,DNSError

class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.dir=tempfile.TemporaryDirectory()
        self.prior=rsm.APP_DIR
        rsm.APP_DIR=Path(self.dir.name)/'state'
        rsm.DB_FILE=rsm.APP_DIR/'state.sqlite3'
        self.db=rsm.connect()
        self.accounts={'client1':{'user':'client1','owner':'demoowner','email':'client@client.test'},
                       'client2':{'user':'client2','owner':'other','email':'other@client.test'},
                       'rootuser':{'user':'rootuser','owner':'root','email':'root@example.net'}}
        self.resellers={'demoowner','other'}
        self.config={'demoowner':dict(enabled=1,verified=1,email='hostmaster@example.org')}
        self.settings={'enabled':'1','default_sender':'server@example.net','default_sender_verified':'1'}
    def tearDown(self):
        self.db.close()
        self.dir.cleanup()
        rsm.APP_DIR=self.prior
        rsm.DB_FILE=self.prior/'state.sqlite3'
    def select(self,name):return rsm.decision(self.settings,self.config,self.accounts,self.resellers,name)
    def test_fresh_install_never_impersonates_vendor_domain(self):
        self.assertEqual(rsm.get_settings(self.db)['default_sender'], '')
        self.assertEqual(rsm.get_settings(self.db)['enabled'], '0')

    def test_custom_reseller(self):self.assertEqual(self.select('client1')['sender'],'hostmaster@example.org')
    def test_other_reseller_default(self):self.assertEqual(self.select('client2')['sender'],'server@example.net')
    def test_root_default(self):self.assertEqual(self.select('rootuser')['sender'],'server@example.net')
    def test_unknown_account_unchanged(self):self.assertIsNone(self.select('unknown')['sender'])
    def test_deleted_reseller_no_leak(self):
        self.resellers.remove('demoowner')
        self.assertEqual(self.select('client1')['sender'],'server@example.net')
    def test_transfer_owner_updates_decision(self):
        self.accounts['client1']['owner']='other'
        self.assertEqual(self.select('client1')['sender'],'server@example.net')
    def test_unverified_fallback(self):
        self.config['demoowner']['verified']=0
        self.assertEqual(self.select('client1')['sender'],'server@example.net')
    def test_default_identity_fails_closed_without_ownership_verification(self):
        self.settings['default_sender_verified']='0'
        self.assertIsNone(self.select('client2')['sender'])
        self.assertEqual(self.select('client1')['sender'],'hostmaster@example.org')

    def test_default_sender_challenge_and_domain_reverification(self):
        with patch.object(rsm,'dns_text') as mock:
            result=rsm.save_general(self.db,{'email':'mailer@example.org','enabled':'1'})
            settings=rsm.get_settings(self.db)
            self.assertEqual(settings['default_sender_verified'],'0')
            self.assertTrue(settings['default_sender_token'])
            mock.return_value=['rsm-verification='+settings['default_sender_token']]
            rsm.verify_general(self.db,{})
            self.assertEqual(rsm.get_settings(self.db)['default_sender_verified'],'1')
            # Change address => old verification is not inherited.
            rsm.save_general(self.db,{'email':'other@example.org','enabled':'1'})
            new=rsm.get_settings(self.db)
            self.assertEqual(new['default_sender_verified'],'0')
            self.assertNotEqual(settings['default_sender_token'],new['default_sender_token'])

    def test_rotate_challenge_revokes_existing_reseller_sender(self):
        with patch.object(rsm,'inventory',return_value=(self.accounts,self.resellers,{})):
            rsm.save_reseller(self.db,{'reseller':'demoowner','email':'hostmaster@example.org','enabled':'1'})
            self.db.execute("UPDATE reseller_config SET verified=1 WHERE reseller='demoowner'")
            self.db.commit()
            old=rsm.get_configs(self.db)['demoowner']['token']
            with self.assertRaises(rsm.RSMError):
                rsm.rotate_challenge(self.db,{'reseller':'demoowner','confirm':'no'})
            rsm.rotate_challenge(self.db,{'reseller':'demoowner','confirm':'yes'})
            now=rsm.get_configs(self.db)['demoowner']
            self.assertEqual(now['verified'],0)
            self.assertNotEqual(now['token'],old)

    def test_rotate_general_revokes_default_identity(self):
        rsm.save_general(self.db,{'email':'hostmaster@example.org','enabled':'1'})
        token=rsm.get_settings(self.db)['default_sender_token']
        self.db.execute("UPDATE settings SET value='1' WHERE key='default_sender_verified'")
        self.db.commit()
        rsm.rotate_challenge(self.db,{'scope':'general','confirm':'yes'})
        now=rsm.get_settings(self.db)
        self.assertEqual(now['default_sender_verified'],'0')
        self.assertNotEqual(now['default_sender_token'],token)

    def test_send_limit_is_atomic_and_can_release_only_same_claim(self):
        with patch.object(rsm.time,'time',return_value=1000000):
            c1=rsm.claim_notice(self.db,'client1')
            with self.assertRaises(rsm.RSMError):
                rsm.claim_notice(self.db,'client1')
            rsm.release_notice(self.db,'client1','incorrect-token')
            with self.assertRaises(rsm.RSMError):
                rsm.claim_notice(self.db,'client1')
            rsm.release_notice(self.db,'client1',c1)
            c2=rsm.claim_notice(self.db,'client1')
            self.assertNotEqual(c1,c2)
        with patch.object(rsm.time,'time',return_value=1000800):
            self.assertNotEqual(c2,rsm.claim_notice(self.db,'client1'))

    def test_state_directory_symlinks_are_rejected(self):
        self.db.close()
        db_file=rsm.DB_FILE
        db_file.rename(db_file.with_suffix('.back'))
        db_file.symlink_to(db_file.with_suffix('.back'))
        with self.assertRaises(rsm.RSMError):
            rsm.connect()
        db_file.unlink()
        db_file.with_suffix('.back').rename(db_file)
        self.db=rsm.connect()

    def test_global_killswitch(self):
        self.settings['enabled']='0'
        self.assertIsNone(self.select('client1')['sender'])
    def test_save_reseller_and_reset_verification(self):
        with patch.object(rsm,'inventory',return_value=(self.accounts,self.resellers,{})):
            rsm.save_reseller(self.db,{'reseller':'demoowner','enabled':'1','email':'a@example.org'})
            before=rsm.get_configs(self.db)['demoowner']
            self.assertEqual(before['verified'],0)
            self.db.execute('UPDATE reseller_config SET verified=1 WHERE reseller=?',('demoowner',));self.db.commit()
            rsm.save_reseller(self.db,{'reseller':'demoowner','enabled':'1','email':'b@example.org'})
            after=rsm.get_configs(self.db)['demoowner']
            self.assertEqual(after['verified'],0)
            self.assertNotEqual(before['token'],after['token'])
    def test_verify_positive(self):
        with patch.object(rsm,'inventory',return_value=(self.accounts,self.resellers,{})):
            rsm.save_reseller(self.db,{'reseller':'demoowner','enabled':'1','email':'h@example.org'})
            token=rsm.get_configs(self.db)['demoowner']['token']
            with patch.object(rsm,'dns_text',return_value=['rsm-verification='+token]):
                rsm.verify(self.db,{'reseller':'demoowner'})
            self.assertEqual(rsm.get_configs(self.db)['demoowner']['verified'],1)
    def test_verify_negative_doesnt_grant(self):
        with patch.object(rsm,'inventory',return_value=(self.accounts,self.resellers,{})):
            rsm.save_reseller(self.db,{'reseller':'demoowner','enabled':'1','email':'h@example.org'})
            with patch.object(rsm,'dns_text',return_value=[]):
                with self.assertRaises(rsm.RSMError):rsm.verify(self.db,{'reseller':'demoowner'})
            self.assertEqual(rsm.get_configs(self.db)['demoowner']['verified'],0)
    def test_reject_nonexistent_reseller(self):
        with patch.object(rsm,'inventory',return_value=(self.accounts,self.resellers,{})):
            with self.assertRaises(rsm.RSMError):
                rsm.save_reseller(self.db,{'reseller':'missing','email':'h@example.com'})
    def test_validate_header_injection(self):
        for address in ['x@example.com\r\nBcc: x@sample.example.com','a@localhost','a@127.0.0.1','a@example.com\n','"Test" <h@example.org>']:
            with self.subTest(address=address),self.assertRaises(rsm.RSMError):rsm.check_email(address)
    def test_validate_username_injection(self):
        for name in ['$(touch /tmp/pwn)','../etc/passwd','other;whoami','UPPER']:
            with self.subTest(name=name),self.assertRaises(rsm.RSMError):rsm.check_user(name)
    def test_dns_inspection_passes_real_selector(self):
        with patch('dns_inspector.diagnostics',return_value={'domain':'example.org'}) as mock:
            self.assertEqual(rsm.inspect({'email':'hostmaster@example.org',
                'ip':'192.0.2.10','selector':'Mail1'}),{'domain':'example.org'})
            mock.assert_called_once_with('example.org','192.0.2.10','mail1')

    def test_dns_inspection_rejects_bad_selector(self):
        for selector in ['a._domainkey.example.com','x' * 64,'x\\nInjected',42]:
            with self.subTest(selector=selector):
                with patch('dns_inspector.diagnostics') as mock:
                    with self.assertRaises(rsm.RSMError):
                        rsm.inspect({'email':'hostmaster@example.org','selector':selector})
                    mock.assert_not_called()

    def test_dns_insert_before_all(self):
        rec='v=spf1 a mx include:_spf.example.net ~all'
        self.assertEqual(suggested_spf(rec,'192.0.2.5')[0],
                         'v=spf1 a mx include:_spf.example.net ip4:192.0.2.5 ~all')
    def test_dns_existing_network(self):
        rec='v=spf1 ip4:192.0.2.0/24 -all'
        self.assertEqual(suggested_spf(rec,'192.0.2.5')[0],rec)
    def test_dns_redirect_conservative(self):
        self.assertIsNone(suggested_spf('v=spf1 redirect=example.net','192.0.2.5')[0])
    def test_dns_ipv6(self):
        self.assertIn('ip6:2001:db8::1',suggested_spf('v=spf1 ~all','2001:db8::1')[0])
    def test_dns_lookup_limit(self):
        self.assertEqual(lookup_cost('v=spf1 a mx include:a.com include:b.com -all'),4)
    def test_duplicate_spf(self):
        def fake(domain,rrtype='TXT'):
            if domain=='example.com':return ['v=spf1 -all','v=spf1 ~all']
            return []
        with patch('dns_inspector.lookup',side_effect=fake):
            r=diagnostics('example.com')
            self.assertEqual(len(r['spf_records']),2)
            self.assertIsNone(r['suggested'])
    def test_dns_alignment_unknown(self):
        with patch('dns_inspector.lookup',return_value=[]):
            self.assertIn('Unknown',diagnostics('example.com')['alignment'])
    def test_no_secret_in_audit(self):
        with patch.object(rsm,'inventory',return_value=(self.accounts,self.resellers,{})):
            rsm.save_reseller(self.db,{'reseller':'demoowner','enabled':'1','email':'h@example.org'})
        token=rsm.get_configs(self.db)['demoowner']['token']
        audit=' '.join(row['result'] for row in self.db.execute('SELECT result FROM audit'))
        self.assertNotIn(token,audit)

if __name__=='__main__':unittest.main()
