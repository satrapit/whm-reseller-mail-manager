import sys
import unittest
import tempfile
from types import SimpleNamespace
from unittest.mock import patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from notify import compose
import notify
import rsm
from rsm import RSMError
class TestMail(unittest.TestCase):
    def test_construction(self):
        msg=compose('server@example.net','recipient@example.com','client1')
        self.assertEqual(msg['To'],'recipient@example.com')
        self.assertEqual(msg['Auto-Submitted'],'auto-generated')
        self.assertNotIn('\n',str(msg['From']))
    def test_notice_cli_dispatch_is_limited_after_first_send(self):
        # No actual WHM/DNS/Exim activity; exercise the DB-backed CLI guard.
        with tempfile.TemporaryDirectory() as d:
            old_dir,old_file=rsm.APP_DIR,rsm.DB_FILE
            rsm.APP_DIR=Path(d)/'state'
            rsm.DB_FILE=rsm.APP_DIR/'state.sqlite3'
            settings={'enabled':'1','default_sender':'','default_sender_verified':'0'}
            configs={'demoowner':{'enabled':1,'verified':1,'email':'hostmaster@example.org',
                                 'token':'test-ownership-token'}}
            accounts={'demoacct':{'user':'demoacct','owner':'demoowner','email':'recipient@example.com'}}
            try:
                with patch.object(notify,'inventory',return_value=(accounts,{'demoowner'},{})), \
                     patch.object(notify,'get_settings',return_value=settings), \
                     patch.object(notify,'get_configs',return_value=configs), \
                     patch.object(notify,'lookup',return_value=['rsm-verification=test-ownership-token']), \
                     patch.object(notify,'sign_message',side_effect=lambda raw,domain:raw), \
                     patch.object(notify.subprocess,'run',return_value=SimpleNamespace(returncode=0)) as send, \
                     patch.object(sys,'argv',['notify.py','--account','demoacct','--send']), \
                     patch.object(notify,'is_root',return_value=True):
                    notify.main()
                    self.assertEqual(send.call_count,1)
                    with self.assertRaises(RSMError):
                        notify.main()
                    self.assertEqual(send.call_count,1)
            finally:
                rsm.APP_DIR,rsm.DB_FILE=old_dir,old_file
    def test_no_header_injection(self):
        with self.assertRaises(RSMError):compose('server@example.net','victim@example.com\nBcc:foo@example.org','client1')
    def test_no_untrusted_subject(self):
        msg=compose('server@example.net','victim@example.com','client1')
        self.assertEqual(msg['Subject'],'Hosting account information notice')
if __name__=='__main__':unittest.main()
