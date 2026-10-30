import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
import rsm

class TestWHMInventory(unittest.TestCase):
    def test_parses_authoritative_owner(self):
        class Result:
            stdout=json.dumps({'metadata':{'result':1},'data':{'acct':[
                {'user':'testacc','owner':'demoowner','email':'legal@example.com','domain':'test.example.com'},
                {'user':'bad user','owner':'other','email':'x@example.com'},
                {'user':'danger','owner':'evil\nuser','email':'x@example.com'},
                {'user':'otheracc','owner':'root','email':'root@example.com'}
            ]}})
        with patch.object(rsm.subprocess,'run',return_value=Result()) as call:
            accounts=rsm.whm_accounts()
            self.assertEqual(accounts['testacc']['owner'],'demoowner')
            self.assertEqual(accounts['otheracc']['owner'],'root')
            self.assertEqual(len(accounts),2)
            args=call.call_args.args[0]
            self.assertEqual(args[1:3],['--output=json','listaccts'])
    def test_rejects_whm_metadata_failure(self):
        class Result:
            stdout=json.dumps({'metadata':{'result':0},'data':{'acct':[]}})
        with patch.object(rsm.subprocess,'run',return_value=Result()):
            with self.assertRaises(rsm.RSMError):rsm.whm_accounts()
    def test_reseller_roster_parsed_without_shell(self):
        with tempfile.NamedTemporaryFile(mode='w+',encoding='ascii') as f:
            f.write('demoowner:all\nother:limited\ninvalid user:all\n')
            f.flush()
            with patch.object(rsm,'RES_FILE',f.name):
                self.assertEqual(rsm.reseller_set(),{'demoowner','other'})
if __name__=='__main__':unittest.main()
