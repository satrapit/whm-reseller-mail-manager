#!/usr/bin/env python3
"""Root-only opt-in sender of *RSM-authored* account notice, never cPanel native email.

Dry-run by default. Recipient comes from current WHM account API, never from user input.
"""
import argparse
import json
import os
import subprocess
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formatdate, make_msgid
from email.utils import formataddr
from rsm import (RSMError,connect,decision,get_configs,get_settings,inventory,check_email,check_user,
                 claim_notice,release_notice)
from dns_inspector import lookup,DNSError
from dkim_signing import sign_message,DKIMError

SENDMAIL='/usr/sbin/sendmail'

def compose(sender,recipient,account):
    sender=check_email(sender);recipient=check_email(recipient);account=check_user(account)
    msg=EmailMessage()
    msg['From']=formataddr(('Hosting Service',sender))
    msg['To']=recipient
    msg['Subject']='Hosting account information notice'
    msg['Date']=formatdate(localtime=False)
    msg['Message-ID']=make_msgid(domain=sender.rsplit('@',1)[1])
    msg['Auto-Submitted']='auto-generated'
    msg['X-Auto-Response-Suppress']='All'
    msg.set_content(f'This informational notice was initiated by the hosting administrator for account {account}.\nContact your hosting provider if you did not expect it.\n')
    return msg

def is_root():
    return os.geteuid()==0


def main():
    parser=argparse.ArgumentParser(description='RSM-owned account notice; NEVER proxies native iContact')
    parser.add_argument('--account',required=True)
    parser.add_argument('--send',action='store_true',help='Explicitly dispatch to authoritative account contact email; otherwise dry-run')
    args=parser.parse_args()
    if not is_root():raise SystemExit('ERROR: root required')
    account=check_user(args.account)
    accounts,resellers,_=inventory()
    if account not in accounts:raise SystemExit('ERROR: account not found')
    db=connect()
    try:
        settings=get_settings(db)
        policy=decision(settings,get_configs(db),accounts,resellers,account)
    finally:db.close()
    print(json.dumps({'account':account,'owner':accounts[account]['owner'],'policy':policy,
                      'recipient_source':'WHM API listaccts email field','delivery':'send' if args.send else 'dry-run'},indent=2))
    if not args.send:return
    sender=policy.get('sender')
    if not sender:raise SystemExit('DENIED: sender policy disabled/unknown')
    owner=accounts[account]['owner']
    if policy.get('reason') in ('root/non-reseller owner: default identity','reseller disabled or unverified: default identity'):
        if settings.get('default_sender_verified')!='1' or sender!=settings.get('default_sender'):
            raise SystemExit('DENIED: fallback sender ownership unverified')
        fallback_token=settings.get('default_sender_token','')
        try:
            allowed=bool(fallback_token) and ('rsm-verification='+fallback_token) in lookup('_rsm.'+sender.rsplit('@',1)[1])
        except DNSError as e:
            raise SystemExit('DENIED: default sender ownership DNS unavailable') from e
        if not allowed:
            raise SystemExit('DENIED: fallback sender DNS ownership no longer valid')
    if owner in resellers:
        db=connect()
        try: c=get_configs(db).get(owner)
        finally: db.close()
        if c and c['enabled'] and c['verified'] and c['email'] == sender:
            domain=sender.rsplit('@',1)[1]
            challenge='rsm-verification='+c['token']
            try: current_txt=lookup('_rsm.'+domain)
            except DNSError as e: raise SystemExit('DENIED: sender domain TXT check failed') from e
            if challenge not in current_txt:raise SystemExit('DENIED: sender domain TXT verification no longer valid')
    recipient=check_email(accounts[account]['email'])
    message=compose(sender,recipient,account)
    # Sign before acquiring the rate-limit slot, so DNS/signing errors don't consume it.
    wire=sign_message(message.as_bytes(policy=SMTP),sender.rsplit('@',1)[1])
    db=connect()
    try: claim_id=claim_notice(db,account)
    finally: db.close()
    # No shell. Trusted WHM recipient and fixed content only; fail closed on uncertain timeouts.
    result=subprocess.run([SENDMAIL,'-oi','-f',sender,'-t'],input=wire,
                          capture_output=True,timeout=15,check=False)
    if result.returncode!=0:
        db=connect()
        try: release_notice(db,account,claim_id)
        finally: db.close()
        raise SystemExit('Mail submission failed (check local Exim log)')
    print('Exim accepted the message submission (NOT proof of inbox delivery).')

if __name__=='__main__':
    try:main()
    except (RSMError,DKIMError,subprocess.SubprocessError) as e:raise SystemExit('ERROR: '+str(e))
