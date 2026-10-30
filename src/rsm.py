#!/usr/bin/env python3
"""RSM administrative core. No external Python dependencies or global MTA rewrites."""
from __future__ import annotations
import json
import os
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from email.utils import parseaddr

APP_DIR = Path('/var/lib/whm-reseller-mail-manager')
DB_FILE = APP_DIR / 'state.sqlite3'
WHMAPI = '/usr/local/cpanel/bin/whmapi1'
RES_FILE = '/var/cpanel/resellers'
USER_RE = re.compile(r'^[a-z][a-z0-9_]{0,15}$')
DOMAIN_RE = re.compile(r'^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-z0-9-]{1,63}(?<!-))+$')
SENDER_RE = re.compile(r'^[A-Za-z0-9.!#$%&\'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+$')
DEFAULT_SENDER = ''

class RSMError(Exception):
    pass

def check_email(s):
    if not isinstance(s, str) or len(s)>254 or any(ord(c)<33 or ord(c)>126 for c in s) or not SENDER_RE.fullmatch(s):
        raise RSMError('Invalid ASCII email address')
    local, domain = s.rsplit('@',1)
    if len(local)>64 or not DOMAIN_RE.fullmatch(domain.lower()) or all(part.isdigit() for part in domain.split('.')):
        raise RSMError('Invalid email domain or local part')
    return local+'@'+domain.lower()

def check_user(u):
    if not isinstance(u,str) or not USER_RE.fullmatch(u):
        raise RSMError('Invalid reseller/account username')
    return u

def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')

def connect():
    APP_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    if APP_DIR.is_symlink():
        raise RSMError('State directory must not be a symlink')
    info=APP_DIR.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.geteuid():
        raise RSMError('State directory is not owned by the current privileged user')
    os.chmod(APP_DIR,0o700)
    if DB_FILE.is_symlink():
        raise RSMError('SQLite database must not be a symlink')
    if DB_FILE.exists():
        info=DB_FILE.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid():
            raise RSMError('SQLite database is not a trusted regular file')
    db=sqlite3.connect(DB_FILE,timeout=6)
    if DB_FILE.is_symlink():
        db.close()
        raise RSMError('SQLite database link changed while opening')
    os.chmod(DB_FILE,0o600)
    db.row_factory=sqlite3.Row
    db.execute('PRAGMA busy_timeout=6000')
    db.execute('PRAGMA foreign_keys=ON')
    db.executescript('''
    CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS reseller_config (
      reseller TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0,
      email TEXT NOT NULL DEFAULT '', verified INTEGER NOT NULL DEFAULT 0,
      token TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
      CHECK(enabled IN (0,1)), CHECK(verified IN (0,1))
    );
    CREATE TABLE IF NOT EXISTS audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT NOT NULL,
      action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS notice_cooldown (
      account TEXT PRIMARY KEY, claimed_at INTEGER NOT NULL, claim_id TEXT NOT NULL
    );
    ''')
    db.execute('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)',('default_sender',DEFAULT_SENDER))
    db.execute('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)',('enabled','0'))
    # Migrate existing installations conservatively: fallback identities must be explicitly verified.
    db.execute('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)',('default_sender_verified','0'))
    db.execute('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)',('default_sender_token',''))
    db.commit()
    return db

def audit(db,action,target,result):
    db.execute('INSERT INTO audit(ts,actor,action,target,result) VALUES (?,?,?,?,?)',
       (utcnow(),'root',action,str(target)[:100],str(result)[:250]))
    db.execute('DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 2000)')

def whm_accounts():
    try:
        p=subprocess.run([WHMAPI,'--output=json','listaccts'],capture_output=True,text=True,timeout=20,check=True)
        obj=json.loads(p.stdout)
        if int(obj.get('metadata',{}).get('result',0))!=1:
            raise RSMError('WHM API reported an error')
        accts=obj.get('data',{}).get('acct',[])
        if not isinstance(accts,list):
            raise RSMError('WHM API returned malformed accounts')
        result={}
        for a in accts:
            if not isinstance(a,dict):
                continue
            u,o=a.get('user'),a.get('owner')
            if isinstance(u,str) and USER_RE.fullmatch(u) and isinstance(o,str) and (o=='root' or USER_RE.fullmatch(o)):
                result[u]={'user':u,'owner':o,'domain':str(a.get('domain','')),
                           'email':str(a.get('email',''))}
        return result
    except (OSError,subprocess.SubprocessError,ValueError,KeyError,TypeError) as e:
        raise RSMError('WHM API listaccts unavailable: '+str(e)[:200])

def reseller_set():
    try:
        res=set()
        with open(RES_FILE,encoding='ascii') as f:
            for l in f:
                name=l.split(':',1)[0].strip()
                if USER_RE.fullmatch(name): res.add(name)
        return res
    except OSError as e:
        raise RSMError('Reseller roster unavailable: '+str(e))

def inventory():
    accounts=whm_accounts()
    resellers=reseller_set()
    tally={r:0 for r in resellers}
    for a in accounts.values():
        owner=a['owner']
        if owner in tally:tally[owner]+=1
    return accounts,resellers,tally

def get_settings(db):
    return {r['key']:r['value'] for r in db.execute('SELECT key,value FROM settings')}

def get_configs(db):
    return {r['reseller']:dict(r) for r in db.execute('SELECT * FROM reseller_config')}

def decision(settings,configs,accounts,resellers,account):
    """Only trusted WHM account ownership can select a reseller. No message guessing."""
    if settings.get('enabled')!='1':return {'sender':None,'reason':'global kill switch: preserve caller behavior'}
    if account not in accounts:return {'sender':None,'reason':'unknown account: preserve caller behavior'}
    owner=accounts[account]['owner']
    fallback=settings.get('default_sender','') if settings.get('default_sender_verified')=='1' else None
    if owner not in resellers:
        return {'sender':fallback,'reason':'root/non-reseller owner: default identity','owner':owner}
    config=configs.get(owner)
    if config and config['enabled'] and config['verified'] and config['email']:
        return {'sender':config['email'],'reason':'verified reseller policy','owner':owner}
    return {'sender':fallback,'reason':'reseller disabled or unverified: default identity','owner':owner}

NOTICE_COOLDOWN_SECONDS=600


def claim_notice(db,account):
    """Atomic per-account send throttle across concurrent root CLI processes."""
    account=check_user(account)
    now=int(time.time())
    claim_id=secrets.token_hex(16)
    db.execute('BEGIN IMMEDIATE')
    try:
        row=db.execute('SELECT claimed_at FROM notice_cooldown WHERE account=?',(account,)).fetchone()
        if row and now-int(row['claimed_at']) < NOTICE_COOLDOWN_SECONDS:
            raise RSMError('RSM notice rate limit: this account was notified recently')
        db.execute('INSERT INTO notice_cooldown(account,claimed_at,claim_id) VALUES(?,?,?) '
                   'ON CONFLICT(account) DO UPDATE SET claimed_at=excluded.claimed_at,claim_id=excluded.claim_id',
                   (account,now,claim_id))
        db.execute('DELETE FROM notice_cooldown WHERE claimed_at < ?',
                   (now-7*24*3600,))
        audit(db,'notice.claim',account,'accepted')
        db.commit()
    except BaseException:
        db.rollback()
        raise
    return claim_id


def release_notice(db,account,claim_id):
    """Release only this exact failed claim; never clear another worker's claim."""
    account=check_user(account)
    with db:
        db.execute('DELETE FROM notice_cooldown WHERE account=? AND claim_id=?',(account,claim_id))
        audit(db,'notice.reject',account,'local sendmail rejected submission')


def public_config(c):
    return {'reseller':c['reseller'],'enabled':bool(c['enabled']),'email':c['email'],
            'verified':bool(c['verified']),'updated_at':c['updated_at'],
            'challenge_name':('_rsm.'+c['email'].split('@')[1] if c['email'] else ''),
            'challenge_value':('rsm-verification='+c['token'] if c['token'] else '')}

def dashboard(db):
    accounts,resellers,tally=inventory()
    cfg=get_configs(db)
    rows=[]
    for r in sorted(resellers):
        c=cfg.get(r,{'reseller':r,'enabled':0,'email':'','verified':0,'token':'','updated_at':''})
        rows.append({**public_config(c),'accounts':tally[r]})
    settings=get_settings(db)
    return {'settings':settings,'resellers':rows,
            'default_challenge_name':('_rsm.'+settings['default_sender'].rsplit('@',1)[1] if '@' in settings['default_sender'] else ''),
            'default_challenge_value':('rsm-verification='+settings['default_sender_token'] if settings['default_sender_token'] else ''),
            'accounts_total':len(accounts),'orphan_configs':sorted(set(cfg)-resellers),
            'events':[dict(a) for a in db.execute('SELECT ts,action,target,result FROM audit ORDER BY id DESC LIMIT 30')],
            'integration':{'native_cpanel_notifications':'unsupported / no verified official sender override hook',
                           'plugin_notice_sender':'available via privileged CLI, not automatically deployed',
                           'exim_modified':False}}

def save_general(db, request):
    email=check_email(request.get('email',''))
    enabled='1' if request.get('enabled')=='1' else '0'
    previous=get_settings(db)
    changed=previous.get('default_sender')!=email or not previous.get('default_sender_token')
    token=secrets.token_hex(24) if changed else previous['default_sender_token']
    verified='0' if changed else previous.get('default_sender_verified','0')
    with db:
        for key,value in (('default_sender',email),('enabled',enabled),
                          ('default_sender_token',token),('default_sender_verified',verified)):
            db.execute('UPDATE settings SET value=? WHERE key=?',(value,key))
        audit(db,'general.update','global','enabled='+enabled+' domain='+email.rsplit('@',1)[1]+' verified='+verified)
    return {'message':'General settings saved. Verify the fallback sender ownership TXT before using it.'}


def verify_general(db,request):
    settings=get_settings(db)
    sender=check_email(settings.get('default_sender',''))
    token=settings.get('default_sender_token','')
    if not token:raise RSMError('Save the default sender before DNS verification')
    domain=sender.rsplit('@',1)[1]
    expected='rsm-verification='+token
    try: found=expected in dns_text('_rsm.'+domain)
    except Exception as exc: raise RSMError('Default sender DNS lookup failed: '+str(exc)[:120])
    with db:
        now=get_settings(db)
        if now['default_sender']!=sender or now['default_sender_token']!=token:
            raise RSMError('Default sender changed during verification')
        db.execute('UPDATE settings SET value=? WHERE key=?',('1' if found else '0','default_sender_verified'))
        audit(db,'general.verify','global','domain='+domain+' verified='+str(found))
    if not found:raise RSMError('TXT verification token not found at _rsm.'+domain)
    return {'message':'Default sender ownership TXT verified.'}

def save_reseller(db,request):
    r=check_user(request.get('reseller',''))
    _,resellers,_=inventory()
    if r not in resellers: raise RSMError('Reseller not in current WHM inventory')
    email=check_email(request.get('email',''))
    enabled=1 if request.get('enabled')=='1' else 0
    old=db.execute('SELECT * FROM reseller_config WHERE reseller=?',(r,)).fetchone()
    same=old is not None and old['email']==email
    token=old['token'] if same else secrets.token_hex(24)
    verified=int(old['verified']) if same else 0
    with db:
        db.execute('''INSERT INTO reseller_config(reseller,enabled,email,verified,token,updated_at)
                      VALUES(?,?,?,?,?,?) ON CONFLICT(reseller) DO UPDATE SET
                      enabled=excluded.enabled,email=excluded.email,verified=excluded.verified,
                      token=excluded.token,updated_at=excluded.updated_at''',
                   (r,enabled,email,verified,token,utcnow()))
        audit(db,'reseller.save',r,'enabled='+str(enabled)+' email='+email+' verified='+str(verified))
    return {'message':'Reseller saved; verify DNS challenge before custom sender is used'}

def rotate_challenge(db,request):
    """Explicitly revoke a leaked ownership challenge; never rotate DKIM keys."""
    if request.get('confirm')!='yes':
        raise RSMError('Explicit challenge rotation confirmation required')
    scope=request.get('scope','reseller')
    token=secrets.token_hex(24)
    if scope=='general':
        sender=get_settings(db).get('default_sender','')
        check_email(sender)
        with db:
            db.execute('UPDATE settings SET value=? WHERE key=?',(token,'default_sender_token'))
            db.execute('UPDATE settings SET value=? WHERE key=?',('0','default_sender_verified'))
            audit(db,'general.challenge.rotate','global','previous ownership verification revoked')
        return {'message':'Fallback sender challenge rotated and verification revoked; publish new TXT then verify.'}
    if scope!='reseller':
        raise RSMError('Invalid rotation scope')
    reseller=check_user(request.get('reseller',''))
    _,resellers,_=inventory()
    if reseller not in resellers:
        raise RSMError('Reseller not present in WHM inventory')
    c=db.execute('SELECT * FROM reseller_config WHERE reseller=?',(reseller,)).fetchone()
    if not c or not c['email']:
        raise RSMError('Save reseller sender before rotating its challenge')
    with db:
        changed=db.execute('UPDATE reseller_config SET token=?,verified=0,updated_at=? WHERE reseller=?',
                           (token,utcnow(),reseller))
        if changed.rowcount!=1:
            raise RSMError('Reseller challenge changed concurrently')
        audit(db,'reseller.challenge.rotate',reseller,'previous ownership verification revoked')
    return {'message':'Reseller ownership challenge rotated and policy verification revoked; publish and verify the replacement TXT.'}


def dns_text(name,rrtype='TXT'):
    from dns_inspector import lookup
    return lookup(name,rrtype)

def verify(db,request):
    r=check_user(request.get('reseller',''))
    _,resellers,_=inventory()
    if r not in resellers: raise RSMError('Reseller no longer exists')
    c=db.execute('SELECT * FROM reseller_config WHERE reseller=?',(r,)).fetchone()
    if not c or not c['email']:raise RSMError('Save a sender address first')
    domain=c['email'].rsplit('@',1)[1]
    name='_rsm.'+domain
    expected='rsm-verification='+c['token']
    try: values=dns_text(name)
    except Exception as e: raise RSMError('DNS verification could not complete: '+str(e)[:160])
    found=expected in values
    with db:
        updated=db.execute('UPDATE reseller_config SET verified=?,updated_at=? WHERE reseller=? AND email=? AND token=?',(int(found),utcnow(),r,c['email'],c['token']))
        if updated.rowcount!=1: raise RSMError('Configuration changed during verification; retry')
        audit(db,'reseller.verify',r,'verified='+str(found))
    if not found: raise RSMError('TXT verification token not found at '+name)
    return {'message':'Domain challenge verified. Review SPF and DKIM before sending.'}

def inspect(request):
    from dns_inspector import diagnostics
    email=check_email(request.get('email',''))
    ip=request.get('ip','').strip()
    selector=request.get('selector','')
    if not isinstance(selector,str) or (selector and not re.fullmatch(r'[A-Za-z0-9_-]{1,63}',selector)):
        raise RSMError('Invalid DKIM selector')
    selector=selector.lower()
    if ip:
        import ipaddress
        try:ipaddress.ip_address(ip)
        except ValueError:raise RSMError('Invalid outbound IP')
    try: return diagnostics(email.rsplit('@',1)[1],ip,selector)
    except Exception as e: raise RSMError('DNS diagnostics failed: '+str(e)[:160])

def audit_reseller(db,request):
    """Read-only audit tied to a saved reseller sender and fresh ownership TXT."""
    from auth_audit import audit_domain
    from dkim_signing import public_record, DKIMError, SELECTOR
    reseller=check_user(request.get('reseller',''))
    _,resellers,_=inventory()
    if reseller not in resellers:
        raise RSMError('Reseller not present in WHM inventory')
    c=db.execute('SELECT * FROM reseller_config WHERE reseller=?',(reseller,)).fetchone()
    if not c or not c['email']:
        raise RSMError('Save the reseller sender before auditing its DNS')
    domain=c['email'].rsplit('@',1)[1]
    ip=str(request.get('ip','')).strip()
    try:
        report=audit_domain(domain,ip,SELECTOR,'rsm-verification='+c['token'])
        report['reseller']=reseller
        report['ownership']['stored_verified']=bool(c['verified'])
        if not c['verified']:
            report['ownership']['status']='needs_action'
            report['ownership']['message']='TXT exists but you must click Verify public DNS to activate the saved ownership policy.'
        report['dkim']['rsm_key_provisioned']=False
        public=public_record(domain)
        if public:
            report['dkim']['rsm_key_provisioned']=True
            values=report['dkim']['records']
            expected_key=public['value'].split('p=',1)[1]
            key_present=any(re.search(r'(?:^|;)\s*p\s*=\s*([^;\s]+)',v) and
                            re.search(r'(?:^|;)\s*p\s*=\s*([^;\s]+)',v).group(1)==expected_key
                            for v in values)
            if not key_present:
                report['dkim']['status']='needs_action'
                report['dkim']['message']='RSM signer key exists. Publish the corresponding TXT public key (do not replace other selectors).'
                report['dkim']['proposal']={'action':'create_or_replace_rsm_selector','name':public['name'],
                    'type':'TXT','value':public['value'],
                    'note':'This dedicated RSM selector is separate from existing DKIM selectors.'}
            else:
                report['dkim']['signing']='rsm_signer_configured_live_signature_unverified'
                report['dkim']['message']='RSM private key and its public DNS match. A real signed message must still be inspected.'
        report['summary']='dns_records_verified_live_signing_unverified' if all(
            report[k]['status']=='verified_dns' for k in ('ownership','spf','dkim','dmarc')) else 'attention_or_further_evidence_required'
        return report
    except Exception as e:
        raise RSMError('Reseller authentication audit failed: '+str(e)[:160])


def provision_reseller_dkim(db,request):
    """Explicit owner-approved key creation; never touches remote DNS or Exim."""
    from dkim_signing import provision, public_record, DKIMError
    reseller=check_user(request.get('reseller',''))
    if request.get('confirm')!='yes':
        raise RSMError('Confirm DKIM private-key provisioning first')
    _,resellers,_=inventory()
    if reseller not in resellers:raise RSMError('Reseller not present in WHM inventory')
    c=db.execute('SELECT * FROM reseller_config WHERE reseller=?',(reseller,)).fetchone()
    if not c or not c['verified'] or not c['email']:
        raise RSMError('Verify reseller sender domain ownership first')
    domain=c['email'].rsplit('@',1)[1]
    try:
        proof_ok='rsm-verification='+c['token'] in dns_text('_rsm.'+domain)
    except Exception as e:
        raise RSMError('DNS ownership check failed: '+str(e)[:120])
    if not proof_ok:
        raise RSMError('Domain ownership TXT was removed or changed')
    try:
        created=provision(domain)
        public=public_record(domain)
    except (OSError,DKIMError,subprocess.SubprocessError) as e:
        raise RSMError('RSM DKIM key operation failed: '+str(e)[:160])
    with db:
        audit(db,'dkim.provision',reseller,'created='+str(created)+' domain='+domain)
    return {'message':'RSM DKIM key ready. Publish the proposed TXT record, then run the reseller DNS audit.',
            'dns_name':public['name'],'dns_value':public['value']}


def preview(db,request):
    account=check_user(request.get('account',''))
    accounts,resellers,_=inventory()
    return decision(get_settings(db),get_configs(db),accounts,resellers,account)

def dispatch(request):
    a=request.get('action','dashboard')
    db=connect()
    try:
        if a=='dashboard':return dashboard(db)
        if a=='save_general':return save_general(db,request)
        if a=='verify_general':return verify_general(db,request)
        if a=='rotate_challenge':return rotate_challenge(db,request)
        if a=='save_reseller':return save_reseller(db,request)
        if a=='verify':return verify(db,request)
        if a=='inspect':return inspect(request)
        if a=='audit_reseller':return audit_reseller(db,request)
        if a=='provision_reseller_dkim':return provision_reseller_dkim(db,request)
        if a=='preview':return preview(db,request)
        raise RSMError('Unknown operation')
    finally:db.close()

def main():
    try:
        if os.name!='posix' or os.geteuid()!=0:
            raise RSMError('Root privilege required')
        request=json.loads(sys.stdin.read(16385))
        if not isinstance(request,dict):raise RSMError('Invalid request')
        print(json.dumps({'ok':True,'data':dispatch(request)},ensure_ascii=False))
    except (RSMError,ValueError,TypeError,sqlite3.Error) as e:
        print(json.dumps({'ok':False,'error':str(e)[:240]},ensure_ascii=False))
        sys.exit(1)

if __name__=='__main__':main()
