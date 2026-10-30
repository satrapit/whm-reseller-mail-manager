#!/usr/bin/env python3
"""Read-only WHM/RSM release acceptance diagnostics; prints no saved TXT secrets.

Run as root on the installation host. No email, DNS record, database mutation,
WHM account changes, service restart, or rollback is performed.
The optional --dns checks published TXT via read-only DNS queries.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import sys

SRC = Path("/opt/src/whm-reseller-mail-manager")
INSTALLED = Path("/opt/whm-reseller-mail-manager/app")
STATE = Path("/var/lib/whm-reseller-mail-manager")
CGI = Path("/usr/local/cpanel/whostmgr/docroot/cgi/rsm/index.cgi")
TEMPLATE = Path("/usr/local/cpanel/whostmgr/docroot/templates/rsm/index.tmpl")
WHM_VERSION = Path("/usr/local/cpanel/version")
EXIM = Path("/etc/exim.conf")
SIGNING = "rsm2026"

def result(checks, name, ok, detail):
    checks.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})

def secure_file(path, mode, root_uid=0):
    try:
        info = path.lstat()
        return (stat.S_ISREG(info.st_mode) and info.st_uid == root_uid
                and (info.st_mode & 0o777) == mode)
    except OSError:
        return False

def secure_directory(path, mode, root_uid=0):
    try:
        info = path.lstat()
        return (stat.S_ISDIR(info.st_mode) and info.st_uid == root_uid
                and (info.st_mode & 0o777) == mode)
    except OSError:
        return False

def same_bytes(a, b):
    try:
        return a.is_file() and b.is_file() and a.read_bytes() == b.read_bytes()
    except OSError:
        return False

def database_report(path):
    """Read-only SQLite connection; never call the mutating rsm.connect()."""
    address = path.as_uri() + "?mode=ro"
    with sqlite3.connect(address, uri=True, timeout=4) as db:
        db.execute("PRAGMA query_only=ON")
        healthy = db.execute("PRAGMA quick_check").fetchone()[0] == "ok"
        settings = dict(db.execute(
            "SELECT key,value FROM settings WHERE key IN ('enabled','default_sender_verified')"))
        rows = list(db.execute(
            "SELECT reseller,enabled,verified,email,token FROM reseller_config"))
    # Include NO email, TXT values or tokens in the returned summary.
    policy = [{"reseller":r, "enabled":bool(e), "verified":bool(v),
               "sender_configured":bool(address), "challenge_present":bool(token)}
              for r,e,v,address,token in rows]
    return healthy, settings, policy

def dns_proofs(path):
    """Check saved verified challenges against public DNS; never print values."""
    root = INSTALLED / "src"
    sys.path.insert(0,str(root))
    from dns_inspector import lookup
    with sqlite3.connect(path.as_uri()+"?mode=ro",uri=True,timeout=4) as db:
        db.execute("PRAGMA query_only=ON")
        accounts = list(db.execute(
            "SELECT reseller,email,verified,token FROM reseller_config WHERE enabled=1"))
        settings = dict(db.execute("SELECT key,value FROM settings"))
    proofs = []
    for reseller,email,verified,token in accounts:
        if not (verified and token and email and "@" in email):
            continue
        try:
            domain=email.rsplit("@",1)[1]
            found = ("rsm-verification="+token) in lookup("_rsm."+domain,"TXT")
        except Exception:
            found = False
        proofs.append((reseller,found))
    if settings.get("default_sender_verified")=="1":
        try:
            token=settings["default_sender_token"]
            domain=settings["default_sender"].rsplit("@",1)[1]
            matched=("rsm-verification="+token) in lookup("_rsm."+domain,"TXT")
        except Exception:
            matched=False
        proofs.append(("global-default",matched))
    return proofs

def run(root, check_dns, exim_expected):
    checks=[]
    result(checks,"privileged_execution",os.geteuid()==0,"Must run as root")
    version_path = root / "VERSION"
    try:
        version=version_path.read_text(encoding="utf-8").strip()
    except OSError:
        version="unknown"
    result(checks,"source_version",(version == "1.0.0" or version.startswith("1.0.0-rc")),
           "Release-candidate source checkout: "+version)
    try:
        whm=WHM_VERSION.read_text(encoding="ascii").strip()
    except OSError:
        whm="unknown"
    result(checks,"whm_compatible",bool(re.match(r"11\.(\d+)\.",whm))
           and int(whm.split(".")[1])>=132,"WHM "+whm)

    for name in ("rsm.py","notify.py","auth_audit.py","dkim_signing.py","dns_inspector.py"):
        result(checks,"installed_"+name,
               same_bytes(root/"src"/name,INSTALLED/"src"/name),"Matches checked-out source")
    result(checks,"installed_cgi",same_bytes(root/"cgi/index.cgi",CGI),"Matches checked-out source")
    result(checks,"installed_template",same_bytes(root/"templates/rsm/index.tmpl",TEMPLATE),
           "Matches checked-out source")
    perl="/usr/local/cpanel/3rdparty/bin/perl"
    try:
        proc=subprocess.run([perl,"-c",str(CGI)],capture_output=True,timeout=12,check=False)
        valid=proc.returncode==0
    except (OSError,subprocess.SubprocessError):
        valid=False
    result(checks,"cgi_perl_syntax",valid,"WHM Perl interpreter syntax check")

    result(checks,"state_directory_mode",secure_directory(STATE,0o700),"root-owned 0700")
    result(checks,"csrf_key_mode",secure_file(STATE/"csrf.key",0o600),"root-owned 0600")
    result(checks,"sqlite_file_mode",secure_file(STATE/"state.sqlite3",0o600),"root-owned 0600")
    key_dir=STATE/"dkim"
    if key_dir.exists():
        result(checks,"dkim_directory_mode",secure_directory(key_dir,0o700),"root-owned 0700")
        for key in sorted(key_dir.glob("*.pem")):
            result(checks,"dkim_key_mode",secure_file(key,0o600),"Private DKIM key root-owned 0600 (name suppressed)")
    else:
        result(checks,"dkim_directory_mode",True,"No DKIM keys provisioned")

    try:
        healthy,settings,policies=database_report(STATE/"state.sqlite3")
        result(checks,"sqlite_readonly_integrity",healthy,"Read-only SQLite PRAGMA quick_check")
        result(checks,"fallback_policy_flag",settings.get("default_sender_verified") in ("0","1"),
               "Global verification marker is present")
        counts={"resellers_configured":len(policies),
                "reseller_verified_enabled":sum(p["enabled"] and p["verified"] for p in policies),
                "reseller_enabled_unverified":sum(p["enabled"] and not p["verified"] for p in policies),
                "global_enabled":settings.get("enabled")=="1",
                "fallback_verified":settings.get("default_sender_verified")=="1"}
    except (OSError,sqlite3.Error,ValueError) as exc:
        result(checks,"sqlite_readonly_integrity",False,"Cannot inspect database safely ("+type(exc).__name__+")")
        counts={}
    if exim_expected:
        try:
            expected=exim_expected.read_text(encoding="ascii").split()
            ok=(len(expected)==2 and expected[1]==str(EXIM)
                and hashlib.sha256(EXIM.read_bytes()).hexdigest()==expected[0])
        except (OSError,UnicodeError):
            ok=False
        result(checks,"exim_config_unchanged",ok,"Compare only /etc/exim.conf to saved digest")
    if check_dns:
        try:
            proofs=dns_proofs(STATE/"state.sqlite3")
            for index,(reseller,matched) in enumerate(proofs, start=1):
                result(checks,"dns_ownership_"+str(index),matched,
                       "Published TXT matches stored proof" if matched else "Verified flag and live DNS disagree")
        except Exception as exc:
            result(checks,"dns_readonly_audit",False,"DNS audit unavailable ("+type(exc).__name__+")")
    return {"version":version,"whm_version":whm,"policy_counts":counts,"checks":checks,
            "result":"PASS" if all(c["result"]=="PASS" for c in checks) else "FAIL",
            "limitations":"No real browser session/ACL/CSRF workflow, rollback or mail delivery tested"}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,default=SRC)
    p.add_argument("--check-dns",action="store_true",help="Read-only public TXT lookup of verified senders")
    p.add_argument("--exim-checksum",type=Path,help="Previously saved sha256sum file for /etc/exim.conf")
    args=p.parse_args()
    summary=run(args.source,args.check_dns,args.exim_checksum)
    print(json.dumps(summary,indent=2,sort_keys=True))
    return 0 if summary["result"]=="PASS" else 1

if __name__=="__main__":
    sys.exit(main())
