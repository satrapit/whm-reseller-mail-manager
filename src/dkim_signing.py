"""Optional, per-sender-domain DKIM for *RSM-authored* messages only.

Uses system OpenSSL and RFC 6376 relaxed/relaxed. This module is NOT an
Exim-wide signing configuration, nor a generic signer for arbitrary mail.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import subprocess
from pathlib import Path

from dns_inspector import DNSError, lookup, public_dns_domain

ROOT = Path("/var/lib/whm-reseller-mail-manager/dkim")
SELECTOR = "rsm2026"
OPENSSL = "/usr/bin/openssl"
SIGNED_HEADERS = ("from", "to", "subject", "date", "message-id")


class DKIMError(Exception):
    pass


def _path(domain):
    if not public_dns_domain(domain):
        raise DKIMError("Invalid DKIM domain")
    return ROOT / (domain + ".pem")


def _safe_key(domain):
    path = _path(domain)
    try:
        parent = path.parent.lstat()
        item = path.lstat()
    except FileNotFoundError:
        return None
    if (not stat.S_ISDIR(parent.st_mode) or (parent.st_mode & 0o077)
            or parent.st_uid != os.geteuid()):
        raise DKIMError("Insecure DKIM key directory permissions or ownership")
    if (not stat.S_ISREG(item.st_mode) or item.st_mode & 0o077
            or item.st_uid != os.geteuid()):
        raise DKIMError("Insecure DKIM private key permissions, ownership or symlink")
    return path


def provision(domain):
    """Explicit root-only creation. Existing keys are never replaced."""
    if os.geteuid() != 0:
        raise DKIMError("Root required to provision DKIM")
    dest = _path(domain)
    if ROOT.is_symlink():
        raise DKIMError("DKIM directory cannot be a symlink")
    ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    if ROOT.is_symlink():
        raise DKIMError("DKIM directory cannot be a symlink")
    os.chmod(ROOT, 0o700)
    if dest.exists() or dest.is_symlink():
        if _safe_key(domain) is None:
            raise DKIMError("Existing DKIM path is invalid")
        return False
    # Reserve a non-predictable temp path, with 0600 permissions.
    import secrets
    temporary = ROOT / ("." + secrets.token_hex(18) + ".tmp")
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    try:
        command = [OPENSSL, "genpkey", "-algorithm", "RSA",
                   "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(temporary)]
        p = subprocess.run(command, capture_output=True, timeout=25, check=False)
        if p.returncode != 0:
            raise DKIMError("OpenSSL failed to create DKIM key")
        os.chmod(temporary, 0o600)
        # Atomic create without replacement, including under concurrent root requests.
        try:
            os.link(temporary, dest, follow_symlinks=False)
        except FileExistsError as exc:
            raise DKIMError("DKIM key appeared concurrently; refusing replacement") from exc
        _safe_key(domain)
        return True
    finally:
        if temporary.exists():
            temporary.unlink()


def public_record(domain):
    path = _safe_key(domain)
    if path is None:
        return None
    p = subprocess.run([OPENSSL, "pkey", "-in", str(path), "-pubout", "-outform", "DER"],
                       capture_output=True, timeout=8, check=False)
    if p.returncode or len(p.stdout) < 100:
        raise DKIMError("Cannot extract DKIM public key")
    key = base64.b64encode(p.stdout).decode("ascii")
    return {"name": SELECTOR + "._domainkey." + domain,
            "value": "v=DKIM1; k=rsa; p=" + key}


def dns_matches(domain):
    record = public_record(domain)
    if not record:
        return False
    try:
        records = lookup(record["name"], "TXT")
    except DNSError as exc:
        raise DKIMError("DKIM public DNS query failed") from exc
    expected = record["value"].split("p=", 1)[1]
    # A selector with multiple published key RRs is ambiguous and must fail closed.
    keys = [entry for entry in records
            if entry.lower().startswith("v=dkim1") or re.search(r"(?:^|;)\s*p\s*=", entry, re.I)]
    if len(keys) != 1:
        return False
    tags = dict((k.lower(), v.strip()) for k, v in
                re.findall(r"(?:^|;)\s*([A-Za-z]+)\s*=\s*([^;]*)", keys[0]))
    return (tags.get("v", "DKIM1").upper() == "DKIM1"
            and tags.get("k", "rsa").lower() == "rsa"
            and tags.get("p") == expected)


def _canon_header(name, value):
    name = name.strip().lower()
    value = re.sub(rb"[ \t]+", b" ", re.sub(rb"\r\n[ \t]+", b" ", value))
    return name + b":" + value.strip(b" \t") + b"\r\n"


def _canon_body(body):
    lines = body.split(b"\r\n")
    lines = [re.sub(rb"[ \t]+", b" ", x.rstrip(b" \t")) for x in lines]
    while lines and not lines[-1]:
        lines.pop()
    return b"\r\n".join(lines) + b"\r\n"


def sign_message(raw, domain):
    """Sign an RFC5322 CRLF message with a pre-provisioned, published key."""
    path = _safe_key(domain)
    if path is None:
        return raw  # no opt-in DKIM key provisioned; existing SPF behavior unchanged
    if not dns_matches(domain):
        raise DKIMError("RSM DKIM key exists but public DNS is missing/mismatched; refusing unsigned send")
    if not isinstance(raw, bytes) or b"\r\n\r\n" not in raw:
        raise DKIMError("Expected SMTP CRLF message")
    head, body = raw.split(b"\r\n\r\n", 1)
    # Only RSM's controlled EmailMessage output is signed; refuse malformed headers.
    unfolded = re.sub(rb"\r\n(?=[ \t])", b" ", head)
    values = {}
    for line in unfolded.split(b"\r\n"):
        if b":" not in line or line[:1] in (b" ", b"\t"):
            raise DKIMError("Malformed email header")
        name, value = line.split(b":", 1)
        try:
            key = name.strip().lower().decode('ascii')
        except UnicodeDecodeError as exc:
            raise DKIMError('Invalid non-ASCII email header name') from exc
        if key in SIGNED_HEADERS:
            if key in values:
                raise DKIMError("Duplicate signed header")
            values[key] = value
    if set(SIGNED_HEADERS) - set(values):
        raise DKIMError("Required DKIM signed header missing")
    body_hash = base64.b64encode(hashlib.sha256(_canon_body(body)).digest()).decode("ascii")
    tags = (f"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={SELECTOR}; "
            f"h={':'.join(SIGNED_HEADERS)}; bh={body_hash}; b=")
    signature_header = b"DKIM-Signature: " + tags.encode("ascii")
    data = b"".join(_canon_header(key.encode("ascii"), values[key]) for key in SIGNED_HEADERS)
    # RFC 6376 §3.7: each h= header ends with CRLF, but the
    # DKIM-Signature header itself MUST be canonicalized WITHOUT its final CRLF.
    # Adding CRLF here makes an otherwise correct RSA signature fail remotely.
    data += _canon_header(b"DKIM-Signature", signature_header.split(b":", 1)[1])[:-2]
    p = subprocess.run([OPENSSL, "dgst", "-sha256", "-sign", str(path)],
                       input=data, capture_output=True, timeout=8, check=False)
    if p.returncode:
        raise DKIMError("OpenSSL DKIM signing failed")
    signature = base64.b64encode(p.stdout)
    # 2048-bit RSA signature keeps this single header comfortably below 998 octets.
    return signature_header + signature + b"\r\n" + raw
