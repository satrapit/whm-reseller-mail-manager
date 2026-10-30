#!/usr/bin/env python3
"""Local public-release secret screening. Read-only; no network or third-party dependencies.

Usage: python3 scripts/audit_public_release.py [--history]
This is a risk-reduction check, NOT a guarantee that repository history is safe.
"""
import argparse
import ipaddress
import re
import subprocess
import sys

MAX_BYTES = 2_000_000
# Split literal prefixes so the scanner does not flag its own pattern definitions.
RULES = {
    "private-key": re.compile(b"-----BEGIN " + b"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(b"(?:gh" + b"p_|gho_|ghu_|ghs_|ghr_|github_pat_)[A-Za-z0-9_]{16,}"),
    "aws-key": re.compile(b"AK" + b"IA[0-9A-Z]{16}"),
    "openai-key": re.compile(b"sk" + b"-[a-zA-Z0-9_-]{20,}"),
    "whm-session": re.compile(b"cp" + b"sess[0-9]{8,20}"),
    "rsm-challenge": re.compile(b"rsm-verification=" + b"[a-fA-F0-9]{40,}"),
}
# Extra checks for a NEW standalone public history. Strict mode deliberately
# fails on the old internal repository's real contributor metadata.
PUBLIC_EMAIL = re.compile(rb"(?i)(?:[a-z0-9._%+-]+)@(?:[a-z0-9.-]+)\.[a-z]{2,}")
PUBLIC_IPV4 = re.compile(rb"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
SAMPLE_EMAIL_SUFFIXES = (
    ".example.com", ".example.net", ".example.org",
    "@example.com", "@example.net", "@example.org",
    ".test", ".invalid", "@users.noreply.github.com",
)
def is_sample_email(email):
    return email.lower() == "git@github.com" or email.lower().endswith(SAMPLE_EMAIL_SUFFIXES)

def public_findings(label, content):
    if b"\x00" in content[:8192]:
        return []
    result=[]
    if any(not is_sample_email(m.group().decode("ascii","replace"))
           for m in PUBLIC_EMAIL.finditer(content)):
        result.append(label + ": non-example email address")
    # Public production IPs are prohibited in sample code and documentation.
    for m in PUBLIC_IPV4.finditer(content):
        try:
            addr=ipaddress.ip_address(m.group().decode("ascii"))
            if addr.is_global:
                result.append(label + ": public IPv4 in samples")
                break
        except ValueError:
            continue
    return result

def author_findings():
    problems=[]
    emails=run(["git","log","--all","--format=%ae%n%ce"]).decode("utf-8","replace").splitlines()
    if not emails:
        problems.append("git history: missing author metadata")
    if any(not is_sample_email(e) for e in emails):
        problems.append("git history: non-example author/committer identity")
    return problems

def run(args):
    return subprocess.check_output(args, stderr=subprocess.DEVNULL)

# An immutable PRIVATE-history blob from the first CGI sandbox test contains
# one fabricated WHM session identifier. It was assembled from fragments in
# the current source. Ignore ONLY this exact dummy sequence in that exact old
# blob; keep scanning the remainder of the blob for other real secrets.
# This exemption is NEVER applied to the new single-commit public export.
PRIVATE_TEST_FIXTURE_BLOB = "blob 2b2af0499156"
PRIVATE_TEST_DUMMY_SESSION = b"cp" + b"sess" + b"1234567890"

def scan(label, content):
    if b"\x00" in content[:8192]:
        return []
    if label == PRIVATE_TEST_FIXTURE_BLOB:
        content = content.replace(PRIVATE_TEST_DUMMY_SESSION,
                                  b"synthetic-session-redacted")
    return [label + ": " + name for name, rx in RULES.items() if rx.search(content)]

def tracked():
    files = run(["git", "ls-files", "-z"]).split(b"\x00")
    for name in filter(None, files):
        try:
            with open(name, "rb") as stream:
                content = stream.read(MAX_BYTES + 1)
            if len(content) <= MAX_BYTES:
                yield name.decode("utf-8", "replace"), content
        except OSError:
            raise RuntimeError("Unreadable tracked file (release gate)")

def history():
    rows = run(["git", "rev-list", "--objects", "--all"]).splitlines()
    seen = set()
    for item in rows:
        sha = item.split(b" ", 1)[0].decode("ascii")
        if sha in seen:
            continue
        seen.add(sha)
        if run(["git", "cat-file", "-t", sha]).strip() != b"blob":
            continue
        size = int(run(["git", "cat-file", "-s", sha]))
        if size > MAX_BYTES:
            continue
        content = run(["git", "cat-file", "blob", sha])
        yield "blob " + sha[:12], content

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--history",action="store_true",help="Scan all reachable git blobs, not just the worktree")
    parser.add_argument("--public-history",action="store_true",help="STRICT: require neutral author metadata and sample-only emails/IPs for clean public snapshot")
    args=parser.parse_args()
    try:
        problems=[]
        for label,content in tracked():
            problems.extend(scan(label,content))
            if args.public_history:
                problems.extend(public_findings(label,content))
        if args.history or args.public_history:
            for label,content in history():
                problems.extend(scan(label,content))
                if args.public_history:
                    problems.extend(public_findings(label,content))
        if args.public_history:
            problems.extend(author_findings())
    except (OSError,RuntimeError,subprocess.CalledProcessError) as exc:
        print("SECURITY SCAN ERROR: "+str(exc)[:180], file=sys.stderr)
        return 2
    if problems:
        for problem in sorted(set(problems)):
            print("POTENTIAL SECRET: " + problem)
        print("RELEASE BLOCKED. Verify findings and rotate exposed credentials; do not just delete the current file.")
        return 1
    if args.public_history:
        print("Public-snapshot sample-only email/IP and neutral author checks passed.")
    print("No matching high-risk token signatures found in "
          + ("working tree or reachable git history." if args.history else "tracked working tree.")
          + " Manual review is still required.")
    return 0

if __name__=="__main__":
    sys.exit(main())
