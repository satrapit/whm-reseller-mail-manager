# Release checklist

Maintainer: arsamnet.com

- [ ] Confirm all tests pass on Python 3.9, 3.11, 3.13; `bash -n scripts/*.sh`.
- [ ] Confirm production-target Perl syntax: `/usr/local/cpanel/3rdparty/bin/perl -c cgi/index.cgi`.
- [ ] Verify no secrets, DKIM private keys, owner challenge values, account contact lists or credentials appear in Git history, examples or release artifacts.
- [ ] Verify `LICENSE` MIT and copyright `arsamnet.com`; review third-party dependency licenses.
- [ ] Test SPF no-record, multiple-record, include/redirect, IP mismatch and proposals without overwrites.
- [ ] Test DKIM no-key, unpublished public key, correct key, corrupt private key, key permission failure and live `dkim=pass` mailbox header.
- [ ] Test DMARC no-record, multiple policies, `p=none`, stronger policy preserved and alignment from received email.
- [ ] Check root-only WHM ACL/CSRF; non-root reseller cannot provision private keys.
- [ ] Confirm no Exim/Dovecot, DNS, customer email or native cPanel notification interception.
- [ ] Backup state and Exim checksum; dry-run upgrade, then deploy to a controlled host; rollback code if necessary.
- [ ] Keep the historical source repository PRIVATE. Export a separate clean-history distribution using `scripts/export_public_snapshot.sh`; review it before publishing a NEW repository.

## Mandatory v1 stable gates

- [x] Install `1.0.0-rc2` on WHM 11.138+ using an approved backup and dry-run; 22/22 read-only checks passed. Desktop/mobile screenshot acceptance remains separate.
- [ ] Verify root-only access, valid WHM `cpsess`, CSRF invalid token and parameter pollution denial.
- [ ] Confirm unchanged reseller identity and intentionally blocked **unverified default** identity; publish default ownership TXT and verify.
- [ ] Test explicit challenge rotation on a test domain and reverify; ensure existing DKIM private key stays intact.
- [ ] Verify per-account 10-minute sending guard and approved recipient routing; compare Exim checksum before/after.
- [ ] Run SPF/DKIM/DMARC external Gmail acceptance test on approved address; test Inbox/Spam placement separately from authentication.
- [ ] Test a fresh install AND existing upgrade, previous-release rollback and uninstall (including retained keys and DB).
- [ ] `python3 scripts/audit_public_release.py --history` plus human review of all reachable git objects, releases, artifacts, screenshots and commit metadata.
- [ ] Manually validate that a screenshot-posted DNS challenge has been rotated before sharing screenshots publicly.
- [ ] Produce signed release tag/archive, changelog, license and attribution, verify version consistency.
- [ ] Obtain maintainer approval before publishing `v1.0.0`; keep this historical repository PRIVATE and change visibility only on a separately reviewed clean-history distribution repository.

- [ ] Read-only on-server evidence: `python3 scripts/verify_live_readonly.py --check-dns --exim-checksum <trusted-file>` returns PASS. Report sanitized counts only.
- [ ] Confirm CGI refuses insecure/symlinked/missing CSRF secret without exposing its contents.

- [ ] Validate overview metrics and action counts on a real WHM account roster; only claim *stored ownership/policy* readiness, never live DKIM/SPF delivery readiness.
- [ ] Check per-reseller next step for empty sender, unverified sender, verified paused sender, and verified enabled sender; check global fallback separately.
- [ ] Confirm tooltip/title and persistent helper guidance for every visible input and checkbox, keyboard focus and mobile layout.
- [ ] Capture `utilities_container.js` actual script URL without a live `cpsess`; do not claim the upstream WHM `unload` notice is fixed by RSM.

- [ ] Pilot screenshot acceptance: inspect revised SMTP IP audit button beneath the help text and the fallback sender legacy-token explanation in a fresh root WHM session.
- [ ] Require explicit owner decision on exposing committer email metadata in public Git history; never upload pilot screenshot files containing `cpsess`.

## Privacy and standalone public snapshot

- [ ] All example accounts/senders/IPs are synthetic, reserved test values; no live infrastructure identifiers appear in public source.
- [ ] `bash scripts/export_public_snapshot.sh /root/rsm-public-clean` produces exactly one new root commit with a neutral test author and no configured Git remote.
- [ ] `python3 scripts/audit_public_release.py --history --public-history` succeeds **inside** the clean exported repository. The private engineering history must fail this strict metadata gate rather than being exposed.
- [ ] Approve a separate GitHub repository before publicizing; do not force push or change visibility of the historical repository.
- [ ] No WHM screenshots, session URLs, customer mail headers, DKIM state, or author contact details are copied into release assets.

## Disposable lifecycle simulation (CI gate)

- [ ] Confirm the GitHub Actions **Isolated WHM lifecycle simulation** job passes: fresh install, second release upgrade, CGI/template/AppConfig rollback, injected failed-upgrade recovery, root-only CSRF symlink rejection, uninstall preserving SQLite/CSRF and reinstall retaining data.
- [ ] This Docker test uses fake WHM/AppConfig and a disabled network. It is NOT equivalent to validating real WHM 11.138 authorization, native menu rendering, SMTP delivery or a staging server with an actual cPanel license.
- [ ] Keep the historical engineering repository private. The public single-commit snapshot must be regenerated after the final code changes and reviewed manually before any release or publicity.

## Non-root access control: direct CGI gate

- [ ] Confirm an actual non-root reseller WHM session cannot request `/cgi/rsm/index.cgi` and view any privileged data. The RSM plugin not appearing in the reseller menu or ACL editor is **expected** because `plugin/rsm.conf` declares `user=root` and `acls=all`; menu absence alone is NOT a direct-route authorization test.
- [x] Add a **sandboxed CGI execution regression** that feeds synthetic `REMOTE_USER` and `Whostmgr::ACLS::checkacl` values: reseller with permissive ACL must return 403 for GET/POST/PUT; root without ACL must return 403; missing user and query spoofing must not bypass the gate. This is not a real WHM browser test.

## Prepared 1.0.0 source — decision record

Release acceptance evidence and incomplete live gates are itemized in [RELEASE_ACCEPTANCE.md](RELEASE_ACCEPTANCE.md). Real receiver evidence establishes DKIM-valid remote delivery, **not SPF/DMARC pass**. A separate licensed WHM staging server is unavailable; destructive rollback/uninstall was tested only inside an isolated Docker mock. Do not check off the real WHM staging or SPF/DMARC acceptance requirements unless those tests have occurred. Explicit maintainer signoff of documented exceptions is required before the signed public v1.0.0 tag and distribution repo are created. The historical engineering repository must remain PRIVATE.
