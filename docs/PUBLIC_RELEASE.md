# Public release process — 1.0.0 (do not skip gates)

Project author/copyright holder: [arsamnet.com](https://arsamnet.com) · MIT License.

## Release policy

The historical engineering repository must remain **PRIVATE**, even after its source samples are sanitized. Release public distributions only from a separate, clean single-commit snapshot repository, as described in [PUBLISH_CLEAN_SNAPSHOT.md](PUBLISH_CLEAN_SNAPSHOT.md). `1.0.0` is the prepared source version, not a declaration of comprehensive production/security readiness. Read [RELEASE_ACCEPTANCE.md](RELEASE_ACCEPTANCE.md) for the exact evidence and untested claims. The final `v1.0.0` tag and GitHub Release must not be created without explicit maintainer acceptance of any remaining untested gates or release risks. Do not conflate all green CI checks with live compatibility.

## 1. Review reachable history AND public materials

From a trusted checkout with full Git history:

```bash
git fetch --all --tags --prune
git status --short
python3 scripts/audit_public_release.py --history
git log --all --format='%h %an <%ae> %s'
git ls-files
```

Manually inspect **all** git commits/trees, release artifacts, wiki, issues, PR comments, screenshots and external linked assets for secrets or identifying information. The script detects only selected high-risk patterns; high-entropy generic tokens, mailbox contacts and unusual credentials can be missed. Rotating an exposed secret is more important than hiding it in a later commit; deletion from the current tree does not scrub old history.

- Never upload screenshots containing active `cpsess` URL fragments, nonpublic recipient data or ownership challenge TXT values.
- The WHM screenshot shared during review contains a DNS challenge; **rotate and reverify** it before reusing or publishing that screenshot or related demonstrations.
- Git history contains author/committer names and emails; check those with all contributors before publication.
- Do not commit DKIM PEM keys, SQLite state, WHM sessions, FTP credentials, tickets, production mail headers, backups or server PCAP data.
- Before public status, re-check that no older release archives embed confidential files.

## 2. Production-like acceptance matrix

- Root session: authorized UI loads; nonroot WHM reseller denied; missing/invalid `cpsess` denied; CSRF mismatch denied; duplicate POST action rejected.
- UI: verify exact screens on actual supported WHM Bootstrap wrapper, desktop, narrow layout and RTL if advertised. Confirm DNS audit panel padding and safe text wrapping.
- Save/verify: reseller ownership token unchanged by an ordinary edit; rotating token disables verified state until the replacement TXT is published.
- Upgrade migration: default sender previously configured is **unverified** until `_rsm` TXT is published and verified; reseller policies remain functional.
- Deliverability: authorized manual RSM test only. Recipient obtained from WHM contact. Confirm externally `spf=pass`, `dkim=pass d=<sender-domain> s=rsm2026`, `dmarc=pass`; spam/inbox placement is a separate reputation test.
- Abuse: same account notification sent twice within 600 seconds must reject second submission; different accounts unaffected.
- Data: verify state/CSRF key 0700/0600, DKIM 0600 root-only, backup permissions and no private key leakage to logs.
- Lifecycle: fresh install, upgrade, failed upgrade restoration, code rollback and uninstall preserving data; ensure no modifications to native cPanel mail, Exim or DNS.
- Test on target WHM and CloudLinux versions. Local unit tests and a single-server pilot do not verify all deployments.

## 3. Safe RC pilot commands

```bash
cd /path/to/trusted/checkout
python3 -m unittest discover -s tests -v
python3 scripts/audit_public_release.py --history
bash -n scripts/*.sh
bash scripts/install.sh --dry-run
# after a secure backup and approved maintenance:
bash scripts/upgrade.sh
/usr/local/cpanel/3rdparty/bin/perl -c /usr/local/cpanel/whostmgr/docroot/cgi/rsm/index.cgi
```

Snapshot `/var/lib/whm-reseller-mail-manager` (root-only, containing state and DKIM keys) and the current Exim checksum before upgrade. Note: rollback only changes code; **it cannot undo state migrations**, revocations or sent email. If the new CGI fails because WHM does not supply the required `cpsess` token, roll back the code and report the exact cPanel version **without** sharing active session URLs.

## 4. Final stable release AFTER gates

1. Complete the live checks available on the approved WHM host; document outstanding tests and obtain explicit acceptance of limitations in `RELEASE_ACCEPTANCE.md`. Finish manual secret review.
2. Keep this internal repository PRIVATE. Approve and integrate the RC changes internally only after CI and review.
3. Verify the prepared distribution source reports version 1.0.0 consistently and rerun all tests and private-history screening.
4. Generate a NEW standalone single-commit checkout using `bash scripts/export_public_snapshot.sh /root/rsm-public-clean`.
5. Verify neutral Git author metadata and strict `--history --public-history` checks; review binary assets manually.
6. Push ONLY that clean snapshot to a NEW EMPTY GitHub repository with no existing branches or PR history.
7. After owner approval, create the signed v1.0.0 tag, archive and release notes **in the new distribution repository only**, and then consider switching only that new repository to Public.

**Do not switch the historical source repository to Public**: its old commits, author metadata and pull request references may remain available despite new fixes.

## Additional read-only evidence collector (RC acceptance)

After installing the RC on WHM, an operator may run:

```bash
cd /opt/src/whm-reseller-mail-manager
/usr/bin/python3 scripts/verify_live_readonly.py \\
  --source /opt/src/whm-reseller-mail-manager \\
  --check-dns \\
  --exim-checksum /root/rsm-release-backup/exim.sha256
```

The tool prints **PASS/FAIL and policy counts only**: not the sender address, saved verification token, DKIM private key or raw DNS TXT. It reads the SQLite database in read-only mode, verifies deployed modules, Perl CGI syntax, root-only key/state permissions and optionally live DNS challenges. No mail is sent and no settings are changed. An Internet/DNS outage may cause DNS assertions to fail closed.

**This diagnostic is not a substitute for the root/non-root WHM browser ACL check, live CSRF negative tests, desktop/mobile UI screenshots, test of rollback or an authorized email-authentication sample.** Do not share session URL, token or raw CGI HTML in public reports.

## Console unload policy warning in native WHM

Chrome 155 disables deprecated `unload` event handlers by default. The observed `utilities_container.js` warning is **not currently attributable to RSM**: RSM's own WHM template contains no JavaScript or `unload` listeners, but it is rendered inside the standard WHM master wrapper. Capture the script's actual source URL (with `cpsess` and credentials redacted) if the warning has functional consequences. Do not edit cPanel core files, weaken browser Permissions Policy or override WHM security headers to silence it.

## Guided native WHM UI acceptance

The dashboard now groups each reseller into exactly one category: **verified/enabled**, **configured but pending DNS proof**, **verified but paused**, or **not configured**. Counts refer to saved policy and current WHM account ownership, not actual authentication of sent mail. The default fallback ownership is a separate status. Each reseller shows a concrete next action; all visible inputs have persistent explanatory text plus an optional native title tooltip (including destructive-action checkboxes). Verify these behaviors on narrow and desktop WHM and validate actual form submission/label focus before a stable tag.

## Screenshot review of pilot on WHM 11.138.x

Private acceptance screenshots were inspected for Overview, Reseller Policies and DNS & Policy Preview. Native WHM header/sidebar/footer, main card layout, sample verified reseller status and account coverage, explanatory help and field labels were visually verified. Two small UX corrections were identified: (1) the DNS audit submit button sat beside the helper paragraph; it now appears below the field and help text, and (2) an existing fallback sender with no token after migration needs explicit instructions to save the unchanged address and generate its TXT challenge. Retest these details after deploying this follow-up patch.

**Confidentiality:** The source screenshot filenames contain a WHM `cpsess` value and the images show sender addresses. Never commit these screenshots or names to the public repository. Terminate the screenshot session and ensure all published demo images are independently sanitized. A review of default-branch commit metadata found a contributor email address; verify the owner's approval to expose historical author information before public visibility. Do not rewrite Git history without a separate approval and migration plan.

## Clean snapshot requirement

Use [PUBLISH_CLEAN_SNAPSHOT.md](PUBLISH_CLEAN_SNAPSHOT.md). The public snapshot must contain only non-sensitive RFC-reserved sample identities and IPs, with a neutral test commit author; the existing internal Git history must never be imported into the distribution repository. A normal corrective commit cannot hide old Git history.

## Isolated lifecycle acceptance via GitHub Actions

The new `lifecycle-simulation` job creates a **disposable mock WHM filesystem inside Docker**, running with `--network none` and a read-only checkout mount. It verifies successful first install, source upgrade, rollback including AppConfig re-registration, recovery after an intentionally broken code initialization, rejection of symlinked CSRF material, uninstall without data purge, and reinstall preserving state. No customer data, Exim, actual WHM service or SMTP transport is involved. Continue to require a genuine WHM staging exercise before declaring full live compatibility and the non-root CGI ACL gate before stable release.
