# Operations and pilot checklist

**Preflight:** cPanel/WHM 11.132+, actual root shell, enough disk space, Python, Perl modules, `dig` and `whmapi1`. Run `scripts/install.sh --dry-run` to see precise missing dependencies; dry-run never writes.

**Configuration:** in WHM as root, set `Default sender = notifications@example.net`. Under resellers choose the example `demoowner`, save `reseller@example.org`, add its public `_rsm.example.org` TXT challenge, wait until the authoritative record is visible, verify. Inspect SPF/DMARC; for DKIM obtain the signing selector and an actual message header by external means. Then enable both that reseller rule and the global RSM-originated message rule.

**Validation:** Preview policy for a known reseller-owned test account, a different reseller account, an account whose owner has changed, and an unknown account. Unknown must report null/preserve. The others should be custom/default based on current owner and verification. Call RSM `notify.py --account TEST_ACCOUNT` without `--send` and confirm correct owner and recipient source before any pilot.

**Authorized pilot:** only if approved on a test account, inspect/confirm the `listaccts` contact address then explicitly run `notify.py --account TEST_ACCOUNT --send`. Examine Exim logs and actually received headers. To halt RSM submissions, disable the global rule immediately. This does **not stop or change native cPanel mail**, because RSM does not intercept it.

**Upgrade/rollback:** installer keeps one previous release path in `/var/lib/whm-reseller-mail-manager/previous_release`. Before upgrading, separately back up state sqlite database and original package. `scripts/rollback.sh --rollback` restores previous code; `scripts/uninstall.sh --uninstall` removes registrations and code, retains data. Check native Exim config has not changed: `exim -bV`, compare `/etc/exim.conf` against pre-install snapshot. `cpsrvd` restart is manual and can interrupt sessions, so schedule it.

**Acceptance boundaries:** The 1.0.0 source is backed by an actual WHM 11.138 RC2 upgrade and 22/22 read-only checks, a reseller access denial observed by the operator, and one remotely delivered DKIM-valid RSM notice. Destructive rollback/uninstall has only been simulated in disposable Docker, not on a second licensed WHM server. Live SPF/DMARC authentication results and all live session/CSRF edge cases remain outside the tested evidence. DNS must be delegated and public to verify TXT. RSM does not replace native cPanel notifications.


## Native WHM UI upgrade

The new view relies on cPanel's bundled Template Toolkit engine and
`master_templates/master.tmpl`. Do not modify cPanel core templates.
Git source checkout and the installed release are separate locations.

```bash
cd /opt/src/whm-reseller-mail-manager
git pull --ff-only
python3 -m unittest discover -s tests -v
bash -n scripts/*.sh
bash scripts/install.sh --dry-run
# At an approved maintenance window only:
bash scripts/upgrade.sh
# Check the installed view:
/usr/local/cpanel/3rdparty/bin/perl -c /usr/local/cpanel/whostmgr/docroot/cgi/rsm/index.cgi
test -f /usr/local/cpanel/whostmgr/docroot/templates/rsm/index.tmpl
```

Reopen the plugin from the WHM left menu in a fresh root session.
WHM itself should render the top header, left sidebar and footer. If the
view fails, inspect the cPanel error log and, if needed, perform
`bash scripts/rollback.sh --rollback` from the trusted checkout. A
restart of `cpsrvd` may be required to refresh routing/template caches;
do not restart repeatedly while troubleshooting. No mail is sent on upgrade.


## Per-reseller DNS authentication checklist

1. Under the reseller policy, save sender email, publish the domain control TXT, click **Verify public DNS**.
2. Supply the **actual SMTP egress IP**, observed from an outgoing SMTP log, to **Check & verify DNS**. The application does not guess it from the A or MX records.
3. For SPF, copy the proposed **single** TXT only if it does not remove legitimate providers. Duplicate SPF policies and redirect/macros require manual assessment. For DMARC, preserve any existing reporting and stronger policy; `p=none` is a monitoring-only starter if no record exists.
4. DKIM: select **Provision RSM DKIM key** explicitly. Publish the provided `rsm2026._domainkey` TXT, leaving all existing DKIM selectors untouched. Run the audit again.
5. Test only an authorized WHM-contact account through dry-run and a single `--send`. Confirm a `DKIM-Signature` header with `d=<sender-domain>`, `s=rsm2026`, plus SPF/DMARC results in the mailbox. Do not equate DNS status or Exim `250 OK` with inbox delivery.
6. Back up `/var/lib/whm-reseller-mail-manager` (including DKIM private keys) with restricted access before upgrades. Never commit private keys or owner TXT tokens to the repository. Restoring SQLite alone without private keys may prevent DKIM signing.

No automatic DNS updates, Exim transport edits or cPanel notification interception take place. `docs/DNS_AUTHENTICATION.md` explains warning states and safe fallback behavior.

## RC hardening migration and rollback

Version `1.0.0` requires explicit verification for the **global fallback sender**, independent of reseller sender verification. Old fallback sender settings remain stored, but may not send until the owner publishes/validates the new `_rsm` TXT. This behavior is intentional. Reseller-specific verified senders remain in effect. Rotating any challenge revokes its verified status and pauses relevant sends. The last code release can be rolled back, **but database verification and cooldown changes are not rolled back**. Take a root-only SQLite/CSRF/DKIM backup before updating.

The new RSM notice limiter prevents repeated sends within 10 minutes for the same cPanel account, across concurrent root commands. Send failures with an explicit nonzero return code release the claim; uncertain timeouts remain rate-limited to prevent duplicates. This does not throttle native cPanel mail.

Production checks: real WHM root session, denied nonroot access, wrong/expired CSRF, duplicate parameter rejection, malformed input, live DNS auth, OpenSSL signer and one authorized Gmail test. Exim checksum should remain unchanged. Inspect `/usr/local/cpanel/logs/error_log` if the native WHM wrapper fails to render. The UI must be reviewed at desktop and narrow viewport widths.

## Rollback and uninstall safeguards

The `scripts/rollback.sh --rollback` command restores the previous code symlink, CGI, Template Toolkit file **and WHM AppConfig registration**, guarded by the same lifecycle lock as installation and uninstall. If rollback fails while restoring, the tool attempts to reinstate the current release code and AppConfig. This is a code rollback only: SQLite contents, ownership proofs, cooldowns, DNS and already-sent notices are unchanged. Back up root-only state and test in staging before use. Uninstall without `--purge-data` preserves `/var/lib/whm-reseller-mail-manager`.

An isolated CI Docker mock checks the lifecycle with no network or real cPanel APIs. It is not proof of non-root ACL enforcement in a real WHM browser, nor proof of deliverability.
