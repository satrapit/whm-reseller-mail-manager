# Quickstart — WHM Reseller System Mail Manager

**Author:** arsamnet.com · **License:** MIT · **Release:** 1.0.0 (release source; publication pending maintainer approval)

## 1. Before installation

A supported cPanel & WHM server (11.132+), actual root login, Python 3.9+, `dig`, `openssl`, WHM API and an approved source checkout are required. Review the source and back up WHM state. The plugin cannot send native cPanel/iContact notices or rewrite customer mail.

```bash
cd /opt/src/whm-reseller-mail-manager
git status --short
python3 -m unittest discover -s tests -v
bash -n scripts/*.sh
bash scripts/install.sh --dry-run
```

## 2. First installation or existing-server upgrade

```bash
# Choose one:
bash scripts/install.sh --install  # new installation
bash scripts/upgrade.sh           # existing installation
/usr/local/cpanel/bin/is_registered_with_appconfig whostmgr rsm
```

Sign in to WHM as **root** at port 2087. Find **Reseller System Mail Manager** in the native menu. No DNS, Exim, cPanel mail settings or messages are modified by installation.

## 3. Configure sender policy

In **Overview**, set the site's own legitimate fallback sender and enable RSM-only policies. New instances start disabled with an empty fallback. In **Reseller policies**, set the reseller's actual `sender@example.net` (substitute your domain), and save. Publish its `_rsm.example.net` TXT, then **Verify public DNS**. Ownership proves control of a DNS challenge, NOT actual mail identity or mailbox access.

## 4. DNS health check

In each reseller card, enter the **real outbound SMTP IP** as observed by the external recipient / Exim SMTP log. Press **Check & verify DNS**. For each record:

- **SPF**: compare the current policy; only one SPF TXT per domain. A proposed candidate preserves the existing tokens but is NOT safe for automatic deployment without checking all sending providers and includes.
- **DKIM**: if requested, explicitly provision the dedicated RSM key; publish `rsm2026._domainkey.example.net` TXT. Do not overwrite `default._domainkey` or unrelated selectors. Long DNS TXT key values may require DNS-provider-specific chunking into one RR.
- **DMARC**: existing `p=quarantine` or `p=reject` values are never weakened. If absent, `v=DMARC1; p=none` is a monitoring-only suggested starting point.

Re-run the audit after DNS propagation. Green/verified *DNS* statuses do NOT prove SPF/DKIM/DMARC on a real delivered message.

## 5. Controlled notification test

Choose a WHM account and confirm its configured contact mailbox is controlled/approved:

```bash
/usr/bin/python3 /opt/whm-reseller-mail-manager/app/src/notify.py --account TESTACCOUNT
# Explicitly authorized, one-time controlled SMTP submission:
/usr/bin/python3 /opt/whm-reseller-mail-manager/app/src/notify.py --account TESTACCOUNT --send
```

Inspect its Exim message ID for `=>`, `**`, `==` and `Completed`. On a received message, check `Authentication-Results`, including `dkim=pass header.d=<sender-domain>` when RSM signing was provisioned.

## 6. Rollback

```bash
bash scripts/rollback.sh --rollback
```

Rollback code does NOT roll back SQLite or cryptographic key material. See [Operations](OPERATIONS.md), [DNS guide](DNS_AUTHENTICATION.md) and [Security](SECURITY.md).

## Important after upgrading from 0.3.x

Existing fallback sender emails remain stored but require **separate TXT verification**. Go to Overview, save the fallback sender again if no token appears, publish `_rsm.<fallback-domain>` TXT, and click **Verify fallback TXT**. This is fail-closed for unverified fallback mail; already verified reseller rules remain valid. The same domain may carry multiple TXT records for different verification challenges. Do not delete the reseller's verified token when adding the fallback token.

Use the **Rotate ownership challenge** control only for a leaked/compromised verification value; it immediately revokes that identity's verified state. After rotation, publish the replacement TXT then verify. **No DKIM key rotation** is performed.

Per-account manual `notify.py --send` test submissions are throttled to once per 10 minutes. Test recipient is always the WHM account contact; no arbitrary recipient or sending from the UI is supported.

See [Public release gate](PUBLIC_RELEASE.md) before making the repository public or tagging v1.0.0.
