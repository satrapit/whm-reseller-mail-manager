# Security model / threat boundaries

## Trust

WHM session authentication is handled by cPanel; CGI **also** enforces `Whostmgr::ACLS::init_acls`, `checkacl('all')` and identity equal to `root`. All read/write backend operations execute as root only under the WHM dispatcher; the bare CLI executable is also root-only. `REMOTE_USER` must be observed on target cPanel to ensure it cannot be forged by an unprivileged request. Session-derived HMAC anti-CSRF values are generated from a 0600 root-only secret and remote address; note proxies/NAT with dynamic remote addresses can affect form expiry. The CGI sends no-store/no-sniff headers and uses the native WHM master template; it does not impose a standalone CSP that could break upstream WHM assets. Config input length limited to 8 KiB.

## Data

SQLite DB, token and audit at `/var/lib/whm-reseller-mail-manager`, with 0700 parent and 0600 files. No stored SMTP credentials because the version does not support external SMTP. DNS domain-challenge tokens are published publicly by design. Audit captures changes/verification result, never SMTP passwords or email bodies. Limit auditor retention to last 2000 events; no delete-all UI.

## Transport and identity

The RSM notice sender uses a fixed-argument, non-shell `sendmail -oi -f <validated>` submission and a fixed content template. The receiving address is derived only from `listaccts` currently associated with that WHM account. Sending is default **dry run** and explicitly guarded by `--send`, root privilege, global switch, and live policy evaluation. A verified DNS TXT proves control of that sender domain at verification time, but does **not** prove mailbox ownership, local Exim DKIM signing or public DMARC alignment. The administrator must check those separately.

## Limits/open risks

- This is not a complete production security audit or live penetration test.
- WHM CGI trust origin and native CSRF behavior must be validated with real WHM.
- No enforced transport TLS for remote delivery: Exim owns onward outbound transport configuration.
- `dig` can query user-supplied valid domain labels (public DNS), but no arbitrary host or port is configurable, limiting network SSRF.
- SPF lookup graph/caching not fully implemented; output clearly labels unverified proposal.
- No native iContact message rewriting; no risk of unintended cross-tenant global sender identity rewrite from this code path.
- Directory and binary integrity depend on root-controlled installation package; verify package checksum before deploying.


## 1.0.0 RSM DKIM keys

DKIM keys are opt-in, created through a root-only, anti-CSRF-protected WHM action after a live ownership TXT check. The private key is never shown in the UI or stored in the code repository. Files reside under `/var/lib/whm-reseller-mail-manager/dkim/` and are only readable by root. The dedicated selector `rsm2026` does not replace other selectors and does not change Exim's DKIM transport. For a provisioned key, `notify.py --send` refuses to send until a matching public TXT is observed; for domains without provisioned keys, historical unsigned delivery behavior remains. Rotation is deliberately not automated; reusing one selector for a replaced key can invalidate messages in transit. Manual rotation should use a new selector and an overlapping DNS transition in a reviewed future release.

Audit results and proposals are DNS-only evidence; `verified_dns` is not `spf=pass`, `dkim=pass` or `dmarc=pass` for any particular email. Domain control does not authorize modification of other users' Exim transports. Threats include recursive SPF evaluation, external DNS latency and resolver poisoning; this release deliberately leaves full SPF evaluation and cryptographic inbound DKIM verification to authoritative mail systems.

## 1.0.0 security changes and residual risk

Root-only CGI requires a nonblank cPanel `cpsess` token and per-form HMAC CSRF; malformed/duplicate parameters and non-GET/POST methods are rejected. The backend still requires effective UID 0 independently. File/directory access checks require ownership by the executing UID and reject symlinks/insecure DKIM modes. The fallback sender now requires a separate verified domain challenge, and opted-in notifications are limited to one per account per 10 minutes via a SQLite transaction.

Ownership TXT tokens are **public in DNS** and are not credentials, but displaying their values in screenshots or logs can facilitate replay of a previously proven domain if controls are weakened. Verified TXT values are collapsed in the UI, and explicit challenge rotation revokes the saved verified flag. Public Git history/screenshot/hosting-server secrets require a manual review, even if the automated regex scanner reports clear.

**Known limitations:** root/WHM environment remains the trust root; per-session CSRF binds to the WHM cpsess URL which must be tested on every supported WHM theme/version. Recipient-side SpamAssassin validation of one remotely delivered DKIM signature is recorded, but no receiver-side SPF/DMARC pass or DNSSEC validation is established; no DNS autorouting or iContact sender override. The built-in private-key signer was tested via OpenSSL and one independent receiving mail server; broader WHM deployments and authentication chains require additional validation. The plugin does not claim security certification or an assurance of zero vulnerabilities.
