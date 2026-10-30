# WHM Reseller System Mail Manager (RSM)

**Version:** `1.0.0` (release source; publication pending maintainer approval) · **Maintainer/author:** [arsamnet.com](https://arsamnet.com) · **License:** MIT.

RSM is a root-only WHM extension for configurable sender policies on **RSM-authored notices**, reseller-domain ownership verification and **read-only per-reseller SPF/DKIM/DMARC audits**. It proposes TXT records based on existing public DNS, never blindly rewrites an existing SPF/DMARC record, and supports an optional RSM-specific 2048-bit RSA DKIM signing key and selector.

**Important boundary:** RSM does **not** change native cPanel/iContact notification senders, customer email, Exim configuration, or public DNS. SPF/DKIM/DMARC DNS checks are not equivalent to authentication results on a real received message.

## Quick start

Read **[Quickstart](docs/QUICKSTART.md)**, **[DNS authentication & DKIM](docs/DNS_AUTHENTICATION.md)** and **[Operations](docs/OPERATIONS.md)**.

From a **trusted** source checkout on a compatible cPanel/WHM server, as root:

```bash
python3 -m unittest discover -s tests -v
bash -n scripts/*.sh
bash scripts/install.sh --dry-run
bash scripts/install.sh --install       # first install only
# Or for existing installations:
bash scripts/upgrade.sh
```

Go to **WHM → Reseller System Mail Manager**. Set a real fallback sender for your own verified domain (new installations intentionally start **empty and globally disabled**, never with a third party's address). Add a reseller sender, publish its `_rsm.<domain>` TXT, verify it, then run **Check & verify DNS** with the confirmed outbound SMTP IP from an Exim log. Review record candidates at the domain's **authoritative** DNS provider. A missing DKIM key requires pressing **Provision RSM DKIM key** with explicit confirmation, publishing `rsm2026._domainkey.<domain>`, then rechecking DNS. Provisioning alone does not send mail.

The test notice command defaults to dry-run:

```bash
/usr/bin/python3 /opt/whm-reseller-mail-manager/app/src/notify.py --account TEST_CPANEL_USER
# Opt-in only after checking the WHM contact address and approving the recipient:
/usr/bin/python3 /opt/whm-reseller-mail-manager/app/src/notify.py --account TEST_CPANEL_USER --send
```

When a provisioned RSM private key exists, outgoing RSM-authored messages are DKIM signed **only if the corresponding public key matches current DNS**. If publication is missing/mismatched, submission is refused rather than silently downgraded. Without a key, existing SPF-based behavior remains unchanged. `sendmail` acceptance is not inbox delivery; inspect the destination's `Authentication-Results`.

## Scope and compatibility

- WHM 11.132+, root-only plugin, Perl CGI through WHM's native Template Toolkit, Python 3.9+, `dig`, `openssl`, Exim for optional notification delivery.
- Root-only SQLite/CSRF state under `/var/lib/whm-reseller-mail-manager/`, with root-only RSM DKIM keys under `.../dkim/` (mode 0700 directory, 0600 private keys).
- Direct public DNS TXT reads only; no remote nameserver login, DNS modifications, arbitrary email recipients or changes to native cPanel mail behavior.
- Stable policy engine uses fresh WHM account ownership. Other resellers' policies do not spill across accounts.
- SPF check confirms an **explicit, positive IP mechanism** for the IP supplied by the admin; it does not resolve the full recursive SPF graph or prove SMTP SPF pass.
- DKIM DNS check validates only publication and key match; real signing must be confirmed in an actual message.
- DMARC DNS check verifies publication and `p=` syntax, not DMARC alignment for an actual message.

See [Architecture](docs/ARCHITECTURE.md), [Threat model](docs/SECURITY.md), [Contributing](CONTRIBUTING.md), [Security policy](SECURITY.md), [Changelog](CHANGELOG.md) and [License](LICENSE).

## Official references

- [cPanel WHM plugin API](https://api.docs.cpanel.net/guides/guide-to-whm-plugins)
- [cPanel email deliverability](https://docs.cpanel.net/cpanel/email/email-deliverability-in-cpanel/)
- [Google sender guidelines](https://support.google.com/mail/answer/81126)
- [DKIM RFC 6376](https://www.rfc-editor.org/rfc/rfc6376)
- [SPF RFC 7208](https://www.rfc-editor.org/rfc/rfc7208)
- [DMARC RFC 7489](https://www.rfc-editor.org/rfc/rfc7489)


## v1.0.0 security changes

- **Default identity is fail-closed.** All fallback senders must pass an independent `_rsm.<domain>` TXT challenge; existing unverified fallback mail is deliberately blocked after upgrading. Saved reseller identities and their existing verification flags are preserved.
- **Token rotation.** Root can rotate either fallback or reseller domain challenge after explicit confirmation. Rotation revokes verification until replacement TXT is published and checked. Existing DKIM keys are never rotated by this action.
- **Notification throttling.** RSM-only `notify.py --send` is limited to one submission per account per **10 minutes**, enforced atomically in SQLite. Dry-run and DNS audits do not consume the quota.
- **Privilege and file validation.** WHM root + a nonempty cPanel session and CSRF are required; duplicate parameters are refused. State, DB and DKIM file ownership/modes are checked; key mismatch and insecure keys fail closed.
- **UI.** Reseller DNS audit is inside the padded card; controls have consistent margins and small-screen layout. Verified TXT values are collapsed by default, not removed from DNS.
- **Public-source screening.** CI performs a narrow high-risk token scan over tracked files and reachable Git history. This is NOT a replacement for full secret scanning, a privacy review or manual release approval.

**Do not publicize production screenshots containing `cpsess` tokens or ownership TXT values.** Rotate an exposed challenge using the new control, then publish and verify its new value.

This independent plugin does not offer a native cPanel/iContact From/envelope override, unrestricted SMTP relay or Inbox placement guarantees. See [v1 readiness gates](docs/PUBLIC_RELEASE.md) and [security audit findings](docs/SECURITY_AUDIT.md).

## Read-only production acceptance diagnostic

With a trusted local checkout and after installation, run `python3 scripts/verify_live_readonly.py --check-dns` as root. This checks file integrity, root-only permissions, SQLite integrity, policy counts and public ownership proofs without printing credentials or sending email. It is not a penetration test and does **not** validate live WHM browser sessions, privilege denial or Inbox placement. See [public release gates](docs/PUBLIC_RELEASE.md).

## Guided WHM administrator experience

The native WHM Overview shows a high-level policy health summary: enabled+verified reseller rules, policies needing action, accounts under ready rules, and the separate global fallback verification state. Each reseller policy displays a specific next step (save sender, publish/verify TXT, enable paused policy, or inspect authentication and preview). Visible form inputs have persistent help and hover/focus title hints; the UI needs no JavaScript or deprecated `unload` events. These states reflect stored verification and current WHM ownership only, not verified real-world mail delivery.

## Public distribution without revealing private history

The historical engineering repository stays private. Run `bash scripts/export_public_snapshot.sh /root/rsm-public-clean` from a trusted, clean release checkout after all acceptance gates. This produces a standalone Git repository with a fresh single commit and neutral example author metadata, and checks the source for personal emails and public infrastructure IP examples. Publish **only** that clean snapshot to a different empty GitHub repository after manual review; never expose this repository's old branches or PR history. See [Clean public distribution](docs/PUBLISH_CLEAN_SNAPSHOT.md).

## Release evidence and limitations

See [Release acceptance](docs/RELEASE_ACCEPTANCE.md) before deployment or publication. The production pilot demonstrated independently received, DKIM-valid RSM notice delivery; **SPF/DMARC pass were not measured**. Destructive recovery actions were tested in an offline mocked container, **not** on a second licensed WHM staging host. The separate distribution repository is the only place a stable tag should be published; the historical engineering repository must stay private.
