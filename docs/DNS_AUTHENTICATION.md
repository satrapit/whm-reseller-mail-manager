# Sender-domain SPF, DKIM and DMARC setup

Author: **arsamnet.com** · RSM 1.0.0

## Evidence levels (do not conflate)

1. **Ownership:** `_rsm.<domain> TXT rsm-verification=<token>` matches the saved per-reseller token. A saved Verified flag is also checked; a new DNS audit does not silently activate policy.
2. **SPF verified_dns:** the queried public SPF TXT contains an explicit positive `ip4` or `ip6` network matching the **confirmed outbound SMTP IP** and no earlier terminal `all` blocks it. This is *not* a full SPF evaluation: `a`, `mx`, `include`, `redirect`, DNS lookup budgets and macros can affect the real result. Always inspect the destination's SPF result.
3. **DKIM verified_dns:** public key syntax is plausible for the chosen selector. It does NOT assert that any specific mail was signed. RSM's dedicated selector also checks that the locally protected private key matches the published `p=`; a real message must carry `DKIM-Signature` and yield `dkim=pass`.
4. **DMARC verified_dns:** one DMARC TXT policy at `_dmarc.<domain>` has a valid `p=none|quarantine|reject`. Actual DMARC pass needs aligned SPF or DKIM from a real message, and published DMARC policy does not prove enforcement.
5. **Actual accepted/delivered:** local Exim queue acceptance is not inbox arrival. Remote SMTP 250 indicates the receiving server accepted the message; verify authenticated results in the received message.

## Read existing records before publishing

Use the plugin's **Check & verify DNS** per reseller. It shows current records and conditional TXT candidates with names and values. It never edits public DNS, Exim, cPanel users or unrelated SPF/DKIM/DMARC data.

- SPF missing: illustrative `v=spf1 ip4:<OUTBOUND_IP> ~all`. **Do not publish it unchanged** if website, CRM, external mail providers or other SMTP servers send as this domain.
- SPF already exists: preserve original mechanisms and insert `ip4:<OUTBOUND_IP>` ahead of `all`, only when safe. `redirect=`, macros and duplicate SPF TXT need manual review.
- DMARC missing: monitoring-only `_dmarc.<domain> TXT "v=DMARC1; p=none"`. Preserve current `rua`, `ruf`, `adkim`, `aspf`, `sp`, and `pct` tags for any existing DMARC policy.
- DKIM: never fabricate `p=`. Generate a signer first (see below) and publish the public key that matches the protected private key.

## RSM-only DKIM signing

The root-only WHM action **Provision RSM DKIM key** is available after domain ownership is verified. It requires explicit administrator confirmation, creates a 2048-bit RSA private key with mode 0600 at:

`/var/lib/whm-reseller-mail-manager/dkim/<domain>.pem`

The directory is root-only (0700). The key is persistent across application upgrades and does not enter the source repository.

The public selector is **`rsm2026._domainkey.<domain>`**. Copy the generated TXT `v=DKIM1; k=rsa; p=<base64-key>` to the domain's actual authoritative DNS zone. Long DKIM TXT records must be represented as a single DNS TXT RR with multiple <=255-byte character strings when required by the DNS provider; do **not** create multiple TXT RRs with separate halves.

Re-run audit to check publication. With a provisioned key, `notify.py --send` checks the live DNS public key, signs the RSM-authored fixed-content email, and submits it via local sendmail. If key and DNS disagree, sending **fails closed**. Without any key provisioned, existing unsigned behavior continues, subject to SPF. The plugin does not generate or intercept cPanel/iContact emails and does not touch global Exim DKIM settings.

**Key rotation:** no automatic replacement. A different selector and overlapping publication are necessary for safe key rotation; do not delete active keys without a reviewed change plan.

## Safeguards

Use a known public outbound IP, not the site's A record or a guess. Never publish a second SPF policy. Keep any existing provider's DKIM selector. Preserve stronger DMARC policies, valid reporting addresses and security settings. DNS-only verification is not an external deliverability guarantee. Keep DKIM private keys out of Git, tickets, logs and public folders; restrict backups. For both high-volume and normal mail, follow the latest recipient provider requirements.

## References

- [RFC 7208 SPF](https://www.rfc-editor.org/rfc/rfc7208)
- [RFC 6376 DKIM](https://www.rfc-editor.org/rfc/rfc6376)
- [RFC 7489 DMARC](https://www.rfc-editor.org/rfc/rfc7489)
- [cPanel Email Deliverability](https://docs.cpanel.net/cpanel/email/email-deliverability-in-cpanel/)
- [Google Sender Guidelines](https://support.google.com/mail/answer/81126)


## v0.3.1 DKIM signature interoperability repair

A real Gmail message from 2026-10-28 returned `dkim=fail` although public and private keys matched, because the previous signer hashed an extra final CRLF after the canonicalized `DKIM-Signature` header (RFC 6376 section 3.7 prohibits that trailing CRLF). Version 0.3.1-beta fixes the signed bytes and adds an OpenSSL regression test. The private key and `rsm2026` TXT must **not** be regenerated for this fix.

Upgrade safely, inspect that the DKIM signature is unchanged in domain/selector (d= / s=), then submit only one explicitly authorized RSM test to a verified recipient. `Authentication-Results: dkim=pass header.d=<sender-domain>` at the recipient is the acceptance criterion. SPF and DMARC passing alone do not prove DKIM correctness.
