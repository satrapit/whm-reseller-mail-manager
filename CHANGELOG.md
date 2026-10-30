# Changelog

## 1.0.0 — 2026-10-30

**Release-source status:** prepared and CI-validated; final public tag and
repository publication require maintainer approval after reading
[release acceptance](docs/RELEASE_ACCEPTANCE.md).

### Features and operational scope

- Root-only WHM Reseller System Mail Manager with native WHM Template Toolkit
  header/sidebar/footer and guided per-reseller configuration.
- Verified sender-domain DNS ownership challenges, separate optional verified
  global fallback identity, SPF/DMARC audit guidance and RSM-owned DKIM signing.
- Account-specific RSM notice sender chosen from authoritative WHM owner and
  contact email; explicit root-initiated send, with a 10-minute per-account
  rate limit. RSM **does not** intercept native cPanel notifications, alter
  Exim/Dovecot configuration or rewrite unrelated customer mail.
- Safe lifecycle scripts for install/upgrade/rollback/uninstall; restore WHM
  AppConfig alongside CGI, template and application code on rollback, and
  retain private state by default during uninstall.
- Root-only private SQLite/CSRF/DKIM key protections; strict CGI checks for
  WHM root identity, ACL, CSRF and input-parameter safety.

### Validation

- 95 unit/regression tests each on Python 3.9, 3.11 and 3.13, syntax scans,
  strict release-history checks and one-commit clean Git export.
- Offline Docker mock simulation of full install/upgrade/rollback/uninstall,
  failed-upgrade recovery and retained-state reinstall.
- WHM 11.138 operational RC installation, 22/22 root-only read-only checks,
  observed non-root denial, and a remotely delivered, DKIM-valid TLS notice.
- **Known limitations:** no separate licensed WHM staging test for destructive
  lifecycle operations; external SPF/DMARC pass was not independently verified.
  See the exact evidence and outstanding gates in release acceptance.

### Distribution

A separate new Git repository must contain exactly one neutral-identity
source commit, this current changelog and a single stable `v1.0.0` tag,
after approved review. Never publish or rewrite the historical private
engineering repository. No private state, customer identifiers, screenshots,
session identifiers or older release archives belong in distribution.
