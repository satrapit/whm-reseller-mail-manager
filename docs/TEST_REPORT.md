# 1.0.0 — Verification report

**Report scope:** current source prepared for the 1.0.0 release.
See [RELEASE_ACCEPTANCE.md](RELEASE_ACCEPTANCE.md) for detailed evidence,
unsupported claims and decision requirements.

## Automated validation

- Prior 1.0.0-rc2 private CI run: 95 regression tests per Python version
  (3.9, 3.11, 3.13), 4/4 jobs passed, including strict secret/history checks.
- Isolated disposable Docker test: clean install, upgrade, code/CGI/template/
  WHM AppConfig rollback, injected failed-upgrade recovery, Symlink rejection,
  uninstall without purging user state and reinstall with retained SQLite/CSRF.
- A fresh final 1.0.0 CI run must pass before creating the public release.

## Actual operational evidence

- Operator installed the prior release candidate on a compatible licensed WHM
  host using verified private backups. Read-only health diagnostics: 22/22
  PASS, including installed-code match, root-only secret modes, SQLite health,
  two DNS ownership proofs and unchanged Exim configuration checksum.
- Operator could not access the direct RSM page as a real non-root reseller;
  precise HTTP status was not captured. A separate sandbox Perl CGI execution
  test verifies synthetic non-root requests receive 403 before rendering.
- One explicitly authorized RSM notification was submitted to Exim and later
  observed delivered by a different mail server over TLS and LMTP. Recipient
  side identified its DKIM signature as valid and aligned with the author and
  envelope-from domains. The observed message was not classified as spam.

## Not independently demonstrated

- Receiver-side `spf=pass` or `dmarc=pass` was not provided.
- No second licensed WHM host was available for a destructive rollback or
  uninstall test; the simulated Docker acceptance does not replace that test.
- Full active-browser CSRF/session negative matrix, DNS challenge rotation,
  mobile WHM screenshots and live rate-limit repeat exercise are pending.

The single-commit public distribution must exclude customer contact data,
private operational screenshots/logs, WHM session URLs, keys and backup
files. No historic engineering authors or commits may be copied from the
private repository. This document intentionally contains no production
addresses or message identifiers.
