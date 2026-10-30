# Security Policy

Maintainer: **arsamnet.com**

## Reporting security issues

Please **do not** publish vulnerabilities, exploit chains, private keys, owner verification tokens or production logs in public GitHub issues. Contact the project maintainers privately using GitHub's private vulnerability reporting feature **if enabled for this repository**, or another established private maintainer channel. Do not assume an unpublished email address exists.

Include a minimal sanitized reproduction, affected version and impact. Maintain authorized testing boundaries. No guarantee of security response time or SLA is implied.

## Deployment and support

This is a privileged **root-only WHM extension**; deploy only from reviewed trusted commits. Secure its SQLite state, CSRF key, RSM DKIM keys and backups. Do not make the key storage directory accessible through public web roots. Follow [technical security model](docs/SECURITY.md) and [release checklist](docs/RELEASE_CHECKLIST.md).

No native cPanel/iContact interception, Exim-global reconfiguration, arbitrary SMTP relay or automatic DNS editing is provided. DNS audit outcomes are not proof of recipient-side authentication.

Before making the repository public, follow `docs/PUBLIC_RELEASE.md`, run `python3 scripts/audit_public_release.py --history`, and review the entire Git history, screenshots, artifacts and metadata manually. A green regex scan is not a security certification.

## Private development history

For any public distribution, publish only a new standalone clean single-commit snapshot. Do not make the existing internal source repository public because historical commit authors and previous file revisions remain available even when removed from HEAD. See `docs/PUBLISH_CLEAN_SNAPSHOT.md`.
