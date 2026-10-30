# RSM 1.0.0 — Release acceptance evidence and explicit limitations

**Distribution status:** source prepared for final acceptance; no public distribution,
stable signed tag, or GitHub Release has been created by this report.
**Project maintainer / copyright:** arsamnet.com (MIT).
**Evidence cutoff:** 2026-10-30. This document contains no customer mailbox,
production IP, message ID, private DNS ownership challenge, session URL, or key.

## Validated

- Unit/regression suite: 95 tests on each of Python 3.9, 3.11 and 3.13, with
  syntax checks, private-repository history screening, and a strict new
  single-commit public-history export rehearsal. The final 1.0.0 source must
  pass these same CI gates again.
- Disposable offline Docker lifecycle: clean install, upgrade, re-register
  WHM AppConfig on rollback, failed-upgrade restoration, unsafe CSRF symlink
  rejection, uninstall retaining private state, reinstall retaining state.
  Mock cPanel/WHM components are used. This proves only the simulated lifecycle.
- Existing operational WHM 11.138 series (maintenance build omitted from the
  public distribution): operator installed 1.0.0-rc2 and
  reported 89/89 tests plus 22/22 **read-only** checks successful; installed
  program/CGI/template matched source; root-only state and keys, SQLite
  integrity, two public DNS ownership TXT proofs and unchanged Exim config
  digest were checked. Later test-only commits do not change the installed
  runtime code.
- Actual WHM reseller: operator reported that a non-root reseller could not
  access the plugin URL and had no plugin/ACL menu entry. The exact live HTTP
  response code was not recorded. Isolated execution of actual CGI auth logic
  confirms 403 for synthetic non-root, missing-user and insufficient-ACL cases.
- Authorized RSM notice: one dry-run selected a verified reseller policy,
  and an explicitly approved real notification was accepted by Exim.
  Independent recipient-server headers show encrypted SMTP transport (TLS 1.3)
  and successful destination LMTP mailbox delivery.
- Recipient-side spam diagnostics reported `DKIM_SIGNED`, `DKIM_VALID`,
  `DKIM_VALID_AU` and `DKIM_VALID_EF`, with the expected application DKIM
  selector and sender-domain alignment. One received notice was not flagged
  as spam. This is not a guarantee of future Inbox placement.
- The operator verified a restricted private-state archive and consistent
  SQLite backup, with `PRAGMA quick_check = ok`. Backup bytes were never
  placed in the source repository.

## Not established / accepted limitations

- No SPF=pass or DMARC=pass receiver `Authentication-Results` were supplied.
  DKIM validation alone does not prove either of these conditions. A real
  externally received message with these results is required before making
  a complete SPF/DKIM/DMARC acceptance claim.
- No separate licensed WHM staging host is available. Production rollback and
  uninstall were deliberately **not** executed. Docker simulation cannot
  establish their behavior on a real cPanel installation. Use a verified
  backup and controlled maintenance window before any future recovery.
- Full live invalid/expired session, CSRF, challenge rotation, 10-minute
  rate-limit repetition, mobile WHM layout and every DNS edge case were not
  independently accepted in the recorded operational pilot.
- The global fallback sender is still **unverified** and is intentionally
  prevented from sending. Two configured, verified reseller policies remain
  independently enabled.
- RSM sends only its **own explicitly triggered** notices. It does not replace
  native WHM/cPanel notifications, modify Exim configuration or intercept
  customer messages.
- Static source-secret scanners are heuristic; manually review sources,
  copyright notices, images, archives, release attachments and metadata.
  A previously shared WHM screenshot showed a DNS ownership proof. Rotate
  and reverify that challenge before publicly reusing the screenshot.

## Publication decision

The source can be prepared as 1.0.0 with these limitations documented, but
**publishing a release requires explicit maintainer approval** of the remaining
risks. Never make the historical engineering repository public or rewrite
its private history. Publish only from a new, reviewed, single-commit Git
distribution with neutral committer metadata, no remotes inherited, and no
private state, screenshots, customer identifiers or earlier release archives.

Acceptance of the source and acceptance of real-world deliverability are
separate decisions. Do not market SPF/DMARC validation as completed.
