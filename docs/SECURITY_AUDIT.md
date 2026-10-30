# 1.0.0 source security assessment and residual risks

Scope: a code review of the root-only WHM CGI, Python policy/storage and RSM notifier, DNS and DKIM subsystems, installation/rollback scripts, GitHub CI and public documentation. This is a **source review**, not a penetration test, formal audit, or proof of zero vulnerabilities.

## Remediated before the prepared release source

| Finding | Risk before hardening | Change |
| --- | --- | --- |
| Unverified fallback identity | A root operator could use an arbitrary fallback domain without TXT proof | Added dedicated `_rsm` challenge and fail-closed fallback; migration requires reverify |
| CGI parameter pollution | Last duplicate field silently replaced earlier field | Duplicate keys rejected; missing WHM session and unsupported methods fail closed |
| Request body handling | A short CGI read could silently parse incomplete payload | Full bounded read required |
| Ownership/DNS replay | No direct rotation UI for exposed TXT challenge | Explicit root-only rotation revokes verified state without touching DKIM keys |
| Notice spam / duplicate sends | Repeated privileged CLI calls could submit unlimited fixed notices | Atomic per-account 600-second cooldown with limited audit |
| Key file trust | Permissions checked but owner identity not | Owner, mode, symlink and directory checks before signing |
| Ambiguous DKIM DNS | Matching public key alongside other selector RRs could be incorrectly accepted | Exactly one DKIM key RR at selector is required |
| UI spacing and accidental token sharing | Audit controls outside padded card, verified token always visible | Moved audit inside card padding; verified challenges collapsed |
| Public source review | No integrated history scan | CI scans tracked files and reachable Git blobs for a subset of common secrets; manual review mandatory |

## Residual limitations and acceptance boundaries

- A real WHM reseller was observed unable to access the direct RSM URL; a precise live HTTP status and complete negative session/CSRF matrix were not captured. CGI authorization logic also passed isolated scripted tests. Changes may fail closed on installations where cPanel omits the expected security token format; do not weaken these checks without reviewed evidence.
- Whostmgr ACL, CGI URL and template wrapper behavior depend on the target cPanel version; unit mocks are not full end-to-end tests.
- DNS inspection does not perform full recursive SPF evaluation or guarantee SPF/DMARC pass. A real remotely received notice had a receiver-validated DKIM signature, but no SPF or DMARC Authentication-Results were supplied.
- The RSM notifier is **not** an integrated replacement for native cPanel/iContact events and does not rewrite customer email. It is a narrowly scoped opt-in fixed notice.
- Private keys are root-owned at rest, but a compromised root user fully compromises the trust boundary. Backups must preserve secret-file permissions.
- Release secret detection is heuristic, not comprehensive. Historical commits, screenshots and external artifacts still require manual review, rotation and owner approval.
- Mail deliverability (especially Spam folder placement) is determined by receiver reputation/content policies in addition to successful SPF/DKIM/DMARC.
- No independent penetration test or licensed second-host staging rollback was performed. These are explicit release acceptance limitations, not validated security guarantees.

## Change safety

No code in the release source edits external DNS, Exim configuration, cPanel native iContact templates, customer mail or existing DKIM selectors. Domain ownership rotation is opt-in and revokes verification. The fallback policy change intentionally prevents unverified sends. `notice_cooldown` adds an idempotent SQLite table; code rollback does not downgrade that DB schema.

## Additional gate: privileged CSRF key / runtime evidence

This release adds strict root ownership and file-mode checks for the CGI's HMAC signing key and its containing directory. An insecure state returns HTTP 503 rather than using a potentially replaced key. This check is separate from the backend and installer permission checks.

The `scripts/verify_live_readonly.py` diagnostic performs local, read-only integrity and permissions checks and optional saved-challenge/public-TXT comparison. Its output is intentionally redacted and cannot validate authenticated browser behavior or externally observed message authentication. A failing diagnostic must block the stable tag until investigated.

## Browser lifecycle compatibility / advisory

Observed Chrome console warning: `utilities_container.js: [Violation] Permissions policy violation: unload is not allowed in this document.` The RSM WHM template includes no JavaScript, and does not register any `unload` handler. The plugin loads inside the native cPanel/WHM master template, whose upstream assets and browser extensions are outside this source tree. Source attribution requires inspection of the actual script URL on the running server. We intentionally do not add a `Permissions-Policy: unload=...` relaxation or change WHM/cPanel vendor files. This is an advisory unless it causes proven UI functionality problems.
