# RSM 1.0.0 — Supported integrations and feasibility

This document describes the **current prepared 1.0.0 source**, not a
promise of future integrations. Official cPanel/WHM AppConfig registration,
WHM ACLs, the WHM accounts/reseller roster and local Exim submission
form the supported integration surface. RSM intentionally does not modify
cPanel core, Exim routers, Dovecot, native notification templates or
customer SMTP deliveries.

## Coverage

| Event or operation | Supported by RSM 1.0.0 | Boundary |
| --- | --- | --- |
| Root-only WHM management page | Yes | Requires actual root WHM session, ACL and CSRF |
| Reseller sender policy based on current WHM ownership | Yes | Verified DNS ownership and explicit enablement |
| Read-only SPF/DMARC guidance | Yes | DNS-only diagnostics, not receiver-side pass |
| Opt-in local DKIM for RSM notice | Yes | Independent RSM selector, root-only private key |
| Root-initiated RSM informational account notice | Yes | Verified policy, authoritative account contact, explicit `--send` |
| Per-account 10-minute notice throttling | Yes | Only RSM-owned notices, not all customer mail |
| Native WHM/cPanel iContact sender override | **No** | No approved interception mechanism implemented |
| cPanel security/quota/account notifications | **No** | Core notification flow left unchanged |
| Customer PHP mail, WordPress, WooCommerce or SMTP | **No** | No sender rewriting or Exim modification |
| External authenticated SMTP relay | **No** | Local Exim only, relay remains infrastructure concern |
| Guaranteed Gmail/Inbox placement | **No** | Depends on receiver filtering and reputation |

## Acceptance evidence

The operational RC pilot on a licensed WHM 11.138 host passed 22/22
read-only diagnostics and safely delivered one RSM-owned notice to an
independent receiving mail server using TLS; its DKIM was validated by the
receiver and the message was delivered via LMTP. This does **not** prove
receiver SPF=pass or DMARC=pass. Root-only CGI denial was operator-observed
for an actual non-root reseller; the exact HTTP response was not logged.

The code lifecycle was tested with offline mocked WHM components in Docker
and can restore prior CGI/template/AppConfig files and retain state. No
separate licensed staging WHM was available for destructive uninstall or
rollback tests. See [release acceptance](RELEASE_ACCEPTANCE.md).

## Future work (NOT part of 1.0.0)

Native cPanel/iContact sender modification is only feasible if a stable,
vendor-supported hook can be demonstrated on actual WHM versions and
tested for header+envelope identity, tenant isolation and rollback. Do not
implement such changes by patching cPanel vendor code or rewriting Exim
globally. Future optional work includes full recursive SPF diagnostics,
external SMTP provider integration, expanded delivery telemetry, repeated
real-world authentication tests and a licensed staging compatibility
matrix. These capabilities are not advertised as delivered in 1.0.0.
