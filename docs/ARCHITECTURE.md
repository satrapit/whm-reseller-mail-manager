# Architecture and design decisions

**Author:** arsamnet.com · MIT

The plugin has three intentionally separated layers.

1. `cgi/index.cgi` authenticates WHM root, checks ACL and per-form HMAC CSRF, limits form lengths and calls the backend via fixed argv. `templates/rsm/index.tmpl` is loaded through cPanel's supported Template Toolkit. The plugin does not modify cPanel core files.
2. `src/rsm.py` manages root-only SQLite state, uses WHM API `listaccts` for account/owner/recipient, and checks `/var/cpanel/resellers` for eligible reseller identities. Domain ownership policy and fresh DNS ownership are separate from message authentication.
3. `src/dns_inspector.py` and `src/auth_audit.py` perform read-only DNS observations and conditional proposals; `src/dkim_signing.py` owns optional RSM-only keys, public-key export, DNS key match, and limited DKIM signing for fixed RSM content. `src/notify.py` sends only explicitly requested fixed RSM notices, with the recipient obtained from WHM, not from the UI.

## Trust and execution

UI can be used only by WHM actual root. Every mutating action is protected with CSRF and audited. DNS hostnames and IPs are validated; `subprocess.run` is invoked with lists and timeouts, never a shell. SQLite state and DKIM keys must be backed up separately from source code. The domain's DNS authority lives outside this plugin; no DNS writes are performed.

## Open-source portability

New installations start disabled and have no default sender. A global sender must be configured with a legitimate address for the deployer's domain. Existing installs retain their current SQLite settings. External mail services and offsite DNS remain administrator-managed. There are no proprietary service dependencies. Python stdlib, system OpenSSL, system `dig`, and cPanel's own interfaces are used.

## Not implemented

No confirmed supported native iContact `From`/envelope sender override, customer email rewriting, policy enforcement in Exim, SPF recursive evaluation, DNS auto-publishing, mailbox ownership proof, bulk mail, or general-purpose SMTP relay. Do not advertise the application as implementing those features.
