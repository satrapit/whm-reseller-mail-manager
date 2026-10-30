# Contributing

Thank you for improving the **WHM Reseller System Mail Manager**, developed by [arsamnet.com](https://arsamnet.com) and released under the MIT License.

## Before contributing

Read [Architecture](docs/ARCHITECTURE.md), [DNS authentication](docs/DNS_AUTHENTICATION.md) and [Security](SECURITY.md). Prefer a concise issue with reproducible steps, cPanel/WHM version, expected behavior and sanitized logs before large changes. Never paste production ownership tokens, SSH keys, DKIM private keys, recipient addresses or session URLs.

## Development

- Python 3.9+ with stdlib only for the application and test suite; system OpenSSL is used for optional RSM-only DKIM signing.
- Avoid monkey-patching cPanel internals, changing Exim templates or modifying customer's mail.
- Keep operations safe by default: no send unless `--send`, no DNS writes, and separate DNS publication from verification.
- Handle untrusted inputs with validation, bounded reads, subprocess argument arrays, timeouts, output escaping and root-only authorization.
- Add unit tests for positive/negative cases, and document exact security / behavior limitations.

Run:

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q src tests
bash -n scripts/*.sh
```

On a real WHM staging server, also run the bundled Perl syntax check and a **single authorized** end-to-end notice test to a mailbox under your control; inspect email authentication headers.

Submit focused PRs describing design, tests, risks and rollback. Changes to compatibility, security boundaries or DKIM must include corresponding documentation. Contributors retain copyright to their contributions and agree they are contributed under MIT.
