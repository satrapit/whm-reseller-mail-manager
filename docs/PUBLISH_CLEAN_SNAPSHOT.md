# Safe public distribution — clean single-commit Git history

## Why a new repository is required

The private engineering repository has existing commits containing personal committer
metadata and, in earlier versions, live sender/domain/IP samples. A new commit that
replaces samples **does not erase** those older Git objects, pull request diffs,
automatically generated GitHub references, or provider caches.

**Never switch the existing internal repository directly to public visibility.**
Keep the private source, review discussions, session screenshots and operational
evidence private. Publishing a single-commit snapshot to a *different, new, empty
repository* avoids exposing the internal history and its contributors.

Official author attribution and MIT LICENSE/NOTICE must remain intact; do not
remove rightful copyright credits. The neutral export committer identity is
only for the distribution snapshot, not a claim about original authorship.

## Preparation and quality gates

1. Review the complete current source tree and all documentation for:
   real email addresses, servers, IPs, credentials, TXT challenges, `cpsess`
   session tokens, screenshots, logs, mail headers and hard-coded client account IDs.
   Only RFC-reserved example emails/domains and documentation IP blocks are allowed
   as sample values. Verify image metadata and other binary files manually.
2. Run tests on the trusted private checkout:

   ```bash
   python3 -m unittest discover -s tests -q
   python3 scripts/audit_public_release.py --history
   bash scripts/install.sh --dry-run
   ```

3. Complete real root/non-root access checks, desktop/mobile UI review, safe
   fallback verification and a staging rollback rehearsal before any stable tag.
4. For a **private rehearsal** of the clean snapshot, run:

   ```bash
   cd /opt/src/whm-reseller-mail-manager
   bash scripts/export_public_snapshot.sh /root/rsm-public-clean
   ```

   The command creates a NEW directory containing a self-contained Git repo with
   **exactly one initial commit**, authored by the neutral
   `RSM Release <release@example.invalid>` test identity; it does not configure
   any remote or publish anything. It fails closed if the strict public audit finds
   non-example email/IP samples, secrets, bad metadata or an unexpected Git state.

5. Confirm the generated snapshot has just one commit and no remotes:

   ```bash
   git -C /root/rsm-public-clean log --oneline --format='%h %an <%ae> %s'
   git -C /root/rsm-public-clean rev-list --count HEAD
   git -C /root/rsm-public-clean remote -v
   python3 /root/rsm-public-clean/scripts/audit_public_release.py --help
   ```

## Publication (only AFTER all gates, on a NEW empty GitHub repository)

Create a NEW empty repository using your GitHub account settings with no generated
README, .gitignore or license. Initially set it to private. Use a name independent
of the existing engineering repository if appropriate. Do not create forks,
mirrors or pull requests importing the old history.

From the clean snapshot checkout **only**, once approved:

```bash
cd /root/rsm-public-clean
python3 scripts/audit_public_release.py --history --public-history
git remote add origin git@github.com:YOUR_ORG/YOUR_NEW_PUBLIC_REPO.git
git push -u origin main
```

Verify the new remote's only commit, files, Actions and GitHub release assets.
After passing manual repository review, change *only the new distribution repo*
to Public. Make the final `v1.0.0` annotated/signed tag and release notes
from the newly reviewed public snapshot. Sign with an approved release key;
the automation does not invent or generate a signature.

**Do not force-push or rewrite the original private repository** without a separate,
explicit review of all clones, branches, tags and pull request references.
The clean export must not include private WHM screenshot filenames or binaries.

## Important boundaries

- This process does not revoke a previously exposed WHM session. Log out of
  affected WHM browser sessions and avoid publishing screenshots with URL IDs.
- Scanner results are heuristic. Human review of files and archived assets is required.
- The exporter does not run WHM production changes or send emails.
- Distribution contains only source, not the real state.sqlite3, CSRF key, or DKIM key.
