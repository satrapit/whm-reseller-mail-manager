#!/usr/bin/env bash
# Build a separate clean-history distribution checkout from the APPROVED RC HEAD.
# Do NOT force-push or publish the original private internal repository.
set -Eeuo pipefail
umask 077
if [[ "$#" -ne 1 || -z "${1:-}" ]]; then
  echo "Usage: bash scripts/export_public_snapshot.sh /root/rsm-public-clean" >&2
  exit 2
fi
command -v git >/dev/null || { echo 'git required' >&2; exit 1; }
command -v tar >/dev/null || { echo 'tar required' >&2; exit 1; }
command -v python3 >/dev/null || { echo 'python3 required' >&2; exit 1; }
root="$(git rev-parse --show-toplevel)"
[[ "$(pwd -P)" == "$root" ]] || { echo 'Run from repository root' >&2; exit 1; }
[[ -z "$(git status --porcelain)" ]] || { echo 'Refusing dirty source worktree' >&2; exit 1; }
version="$(cat VERSION)"
[[ "$version" == "1.0.0" || "$version" == 1.0.0-rc* ]] || { echo 'Expected 1.0.0 candidate or final source' >&2; exit 1; }
dest="$1"
[[ "$dest" = /* && "$dest" != / && "$dest" != "$root" ]] ||
  { echo 'Destination must be a new absolute path outside the source' >&2; exit 1; }
[[ ! -e "$dest" && ! -L "$dest" ]] ||
  { echo 'Destination already exists; refusing to overwrite' >&2; exit 1; }
mkdir -m 700 -- "$dest"
# Only committed files, no .git, no private history, no local sqlite/keys/credentials.
git archive --format=tar HEAD | tar -xf - -C "$dest"
(
  cd "$dest"
  git init -q --initial-branch=main
  git -c user.name="RSM Release" -c user.email="release@example.invalid" \
      -c commit.gpgsign=false add -A
  git -c user.name="RSM Release" -c user.email="release@example.invalid" \
      -c commit.gpgsign=false commit -q -m "Initial public source snapshot of RSM $version"
  # Scan all available objects, sanitized current content, authors and committer metadata.
  python3 scripts/audit_public_release.py --history --public-history
  test "$(git rev-list --count HEAD)" = 1
  test "$(git branch --show-current)" = main
)
echo "CLEAN SNAPSHOT CREATED: $dest"
echo "One new neutral-identity commit; NO remote was configured."
echo "REVIEW the snapshot manually and push ONLY to a NEW EMPTY repository."
