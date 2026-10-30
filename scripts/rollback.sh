#!/usr/bin/env bash
# Restore code and WHM registration from the previous trusted release.
# IMPORTANT: state/SQLite, DNS ownership, cooldown claims and sent mail are NOT rolled back.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Root required' >&2; exit 1; }
[[ "$#" -eq 1 && "$1" == '--rollback' ]] || { echo 'Usage: scripts/rollback.sh --rollback' >&2; exit 2; }

BASE=/opt/whm-reseller-mail-manager
STATE=/var/lib/whm-reseller-mail-manager
CGI=/usr/local/cpanel/whostmgr/docroot/cgi/rsm/index.cgi
TEMPLATE=/usr/local/cpanel/whostmgr/docroot/templates/rsm/index.tmpl
REGISTER=/usr/local/cpanel/bin/register_appconfig

command -v flock >/dev/null || { echo 'flock required' >&2; exit 1; }
exec 9> /run/lock/whm-rsm-install.lock
flock -n 9 || { echo 'Another RSM lifecycle operation is running' >&2; exit 1; }
[[ ! -L "$STATE" && ! -L "$STATE/previous_release" ]] ||
  { echo 'Unsafe state/rollback symlink' >&2; exit 1; }
[[ -L "$BASE/app" && -f "$STATE/previous_release" && -x "$REGISTER" ]] ||
  { echo 'Current release or previous release record unavailable' >&2; exit 1; }

old=$(cat "$STATE/previous_release")
current=$(readlink "$BASE/app")
for release in "$old" "$current"; do
  [[ "$release" == "$BASE"/releases/* && -d "$release" && ! -L "$release" ]] ||
    { echo 'Invalid release target' >&2; exit 1; }
  for required in "$release/cgi/index.cgi" "$release/plugin/rsm.conf" "$release/templates/rsm/index.tmpl"; do
    [[ -f "$required" && ! -L "$required" ]] ||
      { echo 'Release files missing or unsafe' >&2; exit 1; }
  done
done
[[ "$old" != "$current" ]] || { echo 'No different release to restore' >&2; exit 1; }

restore_current_on_error() {
  rc=$?
  if ((rc != 0)); then
    echo 'Rollback failed; restoring current release code and AppConfig' >&2
    ln -s "$current" "$BASE/app.restore"
    mv -Tf "$BASE/app.restore" "$BASE/app"
    cp -p "$current/cgi/index.cgi" "$CGI" || true
    cp -p "$current/templates/rsm/index.tmpl" "$TEMPLATE" || true
    "$REGISTER" "$current/plugin/rsm.conf" || true
  fi
}
trap restore_current_on_error EXIT

ln -s "$old" "$BASE/app.restore"
mv -Tf "$BASE/app.restore" "$BASE/app"
cp -p "$old/cgi/index.cgi" "$CGI"
cp -p "$old/templates/rsm/index.tmpl" "$TEMPLATE"
"$REGISTER" "$old/plugin/rsm.conf"
printf '%s\n' "$current" > "$STATE/previous_release"
chmod 0600 "$STATE/previous_release"
trap - EXIT
echo "Rolled back code and WHM AppConfig registration. Persistent user state retained."
