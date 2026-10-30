#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
MODE="${1:---dry-run}"
[[ "$MODE" == "--dry-run" || "$MODE" == "--install" || "$MODE" == "--upgrade" ]] || { echo 'Usage: ./scripts/install.sh --dry-run|--install|--upgrade'; exit 2; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
BASE=/opt/whm-reseller-mail-manager
STATE=/var/lib/whm-reseller-mail-manager
CGI_DIR=/usr/local/cpanel/whostmgr/docroot/cgi/rsm
TEMPLATE_DIR=/usr/local/cpanel/whostmgr/docroot/templates/rsm
REGISTER=/usr/local/cpanel/bin/register_appconfig
APP_CONFIG=/var/cpanel/apps/rsm.conf
ICON_DIR=/usr/local/cpanel/whostmgr/docroot/addon_plugins
[[ "${EUID}" -eq 0 ]] || { echo 'Must run as root'; exit 1; }
# Protect state and ownership material from symlink redirection.
[[ ! -L "$STATE" && ! -L "$STATE/csrf.key" ]] || { echo 'Unsafe state/CSRF symlink'; exit 1; }
[[ ! -e "$STATE" || -d "$STATE" ]] || { echo 'State path is not a directory'; exit 1; }
# Avoid concurrent installs/rollbacks from the same trusted source.
command -v flock >/dev/null || { echo 'flock is required'; exit 1; }
exec 9> /run/lock/whm-rsm-install.lock
flock -n 9 || { echo 'Another RSM installation is in progress'; exit 1; }
for file in /usr/local/cpanel/version /usr/local/cpanel/bin/whmapi1 "$REGISTER" /usr/local/cpanel/bin/unregister_appconfig /usr/bin/python3 /usr/local/cpanel/3rdparty/bin/perl /usr/bin/dig /usr/bin/openssl; do
    [[ -e "$file" ]] || { echo "Missing requirement: $file"; exit 1; }
done
VERSION="$(cat /usr/local/cpanel/version)"
MAJOR="$(printf '%s' "$VERSION" | sed -nE 's/^11\.([0-9]+)\..*/\1/p')"
[[ -n "$MAJOR" && "$MAJOR" -ge 132 ]] || { echo "Unsupported WHM version: $VERSION"; exit 1; }
/usr/bin/python3 - <<'PY'
import sys
assert sys.version_info >= (3,9),'Python 3.9+ is required'
PY
/usr/local/cpanel/3rdparty/bin/perl -I/usr/local/cpanel -MJSON::PP -MDigest::SHA -MIPC::Open3 -MCpanel::Template -e 'exit 0'
[[ -f "$ROOT/templates/rsm/index.tmpl" ]] || { echo 'Missing WHM template: templates/rsm/index.tmpl'; exit 1; }
printf 'WHM version: %s\nSource: %s\nMode: %s\n' "$VERSION" "$ROOT" "$MODE"
[[ "$MODE" != '--dry-run' ]] || { echo 'Preflight passed; no files changed and no services restarted.'; exit 0; }
mkdir -p "$BASE/releases" "$STATE" "$CGI_DIR" "$TEMPLATE_DIR" "$ICON_DIR" /var/cpanel/apps
chmod 0700 "$STATE"
chmod 0755 "$CGI_DIR" "$TEMPLATE_DIR" /var/cpanel/apps
release="$BASE/releases/$(date -u +%Y%m%dT%H%M%SZ)-$$"
old_release=''
if [[ -L "$BASE/app" ]]; then old_release="$(readlink "$BASE/app")"; fi
mkdir -p "$release/src" "$release/cgi" "$release/plugin" "$release/templates"
cp -a "$ROOT/src/." "$release/src/"
cp -a "$ROOT/cgi/." "$release/cgi/"
cp -a "$ROOT/plugin/." "$release/plugin/"
cp -a "$ROOT/templates/." "$release/templates/"
find "$release" -type d -exec chmod 0755 '{}' +
find "$release" -type f -exec chmod 0644 '{}' +
chmod 0755 "$release/cgi/index.cgi" "$release/src/notify.py" "$release/src/rsm.py"
# No executing python from web document root; application source is outside public CGI.
previous_cgi=""
if [[ -f "$CGI_DIR/index.cgi" ]]; then previous_cgi="$release/previous-index.cgi"; cp -p "$CGI_DIR/index.cgi" "$previous_cgi"; fi
previous_template=""
if [[ -f "$TEMPLATE_DIR/index.tmpl" ]]; then
    previous_template="$release/previous-index.tmpl"
    cp -p "$TEMPLATE_DIR/index.tmpl" "$previous_template"
fi
previous_config=""
if [[ -f "$APP_CONFIG" ]]; then
    previous_config="$release/previous-appconfig.conf"
    cp -p "$APP_CONFIG" "$previous_config"
fi
registered_before=0
if [[ -e "$APP_CONFIG" ]]; then registered_before=1; fi
cleanup_on_failure() {
    rc=$?
    if ((rc != 0)); then
        echo 'Install failed, restoring preceding code/registration' >&2
        if [[ -n "$old_release" ]]; then ln -sfn "$old_release" "$BASE/app.restore"; mv -Tf "$BASE/app.restore" "$BASE/app";
        else rm -f "$BASE/app"; fi
        if [[ -n "$previous_cgi" ]]; then cp -p "$previous_cgi" "$CGI_DIR/index.cgi"; else rm -f "$CGI_DIR/index.cgi"; fi
        if [[ -n "$previous_template" ]]; then cp -p "$previous_template" "$TEMPLATE_DIR/index.tmpl"; else rm -f "$TEMPLATE_DIR/index.tmpl"; fi
        if [[ -n "$previous_config" ]]; then "$REGISTER" "$previous_config" || true; fi
        if ((registered_before==0)) && [[ -e "$APP_CONFIG" ]]; then /usr/local/cpanel/bin/unregister_appconfig rsm || true; fi
    fi
}
trap cleanup_on_failure EXIT
ln -s "$release" "$BASE/app.next"
mv -Tf "$BASE/app.next" "$BASE/app"
cp -p "$release/cgi/index.cgi" "$CGI_DIR/index.cgi"
chmod 0755 "$CGI_DIR/index.cgi"
cp -p "$release/templates/rsm/index.tmpl" "$TEMPLATE_DIR/index.tmpl"
chmod 0644 "$TEMPLATE_DIR/index.tmpl"
# CSS is inline; nothing else publicly served. Icon is optional; preinstalled placeholder from package.
if [[ -f "$ROOT/plugin/rsm.png" ]]; then cp -p "$ROOT/plugin/rsm.png" "$ICON_DIR/rsm.png"; chmod 0644 "$ICON_DIR/rsm.png"; fi
"$REGISTER" "$release/plugin/rsm.conf"
if [[ ! -f "$STATE/csrf.key" ]]; then
    /usr/bin/python3 - <<'PY' > "$STATE/csrf.key"
import secrets
print(secrets.token_hex(48))
PY
fi
chmod 0600 "$STATE/csrf.key"
# Force creation of sqlite state as root. Never send any mail during install.
RSM_STATE_DIR="$STATE" /usr/bin/python3 - <<'PY'
import sys
sys.path.insert(0,'/opt/whm-reseller-mail-manager/app/src')
from rsm import connect
connect().close()
PY
printf '%s\n' "${old_release:-NONE}" > "$STATE/previous_release"
chmod 0600 "$STATE/previous_release"
trap - EXIT
echo 'Installed native WHM Template Toolkit interface; verify header/sidebar/footer in root WHM session.'
echo 'WHM may require a cpsrvd restart to refresh the AppConfig UI.'
echo 'No Exim config, customer mail, DNS or native notifications were modified.'
