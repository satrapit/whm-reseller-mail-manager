#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo 'Root required'; exit 1; }
[[ "$#" -ge 1 && "$#" -le 2 && "${1:-}" == '--uninstall' ]] ||
  { echo 'Usage: scripts/uninstall.sh --uninstall [--purge-data]' >&2; exit 2; }
[[ "$#" -eq 1 || "${2:-}" == '--purge-data' ]] ||
  { echo 'Unknown uninstall option' >&2; exit 2; }
command -v flock >/dev/null || { echo 'flock required' >&2; exit 1; }
exec 9> /run/lock/whm-rsm-install.lock
flock -n 9 || { echo 'Another RSM lifecycle operation is running' >&2; exit 1; }
[[ ! -L /var/lib/whm-reseller-mail-manager ]] ||
  { echo 'Unsafe state symlink' >&2; exit 1; }
BASE=/opt/whm-reseller-mail-manager
STATE=/var/lib/whm-reseller-mail-manager
rm -f /usr/local/cpanel/whostmgr/docroot/cgi/rsm/index.cgi
rmdir /usr/local/cpanel/whostmgr/docroot/cgi/rsm 2>/dev/null || true
rm -f /usr/local/cpanel/whostmgr/docroot/templates/rsm/index.tmpl
rmdir /usr/local/cpanel/whostmgr/docroot/templates/rsm 2>/dev/null || true
rm -f /usr/local/cpanel/whostmgr/docroot/addon_plugins/rsm.png
if [[ -e /var/cpanel/apps/rsm.conf ]]; then
    /usr/local/cpanel/bin/unregister_appconfig rsm
fi
# No other plugin's files, Exim configuration or DNS records are touched.
if [[ -d "$BASE" && ! -L "$BASE" ]]; then rm -rf -- "$BASE"; fi
if [[ "${2:-}" == '--purge-data' ]]; then
    if [[ -d "$STATE" && ! -L "$STATE" ]]; then rm -rf -- "$STATE"; fi
    echo 'RSM data purged.'
else
    echo "RSM data retained in $STATE"
fi
echo 'Uninstalled; cpsrvd restart may be required to refresh WHM navigation.'
