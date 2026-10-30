#!/usr/bin/env bash
# DISPOSABLE CONTAINER ONLY. Simulated WHM tooling; never run on production.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Container root required' >&2; exit 1; }
[[ -f /source/scripts/install.sh ]] || { echo 'Mount source at /source:ro' >&2; exit 1; }
[[ ! -e /usr/local/cpanel/version ]] || { echo 'Refusing to touch an existing WHM environment' >&2; exit 1; }
[[ ! -e /opt/whm-reseller-mail-manager && ! -e /var/lib/whm-reseller-mail-manager ]] ||
  { echo 'Refusing pre-existing plugin/state paths' >&2; exit 1; }

BASE=/opt/whm-reseller-mail-manager
STATE=/var/lib/whm-reseller-mail-manager
CGI=/usr/local/cpanel/whostmgr/docroot/cgi/rsm/index.cgi
TEMPLATE=/usr/local/cpanel/whostmgr/docroot/templates/rsm/index.tmpl
CONF=/var/cpanel/apps/rsm.conf
mkdir -p /usr/local/cpanel/bin /usr/local/cpanel/3rdparty/bin /var/cpanel/apps /run/lock
printf '%s%s\n' '11.138.' '0.19' > /usr/local/cpanel/version
# No real WHM, Exim, email transport, DNS changes or network calls exist here.
cat > /usr/local/cpanel/bin/whmapi1 <<'SH'
#!/bin/sh
exit 1
SH
cat > /usr/local/cpanel/3rdparty/bin/perl <<'SH'
#!/bin/sh
exit 0
SH
cat > /usr/local/cpanel/bin/register_appconfig <<'SH'
#!/bin/sh
set -eu
cp "$1" /var/cpanel/apps/rsm.conf
SH
cat > /usr/local/cpanel/bin/unregister_appconfig <<'SH'
#!/bin/sh
set -eu
test "$1" = rsm
rm -f /var/cpanel/apps/rsm.conf
SH
chmod 0755 /usr/local/cpanel/bin/{whmapi1,register_appconfig,unregister_appconfig} /usr/local/cpanel/3rdparty/bin/perl

if [[ ! -x /usr/bin/python3 ]]; then ln -s "$(command -v python3)" /usr/bin/python3; fi
for required in /usr/bin/dig /usr/bin/openssl; do
  if [[ ! -e "$required" ]]; then
    printf '#!/bin/sh\nexit 0\n' > "$required"
    chmod 0755 "$required"
  fi
done
command -v flock >/dev/null || { echo 'flock missing in test container' >&2; exit 1; }
pass(){ echo "PASS: $*"; }
assert_same(){
  cmp -s "$1" "$2" || { echo "Mismatch: $1 vs $2" >&2; exit 1; }
}
assert_canary(){
  /usr/bin/python3 - <<'PY'
import sqlite3
with sqlite3.connect('/var/lib/whm-reseller-mail-manager/state.sqlite3') as db:
    assert db.execute("SELECT value FROM settings WHERE key='staging_canary'").fetchone()[0]=='unchanged'
PY
}
echo '--- Clean installation ---'
bash /source/scripts/install.sh --dry-run
test ! -e "$BASE"
bash /source/scripts/install.sh --install
test -L "$BASE/app" && test -f "$CGI" && test -f "$TEMPLATE" && test -f "$CONF"
test -f "$STATE/state.sqlite3" && test -f "$STATE/csrf.key"
test "$(stat -c '%a' "$STATE/csrf.key")" = 600
test "$(stat -c '%a' "$STATE/state.sqlite3")" = 600
first=$(readlink "$BASE/app")
test "$(cat "$STATE/previous_release")" = NONE
assert_same "$first/cgi/index.cgi" "$CGI"
assert_same "$first/templates/rsm/index.tmpl" "$TEMPLATE"
assert_same "$first/plugin/rsm.conf" "$CONF"
# Persistent state canary: must survive all code lifecycle operations.
python3 - <<'PY'
import sqlite3
with sqlite3.connect('/var/lib/whm-reseller-mail-manager/state.sqlite3') as db:
    db.execute("INSERT INTO settings(key,value) VALUES (?,?)",('staging_canary','unchanged'))
PY
key_digest=$(sha256sum "$STATE/csrf.key" | cut -d' ' -f1)
pass 'clean install, DB and root permissions'

# A test-only next version has distinguishable CGI, template and AppConfig.
mkdir -p /tmp/rsm-next-source
cp -a /source/. /tmp/rsm-next-source/
printf '\n# lifecycle test: next CGI\n' >> /tmp/rsm-next-source/cgi/index.cgi
printf '\n<!-- lifecycle test: next template -->\n' >> /tmp/rsm-next-source/templates/rsm/index.tmpl
sed -i 's/searchtext=/searchtext=staging-next /' /tmp/rsm-next-source/plugin/rsm.conf

echo '--- Upgrade ---'
bash /tmp/rsm-next-source/scripts/upgrade.sh
second=$(readlink "$BASE/app")
test "$first" != "$second"
assert_same "$second/cgi/index.cgi" "$CGI"
assert_same "$second/templates/rsm/index.tmpl" "$TEMPLATE"
assert_same "$second/plugin/rsm.conf" "$CONF"
test "$(cat "$STATE/previous_release")" = "$first"
test "$(sha256sum "$STATE/csrf.key" | cut -d' ' -f1)" = "$key_digest"
assert_canary
pass 'upgrade preserves state and deploys code, template and registration'

echo '--- Previous-release rollback ---'
bash /source/scripts/rollback.sh --rollback
test "$(readlink "$BASE/app")" = "$first"
test "$(cat "$STATE/previous_release")" = "$second"
assert_same "$first/cgi/index.cgi" "$CGI"
assert_same "$first/templates/rsm/index.tmpl" "$TEMPLATE"
assert_same "$first/plugin/rsm.conf" "$CONF"
assert_canary
pass 'rollback restores app, CGI, template AND WHM AppConfig'

echo '--- Injected post-registration upgrade failure ---'
cp -a /tmp/rsm-next-source /tmp/rsm-failing-source
printf '\nraise RuntimeError("simulated post-register initialization failure")\n' >> /tmp/rsm-failing-source/src/rsm.py
if bash /tmp/rsm-failing-source/scripts/upgrade.sh > /tmp/rsm-failure.log 2>&1; then
  echo 'Upgrade should have failed on simulated init failure' >&2
  exit 1
fi
test "$(readlink "$BASE/app")" = "$first"
test "$(cat "$STATE/previous_release")" = "$second"
assert_same "$first/cgi/index.cgi" "$CGI"
assert_same "$first/templates/rsm/index.tmpl" "$TEMPLATE"
assert_same "$first/plugin/rsm.conf" "$CONF"
assert_canary
pass 'failed upgrade restores previous runtime and registration'

echo '--- Insecure key link must be rejected ---'
mv "$STATE/csrf.key" "$STATE/csrf.key.original"
ln -s "$STATE/csrf.key.original" "$STATE/csrf.key"
if bash /source/scripts/install.sh --dry-run >/tmp/rsm-denied.log 2>&1; then
  echo 'Symlinked CSRF key must fail closed' >&2
  exit 1
fi
rm "$STATE/csrf.key"
mv "$STATE/csrf.key.original" "$STATE/csrf.key"
pass 'untrusted key symlink rejected'

echo '--- Uninstall preserving customer data ---'
bash /source/scripts/uninstall.sh --uninstall
test ! -e "$BASE" && test ! -e "$CGI" && test ! -e "$TEMPLATE" && test ! -e "$CONF"
test -f "$STATE/state.sqlite3" && test -f "$STATE/csrf.key"
assert_canary
test "$(sha256sum "$STATE/csrf.key" | cut -d' ' -f1)" = "$key_digest"
pass 'uninstall removes code and registration but retains state'

echo '--- Reinstall with retained private state ---'
bash /source/scripts/install.sh --install
assert_canary
test "$(sha256sum "$STATE/csrf.key" | cut -d' ' -f1)" = "$key_digest"
pass 'reinstall preserves existing SQLite data and CSRF key'
echo 'LIFECYCLE SIMULATION: ALL PASS (isolated container; NOT a live WHM acceptance test)'
