# Deploy via GitHub SSH (CloudLinux 9 / WHM)

This repository is **private**. Clone using a dedicated **read-only GitHub deploy key**. Perform a dry run first; RSM is a root-only management and notification plugin, not a native cPanel iContact sender override. Application source and credentials should never be served from the public document root.

## 1. Generate a dedicated key on the WHM host

```bash
sudo -i
install -d -m 700 /root/.ssh
ssh-keygen -t ed25519 -f /root/.ssh/whm_reseller_mail_manager_ed25519 -C 'whm-reseller-mail-manager-deploy' -N ''
chmod 600 /root/.ssh/whm_reseller_mail_manager_ed25519
cat /root/.ssh/whm_reseller_mail_manager_ed25519.pub
```

In GitHub repository **Settings → Deploy keys → Add deploy key**, paste the **public `.pub`** key. Keep **Allow write access** unchecked. Never paste the private key into GitHub or a ticket.

## 2. Pin GitHub host key and configure an SSH alias

Fetch host keys, then compare their fingerprints with the values independently published by GitHub before accepting them. Do not trust `ssh-keyscan` output blindly.

```bash
ssh-keyscan -t ed25519 github.com > /root/.ssh/github.com.known_hosts.pending
ssh-keygen -lf /root/.ssh/github.com.known_hosts.pending -E sha256
# Verify the result against https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
cat /root/.ssh/github.com.known_hosts.pending >> /root/.ssh/known_hosts
chmod 600 /root/.ssh/known_hosts
```

Create `/root/.ssh/config` with mode `600`:

```sshconfig
Host github-rsm
    HostName github.com
    User git
    IdentityFile /root/.ssh/whm_reseller_mail_manager_ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile /root/.ssh/known_hosts
```

Test:

```bash
ssh -T git@github-rsm
```

GitHub may report successful authentication with an exit status of 1 because shell access is not provided; this is normal.

## 3. Clone, test and preflight

```bash
install -d -m 750 /opt/src
cd /opt/src
git clone git@github-rsm:YOUR_ORG/YOUR_PRIVATE_RSM_REPOSITORY.git
cd whm-reseller-mail-manager
python3 -m unittest discover -s tests -v
bash scripts/install.sh --dry-run
```

**Before installing:** prefer a separate staging WHM. If only one licensed operational WHM exists, run the documented preflight and read-only checks, take a root-only verified backup of SQLite/CSRF/DKIM state, record the Exim checksum, schedule a maintenance window, obtain explicit administrator approval, and do not attempt destructive rollback/uninstall testing on the live host. An isolated Docker lifecycle simulation is not a substitute for real WHM staging. For a new, explicitly approved installation run `bash scripts/install.sh --install`. The installation copies to `/opt/whm-reseller-mail-manager`, installs the CGI entrypoint and registers with AppConfig. See `README.md`, `docs/OPERATIONS.md`, `docs/SECURITY.md` and `docs/FEASIBILITY.md`.

## Updates

```bash
cd /opt/src/whm-reseller-mail-manager
git pull --ff-only
python3 -m unittest discover -s tests -v
bash scripts/install.sh --dry-run
# After staging validation, apply through the documented upgrade path.
```

**Scope reminder:** RSM does not rewrite the sender of native cPanel notifications or Exim customer mail; changes to production email flow remain out of scope until separately validated.


## Repair WHM navigation 404 caused by a duplicated /cgi/ prefix

On WHM 11.138, a menu link such as `/cpsess.../cgi//cgi/rsm/index.cgi`
indicates that `entryurl` was set to `/cgi/rsm/index.cgi`.
The registered `url` remains `/cgi/rsm/index.cgi`; **only**
`entryurl` should be `rsm/index.cgi`.

For an already installed instance, this is an **AppConfig-only repair**;
do not rerun `install.sh --install`, edit Exim, or replace the CGI script:

```bash
cd /opt/src/whm-reseller-mail-manager
git pull --ff-only
python3 -m unittest discover -s tests -v
install -d -m 700 /root/rsm-release-backup
cp -p /var/cpanel/apps/rsm.conf /root/rsm-release-backup/rsm.conf.before-entryurl-fix
/usr/local/cpanel/bin/register_appconfig "$PWD/plugin/rsm.conf"
grep -E '^(url|entryurl)=' /var/cpanel/apps/rsm.conf
# Only if registration succeeds and both paths are correct:
/usr/local/cpanel/scripts/restartsrv_cpsrvd
```

Expected:
```text
url=/cgi/rsm/index.cgi
entryurl=rsm/index.cgi
```

Log out of WHM, start a fresh root session, and open the menu link.
If the page then returns 403, 500, or 404, stop and inspect the new menu
URL and the `/usr/local/cpanel/logs/error_log` excerpt; do not
repeat the service restart. To roll back **only this repair**, run
`register_appconfig /root/rsm-release-backup/rsm.conf.before-entryurl-fix`
and restart `cpsrvd`. This repair does not install or send any mail.
