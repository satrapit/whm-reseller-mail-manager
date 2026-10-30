"""Static regression tests for native WHM UI integration and safe deployment."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WHMNativeInterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cgi = (ROOT / 'cgi/index.cgi').read_text(encoding='utf-8')
        cls.tmpl = (ROOT / 'templates/rsm/index.tmpl').read_text(encoding='utf-8')
        cls.installer = (ROOT / 'scripts/install.sh').read_text(encoding='utf-8')
        cls.rollback = (ROOT / 'scripts/rollback.sh').read_text(encoding='utf-8')
        cls.uninstall = (ROOT / 'scripts/uninstall.sh').read_text(encoding='utf-8')

    def test_native_whm_template_wrapper_and_shell(self):
        self.assertIn("WRAPPER 'master_templates/master.tmpl'", self.tmpl)
        self.assertIn("theme = 'bootstrap'", self.tmpl)
        self.assertIn('hide_navigation = 0', self.tmpl)
        self.assertIn('hide_header = 0', self.tmpl)
        self.assertIn('[% END %]', self.tmpl)
        self.assertNotIn('<!doctype html>', self.cgi.lower())
        self.assertNotIn('<html', self.cgi.lower())

    def test_contextual_forms_and_human_readable_diagnostics(self):
        self.assertIn('<h1>Reseller System Mail Manager</h1>', self.tmpl)
        self.assertIn('Save a sender address to generate the TXT verification record.', self.tmpl)
        self.assertIn('disabled>Verify public DNS</button>', self.tmpl)
        self.assertIn('rsm.preview_result.reason | html', self.tmpl)
        self.assertIn('rsm.dns_result.suggested | html', self.tmpl)
        self.assertIn('rsm.form_selector | html', self.tmpl)
        self.assertNotIn('value="hostmaster@example.org"', self.tmpl)
        self.assertIn('name="selector"', self.tmpl)
        self.assertIn('name="action" value="inspect"', self.tmpl)
        self.assertIn('name="action" value="preview"', self.tmpl)

    def test_reseller_dns_audit_isolated_to_own_saved_email(self):
        self.assertIn('name="action" value="audit_reseller"', self.tmpl)
        self.assertIn('name="action" value="provision_reseller_dkim"', self.tmpl)
        self.assertIn('rsm.audit_target == reseller.reseller', self.tmpl)
        self.assertIn('rsm.audit_result.spf.status | html', self.tmpl)
        self.assertIn('rsm.audit_result.dmarc.status | html', self.tmpl)
        self.assertIn('rsm.audit_result.dkim.proposal.value | html', self.tmpl)
        self.assertIn('audit_reseller|provision_reseller_dkim', self.cgi)
        self.assertIn("audit_result  =>", self.cgi)

    def test_spacing_wrapper_and_challenge_safety(self):
        # Regression: auth panel was outside the padded reseller body.
        self.assertIn("rsm-reseller-body { padding: 22px 24px 24px;", self.tmpl)
        self.assertIn("Show current ownership TXT value", self.tmpl)
        self.assertIn("rsm-general-ownership", self.tmpl)
        self.assertIn('name="action" value="verify_general"', self.tmpl)
        self.assertIn('name="action" value="rotate_challenge"', self.tmpl)
        self.assertIn("rsm-rotate-form", self.tmpl)
        self.assertIn("WHM security session required", self.cgi)
        self.assertIn("return {} if exists $kv{$k}", self.cgi)

    def test_runtime_csrf_key_must_be_private_root_owned_regular_file(self):
        self.assertIn("sub safe_root_path", self.cgi)
        self.assertIn("safe_root_path($state_dir,'directory',0700)", self.cgi)
        self.assertIn("safe_root_path($key_file,'file',0600)", self.cgi)
        self.assertIn("Plugin security state unavailable", self.cgi)

    def test_readonly_live_diagnostic_documented(self):
        script = ROOT / 'scripts' / 'verify_live_readonly.py'
        self.assertTrue(script.is_file())
        self.assertIn('mode=ro', script.read_text(encoding='utf-8'))
        self.assertIn('No real browser session/ACL/CSRF workflow', script.read_text(encoding='utf-8'))

    def test_dashboard_policy_status_is_mutually_exclusive(self):
        self.assertIn("my ($ready,$needs_dns,$paused,$unconfigured,$covered_accounts)", self.cgi)
        self.assertIn("if (!$entry->{email})", self.cgi)
        self.assertIn("elsif (!$entry->{verified})", self.cgi)
        self.assertIn("elsif (!$entry->{enabled})", self.cgi)
        self.assertIn("else { $ready++;", self.cgi)
        self.assertIn("action_needed => $needs_dns+$paused+$unconfigured", self.cgi)
        self.assertIn("covered_accounts => $covered_accounts", self.cgi)
        for state in ("rsm.ready", "rsm.needs_dns", "rsm.paused",
                      "rsm.unconfigured", "rsm.covered_accounts"):
            self.assertIn(state, self.tmpl)

    def test_guided_onboarding_has_no_browser_lifecycle_script(self):
        self.assertIn("What should I do next?", self.tmpl)
        self.assertIn("RSM configuration status", self.tmpl)
        self.assertIn("Next: Verify DNS ownership", self.tmpl)
        self.assertIn("Next: Enable this policy", self.tmpl)
        self.assertIn("Next: Save a sender", self.tmpl)
        self.assertIn("Ownership verified; sender policy enabled", self.tmpl)
        self.assertIn('id="rsm-general-ownership"', self.tmpl)
        self.assertNotIn("utilities_container.js", self.tmpl)
        self.assertNotIn("addEventListener('unload'", self.tmpl)
        self.assertNotIn('addEventListener("unload"', self.tmpl)
        self.assertNotIn("<script", self.tmpl)

    def test_each_visible_input_has_help_and_accessible_descriptions(self):
        import re
        visible = [tag for tag in re.findall(r"<input\b[^>]*>", self.tmpl)
                   if 'type="hidden"' not in tag]
        self.assertGreaterEqual(len(visible), 12)
        for tag in visible:
            self.assertIn('title=', tag, tag)
        editable = [tag for tag in visible if 'type="checkbox"' not in tag]
        self.assertEqual(len(editable), 7)
        for tag in editable:
            self.assertIn('aria-describedby=', tag, tag)
        self.assertIn("rsm-help-preview-account", self.tmpl)
        self.assertIn("rsm-help-egress-", self.tmpl)

    def test_auth_audit_submit_does_not_float_below_helper_text(self):
        self.assertIn('.rsm-auth-form {display:block;', self.tmpl)
        self.assertIn('.rsm-auth-form button[type="submit"] {margin-top:12px}', self.tmpl)
        self.assertNotIn('.rsm-auth-form {display:flex;', self.tmpl)

    def test_existing_fallback_sender_has_clear_migration_guidance(self):
        self.assertIn('A fallback address is already saved, but no DNS ownership challenge exists yet', self.tmpl)
        self.assertIn('Save global settings', self.tmpl)
        self.assertIn('Until then, fallback sending is blocked', self.tmpl)
        self.assertIn('verified reseller rules are unaffected', self.tmpl)

    def test_cgi_separates_dns_and_preview_results(self):
        self.assertIn("dns_type eq 'inspect'", self.cgi)
        self.assertIn("dns_type eq 'preview'", self.cgi)
        self.assertIn('preview_result', self.cgi)
        self.assertIn('form_account', self.cgi)

    def test_cgi_uses_whm_template_engine(self):
        self.assertIn('use Cpanel::Template ();', self.cgi)
        self.assertIn("Cpanel::Template::process_template('whostmgr'", self.cgi)
        self.assertIn("template_file => 'rsm/index.tmpl'", self.cgi)
        self.assertIn("REMOTE_USER", self.cgi)
        self.assertIn("Whostmgr::ACLS::checkacl('all')", self.cgi)
        self.assertNotIn("default-src 'none'", self.cgi)

    def test_template_escapes_dynamic_output_and_keeps_csrf(self):
        self.assertIn('rsm.flash | html', self.tmpl)
        self.assertIn('rsm.csrf | html', self.tmpl)
        self.assertIn('reseller.challenge_value | html', self.tmpl)
        self.assertIn('rsm.dns_output | html', self.tmpl)
        self.assertIn('event.result | html', self.tmpl)
        self.assertIn('name="csrf"', self.tmpl)
        self.assertIn('name="action" value="save_reseller"', self.tmpl)
        self.assertIn('name="action" value="verify"', self.tmpl)

    def test_templates_participate_in_install_upgrade_rollback_and_uninstall(self):
        self.assertIn('cp -a "$ROOT/templates/." "$release/templates/"', self.installer)
        self.assertIn('cp -p "$release/templates/rsm/index.tmpl" "$TEMPLATE_DIR/index.tmpl"', self.installer)
        self.assertIn('previous_template', self.installer)
        self.assertIn('"$old/templates/rsm/index.tmpl"', self.rollback)
        self.assertIn('rm -f /usr/local/cpanel/whostmgr/docroot/templates/rsm/index.tmpl', self.uninstall)

    def test_rollback_re_registers_previous_whm_appconfig(self):
        self.assertIn('"$REGISTER" "$old/plugin/rsm.conf"', self.rollback)
        self.assertIn('"$REGISTER" "$current/plugin/rsm.conf"', self.rollback)
        self.assertIn('flock -n 9', self.rollback)
        self.assertIn('flock -n 9', self.uninstall)
        self.assertIn('trap restore_current_on_error EXIT', self.rollback)

    def test_isolated_lifecycle_simulation_not_on_live_whm(self):
        root = ROOT / 'tests' / 'lifecycle'
        dockerfile = (root / 'Dockerfile').read_text(encoding='utf-8')
        harness = (root / 'run.sh').read_text(encoding='utf-8')
        workflow = (ROOT / '.github' / 'workflows' / 'tests.yml').read_text(encoding='utf-8')
        self.assertIn('python:3.11-slim-bookworm', dockerfile)
        self.assertIn('Refusing to touch an existing WHM environment', harness)
        self.assertIn('simulated post-register initialization failure', harness)
        self.assertIn('Uninstall preserving customer data', harness)
        self.assertIn('LIFECYCLE SIMULATION: ALL PASS', harness)
        self.assertIn('docker run --rm --network none', workflow)
        self.assertIn(':/source:ro', workflow)

    def test_lifecycle_shell_scripts_are_executable(self):
        # GitHub runners check out the repository with Git's recorded file modes.
        # A syntax-only shell check cannot detect loss of executable permissions.
        for name in ('install.sh', 'upgrade.sh', 'rollback.sh', 'uninstall.sh'):
            with self.subTest(script=name):
                path = ROOT / 'scripts' / name
                self.assertTrue(path.stat().st_mode & 0o111,
                                f'{name} lost its executable bit in Git')

    def test_upgrade_invokes_bash_explicitly(self):
        upgrade = (ROOT / 'scripts/upgrade.sh').read_text(encoding='utf-8')
        self.assertIn('exec bash "$ROOT/install.sh" --upgrade', upgrade)


if __name__ == '__main__':
    unittest.main()
