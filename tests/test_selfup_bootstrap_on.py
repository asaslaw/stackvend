import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""SELFUP-BOOTSTRAP-ON (owner 11-03): scripts/bootstrap.sh writes a NEW install with the self-update upgrader on.

A new install (no vars file before this run) gets `enable_platform_upgrader = true`, so the "Update StackVend" upgrader
(infra/platform/platform_upgrader.tf) is created by its first apply. The variables.tf default stays false, so an
existing install is unchanged. `bootstrap.sh --overwrite-tfvars` on an EXISTING vars file carries over that file's own
enable_platform_upgrader exactly (real HCL parser, sv_tfvar; an absent key = the variables.tf default false), so
regenerating the file never switches an install. A value it cannot read is refused (BOOTSTRAP_UPGRADER_UNREADABLE)
with the file unchanged. Same shape as SAT-46's runner identity carry-over (tests/test_fd7l_bootstrap_per_workload.py);
the behavioural tests run the real bootstrap.sh under lane 5's hermetic harness (stubbed gcloud/tofu; only
`tofu console` is the real engine) and skip without OpenTofu.
"""
import glob
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)
import test_fd7l_bootstrap_per_workload as SAT46  # noqa: E402  (module import only)

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PROJ = L5.PROJ
UPGRADER_LINE = "enable_platform_upgrader           = {}"


def _bootstrap():
    with open(os.path.join(REPO, "scripts", "bootstrap.sh"), encoding="utf-8") as f:
        return f.read()


class TestBootstrapHeredocWritesTheUpgrader(unittest.TestCase):
    def test_heredoc_writes_the_carried_value(self):
        boot = _bootstrap()
        start = boot.index('cat <<EOF > "${TFVARS_PATH}"')
        heredoc = boot[start:]
        heredoc = heredoc[:heredoc.index("\nEOF\n")]
        self.assertIn(UPGRADER_LINE.format("${SV_ENABLE_PLATFORM_UPGRADER}"), heredoc)
        self.assertEqual(heredoc.count("enable_platform_upgrader "), 1)
        # the companion switches keep their variables.tf defaults (kill switch off, console approval on)
        self.assertNotIn("platform_upgrade_trigger_disabled", heredoc)
        self.assertNotIn("platform_upgrade_approval_required", heredoc)
        # the new-install value is the default of the shell variable, set before the heredoc
        self.assertIn('SV_ENABLE_PLATFORM_UPGRADER="true"\n', boot[:start])

    def test_heredoc_line_is_aligned_with_its_neighbours(self):
        boot = _bootstrap()
        heredoc = boot[boot.index('cat <<EOF > "${TFVARS_PATH}"'):]
        heredoc = heredoc[:heredoc.index("\nEOF\n")]
        cols = [m.start(1) - m.start(0) for m in re.finditer(r"^(?:tf_runner_identity|tf_runner_dedicated_sa|"
                                                             r"enable_platform_upgrader) +(=)", heredoc, re.M)]
        self.assertEqual(len(cols), 3, cols)
        self.assertEqual(len(set(cols)), 1, cols)

    def test_variables_tf_default_stays_false(self):
        with open(os.path.join(REPO, "infra", "platform", "variables.tf"), encoding="utf-8") as f:
            tf = f.read()
        block = tf[tf.index('variable "enable_platform_upgrader"'):]
        block = block[:block.index("\n}\n")]
        self.assertRegex(block, r"\n\s*default\s*=\s*false\s*(\n|$)")


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestBootstrapUpgraderCarryOver(SAT46._BootIap):
    """new install -> true; --overwrite-tfvars -> the existing file's value, exactly (absent = false)."""

    def existing(self, extra):
        content = f'project_id = "{PROJ}"\nregion     = "us-central1"\n' + extra
        with open(self.tfvars, "w") as f:
            f.write(content)
        return content

    def backups(self):
        return glob.glob(self.tfvars + ".bak-*")

    def assert_upgrader(self, value):
        tfvars = L5._read(self.tfvars)
        self.assertIn(UPGRADER_LINE.format(value), tfvars)
        self.assertEqual(tfvars.count("enable_platform_upgrader "), 1)

    def test_new_install_has_the_upgrader(self):
        rc, out, err = self.boot_iap()
        self.assertEqual(rc, 0, out + err)
        self.assert_upgrader("true")
        self.assertNotIn("keeping its self-update setting", out + err)

    def test_overwrite_of_a_file_without_the_key_stays_off(self):
        self.existing("")
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assert_upgrader("false")
        self.assertIn("keeping its self-update setting (enable_platform_upgrader = false)", out + err)
        self.assertEqual(len(self.backups()), 1)

    def test_overwrite_of_an_explicit_off_file_stays_off(self):
        self.existing("enable_platform_upgrader = false\n")
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assert_upgrader("false")

    def test_overwrite_of_a_file_with_the_upgrader_keeps_it(self):
        self.existing("enable_platform_upgrader = true\n")
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assert_upgrader("true")
        self.assertIn("keeping its self-update setting (enable_platform_upgrader = true)", out + err)

    def assert_refused(self, extra, code="BOOTSTRAP_UPGRADER_UNREADABLE"):
        before = self.existing(extra)
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn(code, out + err)
        self.assertEqual(L5._read(self.tfvars), before)          # file unchanged
        self.assertEqual(self.backups(), [])                     # refused before the backup
        self.assertEqual(self.tofu_ops(), [])                    # no init / plan / apply
        self.assertEqual([c for c in self.calls() if c.startswith(("gcloud services", "gcloud storage"))], [])
        return out + err

    def test_null_value_is_refused_and_named(self):
        out = self.assert_refused("enable_platform_upgrader = null\n")
        self.assertIn("cannot read enable_platform_upgrader (true or false)", out)
        self.assertNotIn("BOOTSTRAP_RUNNER_IDENTITY_UNREADABLE", out)

    # A value of the wrong type ("maybe", 1: HCL never converts those to bool) makes `tofu console` reject the whole
    # vars file, so the runner identity read just before this one refuses it first, with the file unchanged (the same
    # as SAT-46's own tf_runner_dedicated_sa = "maybe" case).
    def test_string_value_is_refused(self):
        self.assert_refused('enable_platform_upgrader = "maybe"\n', code="BOOTSTRAP_RUNNER_IDENTITY_UNREADABLE")

    def test_number_value_is_refused(self):
        self.assert_refused("enable_platform_upgrader = 1\n", code="BOOTSTRAP_RUNNER_IDENTITY_UNREADABLE")

if __name__ == "__main__":
    unittest.main()
