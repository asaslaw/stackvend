import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""FD-7L-n (SAT-35, owner OQ-35) + SAT-46: scripts/bootstrap.sh writes a NEW install as "Per workload".

Existing installs keep the variables.tf default (PLATFORM, "Shared"); tests/test_fd7l_platform_runner_identity.py pins
that default. A new install has no workloads to migrate, so it also starts with its runners on their own service
accounts (tf_runner_dedicated_sa = true; a create, never a switch, so scripts/apply.sh's readiness check is not
involved). The Phase-0 act-as lever stays off.

SAT-46: `bootstrap.sh --overwrite-tfvars` on an EXISTING vars file carries over that file's tf_runner_identity and
tf_runner_dedicated_sa exactly (real HCL parser; an absent key = the variables.tf default, so a Shared install stays
Shared), so regenerating the file never switches an install. A value it cannot read is refused
(BOOTSTRAP_RUNNER_IDENTITY_UNREADABLE) with the file unchanged. Review M1: bootstrap's gated apply also runs the
step-B readiness gate (scripts/common/runner_switch_gate.sh, shared with apply.sh), for an existing install
bootstrapped again without its vars file; a refusal leaves the new Per-workload vars file on disk and says so. The behavioural tests run the real bootstrap.sh under
lane 5's hermetic harness (stubbed gcloud/tofu; only `tofu console` is the real engine) and skip without OpenTofu.
"""
import glob
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)
import test_lane19_bootstrap_two_clients as L19  # noqa: E402  (module import only)

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PROJ = L5.PROJ
IDENTITY_LINE = 'tf_runner_identity                 = "{}"'
DEDICATED_LINE = "tf_runner_dedicated_sa             = {}"


class TestBootstrapNewInstallIsPerWorkload(unittest.TestCase):
    def test_bootstrap_heredoc_writes_the_runner_identity_variables(self):
        with open(os.path.join(REPO, "scripts", "bootstrap.sh"), encoding="utf-8") as f:
            boot = f.read()
        heredoc = boot[boot.index('cat <<EOF > "${TFVARS_PATH}"'):]
        heredoc = heredoc[:heredoc.index("\nEOF\n")]
        self.assertIn(IDENTITY_LINE.format("${SV_TF_RUNNER_IDENTITY}"), heredoc)
        self.assertIn(DEDICATED_LINE.format("${SV_TF_RUNNER_DEDICATED_SA}"), heredoc)
        self.assertNotIn("tf_runner_vending_act_as", heredoc)
        self.assertNotIn("stackvend_platform_commit", heredoc)   # supplied internally by sv_gated_apply, never a tfvar
        # the new-install values are the defaults of those two shell variables
        before = boot[:boot.index('cat <<EOF > "${TFVARS_PATH}"')]
        self.assertIn('SV_TF_RUNNER_IDENTITY="PER_WORKLOAD"\n', before)
        self.assertIn('SV_TF_RUNNER_DEDICATED_SA="true"\n', before)


class _BootIap(L19._Boot):
    def boot_iap(self, args=(), **env):
        head = [PROJ, "", "", "", "", "", "y", "", "", "octo-org"]
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        answers = head + ["", ""] + ["", ""] + [PROJ, "n"]      # IAP ingress, no OAuth clients, confirm, no stage 2
        return self.run_script("bootstrap.sh", list(args), tty_input="\n".join(answers),
                               STUB_PLAN_JSON=self.plan_json, **env)

    def assert_written(self, identity, dedicated):
        tfvars = L5._read(self.tfvars)
        self.assertIn(IDENTITY_LINE.format(identity), tfvars)
        self.assertIn(DEDICATED_LINE.format(dedicated), tfvars)
        self.assertEqual(tfvars.count("tf_runner_identity "), 1)
        self.assertEqual(tfvars.count("tf_runner_dedicated_sa "), 1)


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestBootstrapRunnerIdentityCarryOver(_BootIap):
    """SAT-46: new install -> PER_WORKLOAD/true; --overwrite-tfvars -> the existing file's values, exactly."""

    def existing(self, extra):
        content = f'project_id = "{PROJ}"\nregion     = "us-central1"\n' + extra
        with open(self.tfvars, "w") as f:
            f.write(content)
        return content

    def backups(self):
        return glob.glob(self.tfvars + ".bak-*")

    def test_new_install_is_per_workload_with_dedicated_runners(self):
        rc, out, err = self.boot_iap()
        self.assertEqual(rc, 0, out + err)
        self.assert_written("PER_WORKLOAD", "true")
        self.assertNotIn("keeping its Terraform runner identity", out + err)

    def test_overwrite_of_a_shared_file_without_the_keys_stays_shared(self):
        self.existing("")
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assert_written("PLATFORM", "false")
        self.assertIn('keeping its Terraform runner identity (tf_runner_identity = "PLATFORM", '
                      "tf_runner_dedicated_sa = false)", out + err)
        self.assertEqual(len(self.backups()), 1)

    def test_overwrite_of_an_explicit_shared_file_is_preserved(self):
        self.existing('tf_runner_identity = "PLATFORM"\ntf_runner_dedicated_sa = false\n')
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assert_written("PLATFORM", "false")

    def test_overwrite_of_a_shared_install_before_step_b_is_preserved(self):
        # declared PER_WORKLOAD (switched) but runners not moved yet: never jump to step B on a regenerate
        self.existing('tf_runner_identity = "PER_WORKLOAD"\n')
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assert_written("PER_WORKLOAD", "false")

    def test_overwrite_of_a_per_workload_file_is_preserved(self):
        self.existing('tf_runner_identity     = "PER_WORKLOAD"\ntf_runner_dedicated_sa = true\n')
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assert_written("PER_WORKLOAD", "true")

    def assert_refused(self, extra):
        before = self.existing(extra)
        rc, out, err = self.boot_iap(["--overwrite-tfvars"])
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("BOOTSTRAP_RUNNER_IDENTITY_UNREADABLE", out + err)
        self.assertEqual(L5._read(self.tfvars), before)          # file unchanged
        self.assertEqual(self.backups(), [])                     # refused before the backup
        self.assertEqual(self.tofu_ops(), [])                    # no init / plan / apply
        self.assertEqual([c for c in self.calls() if c.startswith(("gcloud services", "gcloud storage"))], [])
        return out + err

    def test_malformed_identity_is_refused(self):
        self.assert_refused('tf_runner_identity = "SHARED"\n')

    def test_malformed_dedicated_sa_is_refused(self):
        self.assert_refused('tf_runner_dedicated_sa = "maybe"\n')

    def test_unparseable_file_is_refused(self):
        self.assert_refused('tf_runner_identity = "PLATFORM\n')

    def test_null_dedicated_sa_is_refused_and_named(self):
        out = self.assert_refused("tf_runner_dedicated_sa = null\n")
        self.assertIn("cannot read tf_runner_dedicated_sa", out)

    def test_null_identity_is_refused_and_named(self):
        out = self.assert_refused("tf_runner_identity = null\n")
        self.assertIn("cannot read tf_runner_identity", out)
        self.assertNotIn("cannot read tf_runner_dedicated_sa", out)


# SAT-46 review M1: an existing install re-bootstrapped with no vars file (fresh clone, new machine) is written as
# PER_WORKLOAD + true, so bootstrap's gated apply runs the same step-B readiness gate as apply.sh
# (scripts/common/runner_switch_gate.sh). The readiness helper's `check` (it reads Firestore) is stubbed by a python3
# wrapper in the stub bin; `plan-switch` runs for real on the stub plan.
PY_WRAPPER = r"""#!/bin/bash
if [ "${2:-}" = "check" ] && [ "$(basename "${1:-}")" = "runner_identity_readiness.py" ]; then
  echo "python3 $*" >> "$STUB_LOG"
  { echo "== check stdin"; cat; } >> "$STUB_LOG.readiness"
  echo "Live workloads: 1, READY: 0, NOT READY: 1; project pending deletion (not blocking): 0"
  exit "${STUB_READINESS_RC:-1}"
fi
exec "$(dirname "$0")/python3.orig" "$@"
"""
DEV_SA = f"sa-castor-developer@{PROJ}.iam.gserviceaccount.com"
JOB_SA = f"sa-stackvend-tf-applier@{PROJ}.iam.gserviceaccount.com"
JOB_ADDR = "google_cloud_run_v2_job.tf_applier"


def _job_plan(actions, before_sa, after_sa):
    def tpl(sa):
        return None if sa is None else {"template": [{"template": [{"service_account": sa}]}]}
    return json.dumps({"resource_changes": [{"address": JOB_ADDR, "change": {
        "actions": list(actions), "before": tpl(before_sa), "after": tpl(after_sa), "after_unknown": {}}}]})


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestBootstrapRunsTheStepBGate(_BootIap):
    def setUp(self):
        super().setUp()
        py = os.path.join(self.stub, "python3")
        real = os.path.realpath(py)
        os.remove(py)
        os.symlink(real, os.path.join(self.stub, "python3.orig"))
        with open(py, "w") as f:
            f.write(PY_WRAPPER)
        os.chmod(py, 0o755)

    def set_plan(self, actions, before_sa, after_sa):
        with open(self.plan_json, "w") as f:
            f.write(_job_plan(actions, before_sa, after_sa))

    def readiness_calls(self):
        return [c for c in self.calls() if c.startswith("python3 ") and " check " in c]

    def boot_switch(self, readiness_rc):
        self.set_plan(["update"], DEV_SA, JOB_SA)
        rc, out, err = self.boot_iap(STUB_READINESS_RC=str(readiness_rc))
        return rc, out + err

    def assert_refused_before_confirmation(self, rc, out, code):
        self.assertNotEqual(rc, 0, out)
        self.assertIn(code, out)
        self.assertNotIn("Apply the plan above", out)
        self.assertEqual([c for c in self.tofu_ops() if c.startswith("tofu apply")], [])
        # the new vars file stays on disk as Per workload, and the operator is told how to keep the install Shared
        self.assert_written("PER_WORKLOAD", "true")
        self.assertIn("written by this run, stays on disk as Per workload", out)
        self.assertIn('edit that file to tf_runner_identity = "PLATFORM"', out)

    def test_switch_with_a_not_ready_workload_is_refused(self):
        rc, out = self.boot_switch(1)
        self.assert_refused_before_confirmation(rc, out, "APPLY_RUNNER_SWITCH_NOT_READY")
        calls = self.readiness_calls()
        self.assertEqual(len(calls), 1)
        self.assertIn(f"check --project {PROJ} --broker sa-project-provisioner@{PROJ}.iam.gserviceaccount.com",
                      calls[0])
        self.assertNotIn("stub-token", calls[0])                       # the token goes on stdin only
        self.assertIn("stub-token", L5._read(self.log + ".readiness"))

    def test_switch_that_cannot_be_checked_is_refused(self):
        rc, out = self.boot_switch(2)
        self.assert_refused_before_confirmation(rc, out, "APPLY_RUNNER_SWITCH_UNCHECKED")

    def test_switch_with_every_workload_ready_goes_on_to_the_confirmation(self):
        rc, out = self.boot_switch(0)
        self.assertEqual(rc, 0, out)
        self.assertIn("FD-7L step B readiness: every live workload is READY.", out)
        self.assertNotIn("stays on disk as Per workload", out)
        self.assertEqual(len(self.readiness_calls()), 1)
        self.assertTrue([c for c in self.tofu_ops() if c.startswith("tofu apply")])

    def test_new_install_creates_are_not_a_switch(self):
        self.set_plan(["create"], None, JOB_SA)
        rc, out, err = self.boot_iap()
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.readiness_calls(), [])
        self.assertTrue([c for c in self.tofu_ops() if c.startswith("tofu apply")])


if __name__ == "__main__":
    unittest.main()
