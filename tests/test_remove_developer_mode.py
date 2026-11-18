"""REMOVE-DEVELOPER-MODE (owner 2026-11-09): every install is what the default Consumer mode was, and the Cloud Build
push-deploy triggers are gone.

Pins: the installer has no mode prompt and writes none of the removed variables; `apply.sh` and `upgrade.sh` do not read
them; a vars file with or without those keys keeps working with the real OpenTofu parser (undeclared values in a var
file are a warning, never an error); the removed Terraform surface stays gone while the upgrader stays.
A stored branch source failing typed is pinned in tests/test_sat11_settings_upgrades.py.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import re
import subprocess
import textwrap

import pytest

import test_platform_safe_apply_lane5 as L5

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PROJ = L5.PROJ
LEGACY_LINES = textwrap.dedent('''\
    castor_deployment_mode      = "CONSUMER"
    github_repo                 = ""
    cloudbuild_2nd_gen_repo_id  = ""
    enable_cloud_build_triggers = false
    ''')
REMOVED_VARS = ("castor_deployment_mode", "github_repo", "cloudbuild_2nd_gen_repo_id", "enable_cloud_build_triggers")


def _read(*rel):
    with open(os.path.join(REPO, *rel), encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------------------------------- installer
def test_installer_has_no_mode_prompt_and_writes_no_removed_key():
    src = _read("scripts", "bootstrap.sh")
    for gone in ("Deployment Mode", "CASTOR_MODE", "MODE_UPPER", "ENABLE_TRIGGERS", "REPO_RESOURCE_ID",
                 "builds connections", "sv_ask_upstream_sync", "sv_apply_upstream_sync"):
        assert gone not in src, gone
    heredoc = src[src.index('cat <<EOF > "${TFVARS_PATH}"'):]
    heredoc = heredoc[:heredoc.index("\nEOF\n")]
    for name in REMOVED_VARS:
        assert not re.search(rf"^{name}\s*=", heredoc, re.M), name
    assert re.search(r'^platform_github_repo\s*=\s*""$', heredoc, re.M)
    assert subprocess.run(["bash", "-n", os.path.join(REPO, "scripts", "bootstrap.sh")]).returncode == 0


def test_installer_still_offers_the_stage_two_deploy():
    """RC-F12: every install offers stage 2 (deploy-services.sh --all-jobs) after the Terraform stage."""
    src = _read("scripts", "bootstrap.sh")
    assert "Build and deploy the services and jobs from source now?" in src
    assert 'bash "${REPO_ROOT}/scripts/deploy-services.sh" --all-jobs' in src


# ---------------------------------------------------------------------------------------------------- scripts
@pytest.mark.parametrize("script", ["apply.sh", "upgrade.sh"])
def test_scripts_do_not_read_the_removed_keys(script):
    src = _read("scripts", script)
    for name in REMOVED_VARS:
        assert f"sv_tfvar {name}" not in src, name
    assert "cloud_build_triggers" not in src and "triggers" not in re.sub(r"builds triggers", "", src)


def test_upgrade_always_runs_deploy_services():
    src = _read("scripts", "upgrade.sh")
    assert '    sv_info "5/6 scripts/deploy-services.sh --all-jobs..."\n' in src
    assert "bash \"${REPO_ROOT}/scripts/deploy-services.sh\" --all-jobs" in src


# ---------------------------------------------------------------------------------------------------- Terraform surface
def test_platform_terraform_no_longer_declares_or_uses_the_removed_names():
    for name in REMOVED_VARS + ("cloud_build_triggers", "CASTOR_DEPLOYMENT_MODE", "PLATFORM_GITHUB_REPO",
                                "cloudbuild_version_record_writer", "host_run_egress_cloudbuild_trigger_user"):
        for tf in os.listdir(os.path.join(REPO, "infra", "platform")):
            if tf.endswith(".tf") or tf.endswith(".tfvars.example"):
                assert not re.search(rf"\b{name}\b", _read("infra", "platform", tf)), (tf, name)
    assert not os.path.exists(os.path.join(REPO, "infra", "modules", "cloud_build"))
    assert not os.path.exists(os.path.join(REPO, "apps", "control-center", "infra", "modules", "cloud_build"))
    assert not os.path.exists(os.path.join(REPO, "scripts", "common", "trigger_release.sh"))


def test_the_upgrader_and_its_network_grant_stay():
    upgrader = _read("infra", "platform", "platform_upgrader.tf")
    assert 'resource "google_cloudbuild_trigger" "platform_upgrade"' in upgrader
    assert "sa-stackvend-upgrader" in upgrader
    assert "var.host_network_deployer_grants" in upgrader
    assert "google_cloudbuild_trigger.platform_upgrade" in _read("infra", "platform", "main.tf")
    variables = _read("infra", "platform", "variables.tf")
    assert 'variable "host_network_deployer_grants"' in variables


# ---------------------------------------------------------------------------------------------------- a real tfvars
@pytest.mark.skipif(not L5.REAL_TOFU, reason="needs OpenTofu (local, no network, no backend)")
@pytest.mark.parametrize("extra", ["", LEGACY_LINES], ids=["without_removed_keys", "old_file_with_removed_keys"])
def test_var_file_reads_with_the_platform_target_helper(tmp_path, extra):
    """sv_tfvar (scripts/common/platform_target.sh, the only tfvars reader) reads a value from the file either way."""
    tfvars = tmp_path / "x.tfvars"
    tfvars.write_text(f'project_id = "{PROJ}"\nregion = "us-central1"\n{extra}')
    script = ('. "$1/scripts/common/platform_target.sh"; PLATFORM_DIR="$1/infra/platform"; IAC_BIN="$2"; TFVARS="$3"; '
              "sv_tfvar region")
    r = subprocess.run(["bash", "-c", script, "bash", REPO, L5.REAL_TOFU, str(tfvars)], capture_output=True, text=True,
                       env={**os.environ, "TF_IN_AUTOMATION": "1"})
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == "us-central1"


@pytest.mark.skipif(not L5.REAL_TOFU, reason="needs OpenTofu (local, no network, no backend)")
def test_undeclared_var_file_values_are_a_warning_never_an_error(tmp_path):
    """OpenTofu's rule apply.sh and upgrade.sh rely on for an old vars file: -var-file with an undeclared value warns."""
    (tmp_path / "v.tf").write_text('variable "region" { type = string }\n')
    tfvars = tmp_path / "x.tfvars"
    tfvars.write_text(f'region = "us-central1"\n{LEGACY_LINES}')
    env = {**os.environ, "TF_DATA_DIR": str(tmp_path / ".tfdata")}
    init = subprocess.run([L5.REAL_TOFU, f"-chdir={tmp_path}", "init", "-input=false", "-no-color"],
                          capture_output=True, text=True, env=env)
    assert init.returncode == 0, init.stderr
    r = subprocess.run([L5.REAL_TOFU, f"-chdir={tmp_path}", "plan", "-input=false", "-no-color", f"-var-file={tfvars}"],
                       capture_output=True, text=True, env=env)
    assert r.returncode == 0, r.stderr
    assert "undeclared variable" in (r.stdout + r.stderr)


@pytest.mark.skipif(not L5.REAL_TOFU, reason="needs OpenTofu for the local `tofu console` tfvars parser")
class TestApplyWithOldAndNewVarFiles(L5._Harness):
    """apply.sh through its guards (stubbed gcloud/tofu except `tofu console`): both vars-file shapes work."""

    def test_old_vars_file_still_adopts(self):
        self.write(f"infra/platform/{PROJ}.tfvars", L5._tfvars(extra=LEGACY_LINES))
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write("google_storage_bucket.git_repos_bucket[0]\ngoogle_cloud_run_v2_service.git_server[0]\n")
        rc, _, err = self.run_script("apply.sh", ["adopt"], PROJECT_ID=PROJ, STUB_STATE_LIST=state)
        self.assertEqual(rc, 0, err)
        self.assertIn("Nothing to adopt", err)

    def test_plan_with_an_old_vars_file_reads_every_guard_value(self):
        self.write(f"infra/platform/{PROJ}.tfvars", L5._tfvars(extra=LEGACY_LINES))
        rc, _, err = self.run_script("apply.sh", ["plan", "-no-color"], PROJECT_ID=PROJ)
        self.assertEqual(rc, 0, err)

    def test_plan_with_a_vars_file_that_never_had_the_keys(self):
        self.write(f"infra/platform/{PROJ}.tfvars", L5._tfvars())
        rc, _, err = self.run_script("apply.sh", ["plan", "-no-color"], PROJECT_ID=PROJ)
        self.assertEqual(rc, 0, err)
