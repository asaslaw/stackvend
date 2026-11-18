import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""BOOTSTRAP-EXISTING-TFVARS-SELF-CORRECT (owner 11-10): an existing infra/platform/<project_id>.tfvars is no longer
a dead end for scripts/bootstrap.sh.

One READ-ONLY GET of gs://castor-tfstate-<id>/platform/state/default.tfstate decides, by HTTP status:
  * 404, or a state with no resources -> the file is left from an unfinished earlier run: it is moved to a
    timestamped backup and the run continues as a NEW install (no prompt);
  * 200 with resources -> an installed platform: a terminal is asked (default Yes) and Yes continues exactly as
    --overwrite-tfvars (carry-over of the file's values); No, or no terminal, is a typed stop with the file unchanged;
  * anything else -> not checked: a terminal is asked (default No); otherwise a typed stop.
--overwrite-tfvars and a run with no file make no state call. The behavioural tests run the real bootstrap.sh under
lane 5's hermetic harness (stubbed gcloud/curl/tofu; only `tofu console` is the real engine).
"""
import glob
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only)
import test_lane19_bootstrap_two_clients as L19  # noqa: E402  (module import only)

PROJ = L5.PROJ
IDENTITY_LINE = 'tf_runner_identity                 = "{}"'

# Answers the platform-state GET (and only it); every other curl call is logged and answers nothing, as before.
STATE_CURL_CASE = r'''case "$*" in *platform%2Fstate%2Fdefault.tfstate*)
  st_out=""; st_prev=""
  for st_a in "$@"; do [ "$st_prev" = "-o" ] && st_out="$st_a"; st_prev="$st_a"; done
  st_stdin="$(cat)"
  echo "curl $*" >> "$STUB_LOG.state"
  case "$st_stdin" in *'header = "Authorization: Bearer '*) echo "auth-on-stdin" >> "$STUB_LOG.state" ;; esac
  if [ -n "${STUB_STATE_GET_BODY:-}" ]; then cat "$STUB_STATE_GET_BODY" > "$st_out"; fi
  printf '%s' "${STUB_STATE_GET_CODE:-404}"
  exit 0 ;;
esac
'''
CURL = "#!/bin/bash\n" + STATE_CURL_CASE + 'echo "curl $*" >> "$STUB_LOG"\nexit 0\n'


def _state(n):
    return json.dumps({"version": 4, "resources": [{"type": "google_project_service", "name": f"r{i}"}
                                                   for i in range(n)]})


class TestGuardText(unittest.TestCase):
    def test_the_old_dead_end_is_gone_and_the_terraform_tfvars_guard_stays(self):
        with open(os.path.join(L5.SCRIPTS, "bootstrap.sh"), encoding="utf-8") as f:
            boot = f.read()
        self.assertNotIn("looks like an existing install.", boot)
        self.assertNotIn("Rename it to <its project_id>.tfvars (or remove it) and re-run bootstrap.", boot)
        self.assertIn('if [ -e "${TF_DIR}/terraform.tfvars" ]; then', boot)
        self.assertIn("BOOTSTRAP-EXISTING-TFVARS-SELF-CORRECT", boot)


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestExistingTfvarsSelfCorrect(L19._Boot):
    def setUp(self):
        super().setUp()
        with open(os.path.join(self.stub, "curl"), "w") as f:
            f.write(CURL)
        self.body = os.path.join(self.tmp, "state.json")

    def existing(self):
        content = (f'project_id = "{PROJ}"\nregion     = "us-central1"\n'
                   'tf_runner_identity = "PLATFORM"\ntf_runner_dedicated_sa = false\n')
        with open(self.tfvars, "w") as f:
            f.write(content)
        return content

    def boot_iap(self, extra_answers=(), args=(), **env):
        # region, zone, org, billing, folder, environment, VCS (no mode prompt since REMOVE-DEVELOPER-MODE), owner
        head = [PROJ] + list(extra_answers) + ["", "", "", "", "", "y", "", "", "octo-org"]
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        answers = head + ["", ""] + ["", ""] + [PROJ, "n"]      # IAP ingress, no OAuth clients, confirm, no stage 2
        return self.run_script("bootstrap.sh", list(args), tty_input="\n".join(answers),
                               STUB_PLAN_JSON=self.plan_json, **env)

    def state_calls(self):
        p = self.log + ".state"
        return open(p).read() if os.path.exists(p) else ""

    def backups(self):
        return glob.glob(self.tfvars + ".bak-*")

    def read(self, p):
        with open(p) as f:
            return f.read()

    # --- no state: a leftover from an unfinished run -> backup + new install, no prompt -------------------------
    def test_no_state_moves_the_file_aside_and_installs_fresh(self):
        old = self.existing()
        rc, out, err = self.boot_iap(STUB_STATE_GET_CODE="404")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("left from an unfinished earlier run", out + err)
        self.assertEqual(len(self.backups()), 1)
        self.assertEqual(self.read(self.backups()[0]), old)
        self.assertIn(IDENTITY_LINE.format("PER_WORKLOAD"), self.read(self.tfvars))   # new-install defaults
        self.assertIn("auth-on-stdin", self.state_calls())                            # token never on argv

    def test_empty_state_is_treated_like_no_state(self):
        self.existing()
        with open(self.body, "w") as f:
            f.write(_state(0))
        rc, out, err = self.boot_iap(STUB_STATE_GET_CODE="200", STUB_STATE_GET_BODY=self.body)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("left from an unfinished earlier run", out + err)
        self.assertIn(IDENTITY_LINE.format("PER_WORKLOAD"), self.read(self.tfvars))

    # --- a real install -> ask (default Yes), Yes = the --overwrite-tfvars carry-over --------------------------
    def test_installed_project_default_yes_reruns_with_carry_over(self):
        self.existing()
        with open(self.body, "w") as f:
            f.write(_state(5))
        rc, out, err = self.boot_iap(extra_answers=[""], STUB_STATE_GET_CODE="200", STUB_STATE_GET_BODY=self.body)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("already has a StackVend install (platform state with 5 resources)", out + err)
        self.assertIn(IDENTITY_LINE.format("PLATFORM"), self.read(self.tfvars))       # carried over, not switched
        self.assertEqual(len(self.backups()), 1)

    def test_installed_project_no_is_a_typed_stop_with_the_file_unchanged(self):
        old = self.existing()
        with open(self.body, "w") as f:
            f.write(_state(5))
        rc, out, err = self.boot_iap(extra_answers=["n"], STUB_STATE_GET_CODE="200", STUB_STATE_GET_BODY=self.body)
        self.assertNotEqual(rc, 0)
        self.assertIn("BOOTSTRAP_EXISTING_INSTALL_DECLINED", out + err)
        self.assertEqual(self.read(self.tfvars), old)
        self.assertEqual(self.backups(), [])

    # --- the state could not be read -> ask (default No) -----------------------------------------------------
    def test_unchecked_state_default_no_is_a_typed_stop(self):
        old = self.existing()
        rc, out, err = self.boot_iap(extra_answers=[""], STUB_STATE_GET_CODE="403")
        self.assertNotEqual(rc, 0)
        self.assertIn("BOOTSTRAP_STATE_UNCHECKED", out + err)
        self.assertIn("returned 403", out + err)
        self.assertEqual(self.read(self.tfvars), old)

    def test_unchecked_state_yes_reruns_with_carry_over(self):
        self.existing()
        rc, out, err = self.boot_iap(extra_answers=["y"], STUB_STATE_GET_CODE="403")
        self.assertEqual(rc, 0, out + err)
        self.assertIn(IDENTITY_LINE.format("PLATFORM"), self.read(self.tfvars))
        self.assertEqual(len(self.backups()), 1)

    # --- Do No Harm: no file, or --overwrite-tfvars -> no state call, unchanged behaviour ----------------------
    def test_no_file_makes_no_state_call(self):
        rc, out, err = self.boot_iap()
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.state_calls(), "")

    def test_overwrite_flag_makes_no_state_call(self):
        self.existing()
        rc, out, err = self.boot_iap(args=["--overwrite-tfvars"])
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.state_calls(), "")
        self.assertIn(IDENTITY_LINE.format("PLATFORM"), self.read(self.tfvars))

    # --- terraform.tfvars (tofu auto-loads it): moved to where it belongs, never a stop -------------------------
    def tt(self, content):
        p = os.path.join(self.platform, "terraform.tfvars")
        with open(p, "w") as f:
            f.write(content)
        return p

    def test_terraform_tfvars_for_this_project_is_renamed_then_self_corrected(self):
        tt = self.tt(f'project_id = "{PROJ}"\nregion = "us-central1"\n')
        rc, out, err = self.boot_iap(STUB_STATE_GET_CODE="404")
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.exists(tt))
        self.assertIn("[MOVED]", out + err)
        self.assertIn("left from an unfinished earlier run", out + err)
        self.assertEqual(len(self.backups()), 1)
        self.assertIn(IDENTITY_LINE.format("PER_WORKLOAD"), self.read(self.tfvars))

    def test_terraform_tfvars_for_another_project_is_renamed_to_it(self):
        tt = self.tt(f'project_id = "{L5.OTHER}"\nregion = "us-central1"\n')
        rc, out, err = self.boot_iap()
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.exists(tt))
        self.assertTrue(os.path.exists(os.path.join(self.platform, f"{L5.OTHER}.tfvars")))
        self.assertEqual(self.state_calls(), "")                     # this project had no file: no state check

    def test_unreadable_terraform_tfvars_is_backed_up(self):
        tt = self.tt("this is not HCL {{{\n")
        rc, out, err = self.boot_iap()
        self.assertEqual(rc, 0, out + err)
        self.assertFalse(os.path.exists(tt))
        self.assertEqual(len(glob.glob(tt + ".bak-*")), 1)


if __name__ == "__main__":
    unittest.main()
