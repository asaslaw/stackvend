import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""BOOTSTRAP-PREFILL (owner 11-03): scripts/bootstrap.sh takes the defaults of four prompts from the environment.

STACKVEND_PROJECT_ID, STACKVEND_ORG_ID, STACKVEND_BILLING_ACCOUNT_ID and STACKVEND_FOLDER_ID (set by
scripts/pre-bootstrap.sh when it starts bootstrap) are shown in the prompt's brackets; Enter accepts, typing overrides;
the chosen value is checked exactly like typed input. Unset = today's behaviour (project: the gcloud config project).
Runs the real bootstrap.sh under lane 5's hermetic harness (stubbed gcloud/tofu/curl; only `tofu console` is the real
engine) and skips without OpenTofu.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)
import test_bootstrap_folder_iam_preflight as FIAM  # noqa: E402  (module import only)

PROJ = L5.PROJ
OTHER = L5.OTHER
ORG = "organizations/123456789012"
BILLING = "01ABCD-23EF45-67890A"
FOLDER = "folders/4242"
PREFILL = {"STACKVEND_PROJECT_ID": PROJ, "STACKVEND_ORG_ID": ORG, "STACKVEND_BILLING_ACCOUNT_ID": BILLING,
           "STACKVEND_FOLDER_ID": FOLDER}


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestBootstrapPrefill(FIAM._FolderIam):
    def boot(self, project="", org="", billing="", folder="", **env):
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization, or the
        # stub answers no Tag Administrator permissions and no platform state: no tag)
        head = [project, "", "", org, billing, folder, "y", "", "", "octo-org"]
        # IAP ingress, no OAuth clients, confirm; then "n" to the billing grants question (asked only when a billing
        # account is set: the stub check cannot tell) and "n" to stage 2 (a spare "n" is left unread).
        answers = head + ["", ""] + ["", ""] + [PROJ, "n", "n"]
        env.setdefault("STUB_ACCOUNT", FIAM.ACCOUNT)
        rc, out, err = self.run_script("bootstrap.sh", [], tty_input="\n".join(answers),
                                       STUB_PLAN_JSON=self.plan_json, **env)
        return rc, out + err

    def tfvar(self, key):
        for line in L5._read(self.tfvars).splitlines():
            if line.split("=", 1)[0].strip() == key:
                return line.split("=", 1)[1].strip().strip('"')
        raise AssertionError(key)

    def test_each_value_is_shown_as_the_default_and_enter_accepts_it(self):
        rc, out = self.boot(STUB_GCLOUD_CONFIG_PROJECT=OTHER, **PREFILL)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Enter Google Cloud Project ID for StackVend Platform [{PROJ}]: ", out)
        self.assertIn(f"Enter Google Cloud Organization ID (e.g. organizations/123456789012) [{ORG}]: ", out)
        self.assertIn(f"Enter Billing Account ID (e.g. 01XXXX-XXXXXX-XXXXXX) [{BILLING}]: ", out)
        self.assertIn(f"Enter Managed Workloads Folder ID (e.g. folders/123456789012) [{FOLDER}]: ", out)
        self.assertEqual(self.tfvar("project_id"), PROJ)                  # the env value beats the gcloud config one
        self.assertEqual(self.tfvar("organization_id"), ORG)
        self.assertEqual(self.tfvar("billing_account_id"), BILLING)
        self.assertEqual(self.tfvar("castor_managed_workloads_folder_id"), FOLDER)
        self.assert_one_read_only_call()                                   # the prefilled folder is checked too

    def test_typed_values_override(self):
        env = dict(PREFILL, STACKVEND_PROJECT_ID=OTHER, STACKVEND_ORG_ID="organizations/999",
                   STACKVEND_BILLING_ACCOUNT_ID="01FFFF-EEEEEE-DDDDDD", STACKVEND_FOLDER_ID="folders/999")
        rc, out = self.boot(project=PROJ, org=ORG, billing=BILLING, folder=FOLDER, **env)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.tfvar("project_id"), PROJ)
        self.assertEqual(self.tfvar("organization_id"), ORG)
        self.assertEqual(self.tfvar("billing_account_id"), BILLING)
        self.assertEqual(self.tfvar("castor_managed_workloads_folder_id"), FOLDER)
        self.assertIn(URL_FOR_4242, "\n".join(self.folder_iam_calls()))

    def test_unset_is_unchanged(self):
        rc, out = self.boot(STUB_GCLOUD_CONFIG_PROJECT=PROJ)
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Enter Google Cloud Project ID for StackVend Platform [{PROJ}]: ", out)
        self.assertIn("Enter Google Cloud Organization ID (e.g. organizations/123456789012) [optional]: ", out)
        self.assertIn("Enter Billing Account ID (e.g. 01XXXX-XXXXXX-XXXXXX) [optional - press Enter to skip]: ", out)
        self.assertIn("Enter Managed Workloads Folder ID (e.g. folders/123456789012) [optional - press Enter to skip]: ",
                      out)
        self.assertEqual(self.tfvar("project_id"), PROJ)
        for key in ("organization_id", "billing_account_id", "castor_managed_workloads_folder_id"):
            self.assertEqual(self.tfvar(key), "", key)
        self.assertEqual(self.folder_iam_calls(), [])

    def test_empty_env_values_are_unset(self):
        rc, out = self.boot(STUB_GCLOUD_CONFIG_PROJECT=PROJ, STACKVEND_PROJECT_ID="", STACKVEND_ORG_ID="",
                            STACKVEND_BILLING_ACCOUNT_ID="", STACKVEND_FOLDER_ID="")
        self.assertEqual(rc, 0, out)
        self.assertIn("[optional]: ", out)
        self.assertEqual(self.tfvar("project_id"), PROJ)

    def test_invalid_project_id_is_refused_like_typed_input(self):
        rc, out = self.boot(**dict(PREFILL, STACKVEND_PROJECT_ID="Bad_Project"))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("'Bad_Project' is not a valid GCP project id.", out)
        self.assertEqual(self.writes(), [])
        self.assertEqual(self.tofu_ops(), [])

    def test_invalid_folder_is_refused_like_typed_input(self):
        rc, out = self.boot(**dict(PREFILL, STACKVEND_FOLDER_ID="my-folder"))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("BOOTSTRAP_FOLDER_ID_INVALID", out)
        self.assertEqual(self.writes(), [])
        self.assertFalse(os.path.exists(self.tfvars))

    def test_malformed_billing_gets_the_typed_input_warning(self):
        # Same as typed input: a warning and "Keep this value anyway? (y/N)"; Enter there (No) asks to re-enter, and
        # Enter again skips the billing account. Answers: project, region, zone, org, billing, keep, re-enter, folder,
        # tag question (y), environment, VCS, GitHub owner, ingress (2), OAuth clients (2), confirmation,
        # stage 2.
        answers = ["", "", "", "", "", "", "", "", "y", "", "", "octo-org"] + ["", ""] + ["", ""] + [PROJ, "n"]
        rc, out, err = self.run_script("bootstrap.sh", [], tty_input="\n".join(answers), STUB_PLAN_JSON=self.plan_json,
                                       STUB_ACCOUNT=FIAM.ACCOUNT, **dict(PREFILL, STACKVEND_BILLING_ACCOUNT_ID="not-billing"))
        out = out + err
        self.assertEqual(rc, 0, out)
        self.assertIn("Warning: 'not-billing' does not match standard GCP billing format", out)
        self.assertIn("Keep this value anyway? (y/N): ", out)
        self.assertEqual(self.tfvar("billing_account_id"), "")
        self.assertEqual(self.tfvar("castor_managed_workloads_folder_id"), FOLDER)   # the folder prompt took its default


URL_FOR_4242 = "https://cloudresourcemanager.googleapis.com/v3/folders/4242:testIamPermissions"


class TestBootstrapPrefillStatic(unittest.TestCase):
    def test_only_the_four_prompts_read_the_environment(self):
        with open(os.path.join(L5.SCRIPTS, "bootstrap.sh"), encoding="utf-8") as f:
            src = f.read()
        code = "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))
        self.assertEqual(code.count("${STACKVEND_PROJECT_ID:-"), 1)
        for name in ("STACKVEND_ORG_ID", "STACKVEND_BILLING_ACCOUNT_ID", "STACKVEND_FOLDER_ID"):
            self.assertEqual(code.count("${" + name + ":-"), 2, name)        # once in the prompt, once as the default
        self.assertIn('DEFAULT_PROJECT_ID="${STACKVEND_PROJECT_ID:-${CURRENT_PROJECT}}"', code)


if __name__ == "__main__":
    unittest.main()
