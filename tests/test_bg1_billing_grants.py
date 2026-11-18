"""BG-1 (owner request 10-18): billing-account grants by core Terraform, never a failed install.

Covers:
1. infra/platform/billing_iam.tf: additive google_billing_account_iam_member only (never _policy/_binding),
   gated on var.bind_billing_iam (null default) and a non-empty billing_account_id; nothing else in the platform
   reads the variable (so an install with it unset plans exactly what it planned before BG-1).
   BG-1-b (owner 10-20): the same gate also adds ONE additive roles/billing.viewer member for the lane 18 Control
   Center persona SA (google_billing_account_iam_member.cc_billing_viewer); nothing when unset/false.
   Real engine (installer tofu >= 1.10 + the exact platform pins: google/google-beta 6.50.0, random 3.9.1, offline mirror): `tofu validate` of the whole
   platform and `tofu test` with mock providers (0 members when unset/false, 2 additive members when true).
   Skipped when the untracked tools are absent (STACKVEND_PLATFORM_TOFU / STACKVEND_PLATFORM_TOFU_MIRROR).
2. scripts/apply.sh + scripts/common/platform_target.sh preflight, run under the lane-5 stub harness (stub gcloud,
   tofu, curl on PATH; nothing can reach GCP): permission present -> -var=bind_billing_iam=true; absent / 403 /
   curl error -> false + WARNING and the apply still proceeds; an explicit tfvars value wins; no billing account ->
   the plan command line is byte-identical to before. bootstrap.sh: Terraform grant first, gcloud only as fallback.
3. Control Center /api/settings/billing-status via FastAPI TestClient in a guarded child process with the billing
   API mocked: GRANTED / NOT_GRANTED / CANNOT_VERIFY (HTTP status), never a 500.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
BILLING_TF = os.path.join(PLATFORM, "billing_iam.tf")
SCRIPTS = os.path.join(REPO, "scripts")
CC_DIR = os.path.join(REPO, "apps", "control-center")
DASHBOARD = os.path.join(CC_DIR, "templates", "dashboard.html")

_spec = importlib.util.spec_from_file_location("lane5_harness_for_bg1", os.path.join(HERE, "test_platform_safe_apply_lane5.py"))
_lane5 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_lane5)

PROJ = _lane5.PROJ
BILLING = "01AAAA-BBBBBB-CCCCCC"
SAS = ("sa-project-provisioner", "sa-castor-developer")
ADDR = 'google_billing_account_iam_member.billing_user["%s"]'

# The platform needs OpenTofu >= 1.10 (`removed { lifecycle { destroy = false } }` in main.tf; 1.9.0 is only the workload
# /validate engine), so this is the installer's tofu (oracle column) with the exact platform provider pins (6.50.0).
PLATFORM_TOFU = os.environ.get("STACKVEND_PLATFORM_TOFU") or shutil.which("tofu") or ""
PLATFORM_MIRROR = os.environ.get("STACKVEND_PLATFORM_TOFU_MIRROR") or os.path.join(REPO, "eval", ".tofu-mirror")


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


# ==============================================================================
# 1. Terraform
# ==============================================================================
class TestBillingIamTfStatic(unittest.TestCase):
    def test_only_additive_member_resources(self):
        tf = _strip_comments(_read(BILLING_TF))
        heads = re.findall(r'^resource\s+"([^"]+)"\s+"([^"]+)"', tf, re.M)
        self.assertEqual(heads, [("google_billing_account_iam_member", "billing_user"),
                                 ("google_billing_account_iam_member", "cc_billing_viewer")])
        for f in os.listdir(PLATFORM):
            if f.endswith(".tf"):
                body = _strip_comments(_read(os.path.join(PLATFORM, f)))
                self.assertNotIn("google_billing_account_iam_policy", body, f)
                self.assertNotIn("google_billing_account_iam_binding", body, f)

    def test_gate_role_and_members(self):
        tf = _read(BILLING_TF)
        self.assertIn('var.bind_billing_iam == true && local.billing_iam_account_id != ""', tf)
        self.assertIn('toset(["sa-project-provisioner", "sa-castor-developer"])', tf)
        self.assertIn('role               = "roles/billing.user"', tf)
        self.assertIn('member             = "serviceAccount:${google_service_account.agents[each.key].email}"', tf)
        self.assertIn('trimprefix(var.billing_account_id, "billingAccounts/")', tf)

    def test_cc_billing_viewer_same_gate_cc_persona_additive(self):
        """BG-1-b: one additive member, roles/billing.viewer, the lane 18 CC persona SA, the billing_user gate."""
        tf = _strip_comments(_read(BILLING_TF))
        self.assertIn("bind_billing_iam_on    = var.bind_billing_iam == true && local.billing_iam_account_id != \"\"", tf)
        self.assertIn("local.bind_billing_iam_on\n    ? toset([\"sa-project-provisioner\", \"sa-castor-developer\"])", tf)
        block = tf[tf.index('resource "google_billing_account_iam_member" "cc_billing_viewer"'):]
        block = block[:block.index("\n}") + 2]
        self.assertIn("count              = local.bind_billing_iam_on ? 1 : 0", block)
        self.assertIn("billing_account_id = local.billing_iam_account_id", block)
        self.assertIn('role               = "roles/billing.viewer"', block)
        self.assertIn('member             = "serviceAccount:${local.cc_sa_email}"', block)
        guard = _strip_comments(_read(os.path.join(PLATFORM, "destructive_guard.tf")))
        self.assertIn('cc_sa_email        = google_service_account.stackvend_personas["sa-stackvend-control-center"].email', guard)

    def test_variable_defaults_to_null_and_is_read_only_by_billing_iam_tf(self):
        """Negative (nothing else changes): only billing_iam.tf reads var.bind_billing_iam or its locals."""
        attrs = _lane5.attributes(_read(os.path.join(PLATFORM, "variables.tf")))
        d = {(p[0], a): v for p, a, v in attrs}
        self.assertEqual(d[('variable "bind_billing_iam"', "default")], "null")
        self.assertEqual(d[('variable "bind_billing_iam"', "type")], "bool")
        for f in os.listdir(PLATFORM):
            if not f.endswith(".tf") or f == "billing_iam.tf":
                continue
            body = _strip_comments(_read(os.path.join(PLATFORM, f)))
            for name in ("var.bind_billing_iam", "local.billing_iam_account_id", "local.billing_user_service_accounts",
                         "local.bind_billing_iam_on",
                         "google_billing_account_iam_member"):
                self.assertNotIn(name, body, f)

    def test_main_tf_points_at_the_new_file(self):
        main = _read(os.path.join(PLATFORM, "main.tf"))
        self.assertIn("# NOTE (BG-1): Billing Account IAM lives in billing_iam.tf.", main)
        self.assertNotIn("Platform Terraform never modifies Billing Account IAM", main)


TFTEST = textwrap.dedent('''\
    # Mock providers: no credentials, no API calls. Service accounts get a valid email/member (the provider
    # validates IAM member syntax at plan time; a random mock string is not one).
    mock_provider "google" {
      mock_resource "google_service_account" {
        defaults = {
          email  = "sa-mock@proj-aaaa1.iam.gserviceaccount.com"
          member = "serviceAccount:sa-mock@proj-aaaa1.iam.gserviceaccount.com"
          name   = "projects/proj-aaaa1/serviceAccounts/sa-mock@proj-aaaa1.iam.gserviceaccount.com"
        }
      }
      mock_resource "google_logging_project_sink" {
        defaults = {
          writer_identity = "serviceAccount:sink-mock@proj-aaaa1.iam.gserviceaccount.com"
        }
      }
    }
    mock_provider "google-beta" {}
    # ORG-POLICY-FOLDER: the host-quota google alias (providers.tf) used only by google_org_policy_policy.managed_folder_vm_external_ip.
    mock_provider "google" {
      alias = "host_quota"
    }
    mock_provider "random" {}

    # BG-1-b: a distinct CC persona email, so the viewer member provably names that SA (not a shared mock).
    override_resource {
      target = google_service_account.stackvend_personas["sa-stackvend-control-center"]
      values = {
        email  = "sa-stackvend-control-center@proj-aaaa1.iam.gserviceaccount.com"
        member = "serviceAccount:sa-stackvend-control-center@proj-aaaa1.iam.gserviceaccount.com"
      }
    }
    # Lane 18 `check "stackvend_managed_tag_configured"` (a failed check block fails a tofu test run): give the
    # install an organization + managed folder and a realistic tag value id (as tests/fixtures/lane18_s0 does).
    override_resource {
      target = google_tags_tag_value.stackvend_managed_true[0]
      values = { name = "281478392000", id = "tagValues/281478392000" }
    }

    variables {
      project_id                         = "proj-aaaa1"
      billing_account_id                 = "01AAAA-BBBBBB-CCCCCC"
      cc_google_oauth_client_id          = "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"
      organization_id                    = "organizations/111111111111"
      castor_managed_workloads_folder_id = "folders/222222222222"
    }

    run "unset_plans_no_billing_resources" {
      command = plan
      assert {
        condition     = length(google_billing_account_iam_member.billing_user) == 0
        error_message = "bind_billing_iam unset must plan no billing-account IAM"
      }
      assert {
        condition     = length(google_billing_account_iam_member.cc_billing_viewer) == 0
        error_message = "bind_billing_iam unset must plan no CC billing viewer"
      }
    }

    run "false_plans_no_billing_resources" {
      command = plan
      variables {
        bind_billing_iam = false
      }
      assert {
        condition     = length(google_billing_account_iam_member.billing_user) == 0
        error_message = "bind_billing_iam=false must plan no billing-account IAM"
      }
      assert {
        condition     = length(google_billing_account_iam_member.cc_billing_viewer) == 0
        error_message = "bind_billing_iam=false must plan no CC billing viewer"
      }
    }

    run "true_without_billing_account_plans_nothing" {
      command = plan
      variables {
        bind_billing_iam   = true
        billing_account_id = ""
      }
      assert {
        condition     = length(google_billing_account_iam_member.billing_user) == 0
        error_message = "no billing account -> nothing to grant"
      }
      assert {
        condition     = length(google_billing_account_iam_member.cc_billing_viewer) == 0
        error_message = "no billing account -> no CC billing viewer"
      }
    }

    run "true_plans_two_additive_members" {
      command = apply
      variables {
        bind_billing_iam   = true
        billing_account_id = "billingAccounts/01AAAA-BBBBBB-CCCCCC"
      }
      assert {
        condition     = length(google_billing_account_iam_member.billing_user) == 2
        error_message = "expected exactly two members"
      }
      assert {
        condition     = toset(keys(google_billing_account_iam_member.billing_user)) == toset(["sa-project-provisioner", "sa-castor-developer"])
        error_message = "wrong service accounts"
      }
      assert {
        condition     = alltrue([for k, m in google_billing_account_iam_member.billing_user : m.role == "roles/billing.user" && m.billing_account_id == "01AAAA-BBBBBB-CCCCCC" && m.member == "serviceAccount:${google_service_account.agents[k].email}"])
        error_message = "wrong role, billing account id or member"
      }
      assert {
        condition     = length(google_billing_account_iam_member.cc_billing_viewer) == 1
        error_message = "expected exactly one CC billing viewer member"
      }
      assert {
        condition     = google_billing_account_iam_member.cc_billing_viewer[0].role == "roles/billing.viewer" && google_billing_account_iam_member.cc_billing_viewer[0].billing_account_id == "01AAAA-BBBBBB-CCCCCC" && google_billing_account_iam_member.cc_billing_viewer[0].member == "serviceAccount:sa-stackvend-control-center@proj-aaaa1.iam.gserviceaccount.com"
        error_message = "CC billing viewer: wrong role, billing account id or member (must be the CC persona SA)"
      }
    }
''')


@pytest.fixture(scope="module")
def platform_engine(tmp_path_factory):
    if not (os.access(PLATFORM_TOFU, os.X_OK) and os.path.isdir(PLATFORM_MIRROR)):
        pytest.skip("tofu + platform provider mirror (untracked) not present; set "
                    "STACKVEND_PLATFORM_TOFU / STACKVEND_PLATFORM_TOFU_MIRROR")
    root = tmp_path_factory.mktemp("bg1tf")
    shutil.copytree(PLATFORM, root / "infra" / "platform",
                    ignore=shutil.ignore_patterns(".terraform*", "*.tfvars", "*.tfstate*", "*.bak-*"))
    for mod in ("workflows",):
        shutil.copytree(os.path.join(REPO, "infra", "modules", mod), root / "infra" / "modules" / mod,
                        ignore=shutil.ignore_patterns(".terraform*"))
    (root / "workflows").mkdir()
    for wf in ("main_orchestrator.yaml", "sre_remediation.yaml"):      # read by infra/modules/workflows (file())
        shutil.copy(os.path.join(REPO, "workflows", wf), root / "workflows" / wf)
    (root / "mcp-servers" / "kubernetes").mkdir(parents=True)        # read by main.tf (file(), lane 14 Helm pin)
    shutil.copy(os.path.join(REPO, "mcp-servers", "kubernetes", "helm-pin.json"),
                root / "mcp-servers" / "kubernetes" / "helm-pin.json")
    cli = root / "cli.tfrc"
    cli.write_text('provider_installation {\n  filesystem_mirror {\n    path = %s\n  }\n}\n' % json.dumps(PLATFORM_MIRROR))
    env = {"PATH": "/usr/bin:/bin", "HOME": str(root), "TF_CLI_CONFIG_FILE": str(cli),
           "TF_DATA_DIR": str(root / ".tfdata"), "TF_IN_AUTOMATION": "1", "CHECKPOINT_DISABLE": "1"}
    wd = str(root / "infra" / "platform")

    def run(*args, timeout=600):
        return subprocess.run([PLATFORM_TOFU, *args], cwd=wd, env=env, capture_output=True, text=True, timeout=timeout)

    r = run("init", "-backend=false", "-input=false", "-no-color")
    assert r.returncode == 0, r.stdout + r.stderr
    return run, root


def test_platform_validates_at_production_set(platform_engine):
    run, _ = platform_engine
    r = run("validate", "-no-color")
    assert r.returncode == 0, r.stdout + r.stderr


def test_billing_iam_counts_with_mock_providers(platform_engine):
    run, root = platform_engine
    tests_dir = root / "infra" / "platform" / "tests"
    tests_dir.mkdir(exist_ok=True)
    (tests_dir / "bg1.tftest.hcl").write_text(TFTEST)
    r = run("test", "-no-color", "-verbose")
    out = r.stdout + r.stderr
    assert r.returncode == 0, out
    assert "4 passed, 0 failed" in out, out


# ==============================================================================
# 2. apply.sh / bootstrap.sh preflight (stub harness)
# ==============================================================================
CURL_STUB = r'''#!/bin/bash
# Records argv (the token must never be on it) and the stdin config; answers like curl -w '\n%{http_code}'.
echo "curl $*" >> "$STUB_LOG"
case " $* " in
  *" -K - "*) cat > "$STUB_LOG.curlcfg" ;;
  *) exit 0 ;;   # other curl calls (bootstrap's Firestore seeding): logged only
esac
[ "${STUB_CURL_RC:-0}" = "0" ] || exit "${STUB_CURL_RC}"
printf '%s\n%s' "${STUB_CURL_BODY-}" "${STUB_CURL_CODE:-200}"
'''

PERMS_ADMIN = json.dumps({"permissions": ["billing.accounts.setIamPolicy", "billing.accounts.getIamPolicy"]})
PERMS_READ = json.dumps({"permissions": ["billing.accounts.getIamPolicy"]})


@unittest.skipUnless(_lane5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class _BgHarness(_lane5._Harness):
    def setUp(self):
        super().setUp()
        p = os.path.join(self.stub, "curl")
        with open(p, "w") as f:
            f.write(CURL_STUB)
        os.chmod(p, 0o755)

    def tfvars(self, extra=""):
        self.tfvars_path = self.write(f"infra/platform/{PROJ}.tfvars", _lane5._tfvars(extra=extra))
        return self.tfvars_path

    def plans(self):
        return [x for x in self.calls() if x.startswith("tofu plan")]

    def curls(self):
        return [x for x in self.calls() if x.startswith("curl ") and "cloudbilling" in x]

    def assert_never_mutates_billing(self):
        c = "\n".join(self.calls())
        self.assertNotIn("add-iam-policy-binding", c)
        self.assertNotIn(":setIamPolicy", "\n".join(self.curls()))
        for x in self.curls():
            self.assertIn(f"https://cloudbilling.googleapis.com/v1/billingAccounts/{BILLING}:testIamPermissions", x)
            self.assertNotIn("stub-token", x)          # token only on curl's stdin config
            self.assertIn("-K -", x)


class TestApplyPreflight(_BgHarness):
    def _plan(self, extra=f'billing_account_id = "{BILLING}"\n', **env):
        self.tfvars(extra)
        return self.run_script("apply.sh", ["plan", "-no-color"], PROJECT_ID=PROJ, **env)

    def _base_plan(self):
        return f"tofu plan -lock=false -input=false -var-file={os.path.realpath(self.tfvars_path)} -no-color"

    def test_admin_gets_true(self):
        rc, out, err = self._plan(STUB_CURL_BODY=PERMS_ADMIN, STUB_CURL_CODE="200")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=true"])
        self.assertIn("Billing Account Administrator rights confirmed", err)
        self.assertNotIn("[WARN]", err)
        self.assertEqual(len(self.curls()), 1)
        with open(self.log + ".curlcfg") as f:
            self.assertEqual(f.read(), 'header = "Authorization: Bearer stub-token"\n')
        self.assert_never_mutates_billing()

    def _assert_skipped(self, err, reason_fragment):
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=false"])
        self.assertIn("[WARN]", err)
        self.assertNotIn("[ERROR]", err)
        self.assertIn(f"will NOT be granted on billing account {BILLING}", err)
        for sa in SAS:
            self.assertIn(f"serviceAccount:{sa}@{PROJ}.iam.gserviceaccount.com", err)
            self.assertIn(f"gcloud billing accounts add-iam-policy-binding {BILLING} --member=serviceAccount:{sa}@{PROJ}"
                          ".iam.gserviceaccount.com --role=roles/billing.user", err)
        self.assertIn(f"PROJECT_ID={PROJ} bash scripts/apply.sh apply", err)
        self.assertIn("Control Center > Settings", err)
        self.assertIn(reason_fragment, err)
        self.assert_never_mutates_billing()

    def test_permission_absent_false_with_warning(self):
        rc, out, err = self._plan(STUB_CURL_BODY=PERMS_READ, STUB_CURL_CODE="200")
        self.assertEqual(rc, 0, err)
        self._assert_skipped(err, "lacks billing.accounts.setIamPolicy")

    def test_empty_permissions_false(self):
        rc, out, err = self._plan(STUB_CURL_BODY="{}", STUB_CURL_CODE="200")
        self.assertEqual(rc, 0, err)
        self._assert_skipped(err, "not a Billing Account Administrator")

    def test_403_false_with_warning(self):
        rc, out, err = self._plan(STUB_CURL_BODY='{"error":{"code":403}}', STUB_CURL_CODE="403")
        self.assertEqual(rc, 0, err)
        self._assert_skipped(err, "answered HTTP 403")

    def test_curl_error_false_with_warning(self):
        rc, out, err = self._plan(STUB_CURL_RC="7")
        self.assertEqual(rc, 0, err)
        self._assert_skipped(err, "(no response)")

    def test_garbage_answer_false(self):
        rc, out, err = self._plan(STUB_CURL_BODY="<html>", STUB_CURL_CODE="200")
        self.assertEqual(rc, 0, err)
        self._assert_skipped(err, "unreadable answer")

    def test_malformed_billing_id_not_sent(self):
        rc, out, err = self._plan(extra='billing_account_id = "not-a-billing-id"\n')
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.curls(), [])
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=false"])
        self.assertIn("is not in the 01XXXX-XXXXXX-XXXXXX format", err)

    def test_billing_prefix_is_stripped(self):
        rc, out, err = self._plan(extra=f'billing_account_id = "billingAccounts/{BILLING}"\n',
                                  STUB_CURL_BODY=PERMS_ADMIN, STUB_CURL_CODE="200")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=true"])
        self.assert_never_mutates_billing()

    def test_explicit_tfvars_wins(self):
        for value in ("true", "false"):
            open(self.log, "w").close()
            rc, out, err = self._plan(extra=f'billing_account_id = "{BILLING}"\nbind_billing_iam = {value}\n',
                                      STUB_CURL_BODY=PERMS_ADMIN if value == "false" else "{}", STUB_CURL_CODE="200")
            self.assertEqual(rc, 0, err)
            self.assertEqual(self.curls(), [], value)
            self.assertEqual(self.plans(), [self._base_plan()], value)    # the tfvars value, no -var override
            self.assertIn(f"bind_billing_iam = {value} is set in", err)

    def test_no_billing_account_is_byte_identical(self):
        """Negative: unset + no billing account -> no call and the exact pre-BG-1 plan command line."""
        rc, out, err = self._plan(extra="")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.curls(), [])
        self.assertEqual(self.plans(), [self._base_plan()])
        self.assertNotIn("bind_billing_iam", err)
        self.assert_no_mutation_calls()

    EXCLUDE = ("-exclude=google_billing_account_iam_member.billing_user"
               " -exclude=google_billing_account_iam_member.cc_billing_viewer")

    def _state(self, text):
        st = os.path.join(self.tmp, "state.txt")
        with open(st, "w") as f:
            f.write(text)
        return st

    def _in_state(self):
        return self._state('google_service_account.agents["sa-castor-developer"]\n' + (ADDR % "sa-project-provisioner") + "\n")

    def test_in_state_no_billing_role_is_excluded(self):
        """RT F1 (verdict NONE): keep them declared AND exclude them, so the non-admin run can neither fail a
        refresh (getIamPolicy 403) nor a re-create (setIamPolicy 403)."""
        rc, out, err = self._plan(STUB_CURL_BODY="{}", STUB_CURL_CODE="403", STUB_STATE_LIST=self._in_state())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=true " + self.EXCLUDE])
        self.assertIn("skipped, kept as is", err)
        self.assertNotIn("will NOT be granted", err)
        self.assert_never_mutates_billing()

    def test_in_state_read_only_role_is_excluded(self):
        """RT F1 (verdict GET): a grant removed out of band would plan a create that fails on setIamPolicy."""
        rc, out, err = self._plan(STUB_CURL_BODY=PERMS_READ, STUB_CURL_CODE="200", STUB_STATE_LIST=self._in_state())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=true " + self.EXCLUDE])
        self.assertIn("skipped, kept as is", err)

    def test_viewer_only_in_state_is_excluded(self):
        """BG-1-b: the CC billing viewer alone in state also keeps the gate on and is excluded (never a delete)."""
        st = self._state('google_service_account.agents["sa-castor-developer"]\n'
                         "google_billing_account_iam_member.cc_billing_viewer[0]\n")
        rc, out, err = self._plan(STUB_CURL_BODY="{}", STUB_CURL_CODE="403", STUB_STATE_LIST=st)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=true " + self.EXCLUDE])
        self.assertIn("skipped, kept as is", err)
        self.assert_never_mutates_billing()

    def test_in_state_with_target_has_no_exclude(self):
        """tofu refuses -exclude with -target (and -target leaves the members out anyway)."""
        self.tfvars(f'billing_account_id = "{BILLING}"\n')
        rc, out, err = self.run_script("apply.sh", ["plan", "-target=google_pubsub_topic.x"], PROJECT_ID=PROJ,
                                       STUB_CURL_BODY="{}", STUB_CURL_CODE="403", STUB_STATE_LIST=self._in_state())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.plans(), [f"tofu plan -lock=false -input=false -var-file={os.path.realpath(self.tfvars_path)}"
                                        " -target=google_pubsub_topic.x -var=bind_billing_iam=true"])
        self.assertIn("kept as is", err)

    def test_in_state_admin_has_no_exclude(self):
        rc, out, err = self._plan(STUB_CURL_BODY=PERMS_ADMIN, STUB_CURL_CODE="200", STUB_STATE_LIST=self._in_state())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=true"])
        self.assertNotIn(self.EXCLUDE, "\n".join(self.calls()))

    def test_large_state_list_still_finds_members(self):
        """RT F3: a >64 KB state list must not lose the match to SIGPIPE under pipefail."""
        filler = "".join('google_project_iam_member.filler["%06d-%s"]\n' % (i, "x" * 60) for i in range(1600))
        self.assertGreater(len(filler), 100_000)
        st = self._state((ADDR % "sa-castor-developer") + "\n" + filler)
        rc, out, err = self._plan(STUB_CURL_BODY="{}", STUB_CURL_CODE="403", STUB_STATE_LIST=st)
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.plans(), [self._base_plan() + " -var=bind_billing_iam=true " + self.EXCLUDE])

    def test_unreadable_tfvar_warns_and_continues(self):
        """RT F2: an unreadable bind_billing_iam never aborts the run; no decision, no call."""
        # A console that fails only for the bind_billing_iam read (every other tfvars read stays real).
        wrapper = os.path.join(self.tmp, "console-fails-for-bind")
        with open(wrapper, "w") as f:
            f.write('#!/bin/bash\nin="$(cat)"\ncase "$in" in *bind_billing_iam*) exit 1 ;; esac\n'
                    'printf "%s\\n" "$in" | exec "$REAL_TOFU_INNER" "$@"\n')
        os.chmod(wrapper, 0o755)
        rc, out, err = self._plan(STUB_CURL_BODY=PERMS_ADMIN, STUB_CURL_CODE="200",
                                  REAL_TOFU=wrapper, REAL_TOFU_INNER=_lane5.REAL_TOFU)
        self.assertEqual(rc, 0, err)
        self.assertIn("no billing grant decision made", err)
        self.assertNotIn("[ERROR]", err)
        self.assertEqual(self.curls(), [])
        self.assertEqual(self.plans(), [self._base_plan()])

    def test_explicit_false_with_members_in_state_warns(self):
        """RT F6: an explicit false after Terraform made the grants plans their removal: say so."""
        rc, out, err = self._plan(extra=f'billing_account_id = "{BILLING}"\nbind_billing_iam = false\n',
                                  STUB_STATE_LIST=self._in_state())
        self.assertEqual(rc, 0, err)
        self.assertIn("tries to REMOVE them", err)
        self.assertEqual(self.curls(), [])
        self.assertEqual(self.plans(), [self._base_plan()])

    def test_permission_list_type_checked(self):
        """RT F9: a string 'permissions' must not substring-match setIamPolicy."""
        rc, out, err = self._plan(STUB_CURL_BODY=json.dumps({"permissions": "billing.accounts.setIamPolicy"}),
                                  STUB_CURL_CODE="200")
        self.assertEqual(rc, 0, err)
        self._assert_skipped(err, "unreadable answer")

    def test_non_admin_apply_proceeds(self):
        """An installer without Billing Account Administrator: the apply still runs (grant skipped, warning)."""
        plan_json = os.path.join(self.tmp, "plan.json")
        with open(plan_json, "w") as f:
            f.write(_lane5._plan_json([["create"]]))
        self.tfvars(f'billing_account_id = "{BILLING}"\n')
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ, PROJECT_ID=PROJ,
                                       STUB_PLAN_JSON=plan_json, STUB_CURL_BODY="{}", STUB_CURL_CODE="403")
        self.assertEqual(rc, 0, err)
        plans = self.plans()
        self.assertEqual(len(plans), 1)
        self.assertIn(" -var=bind_billing_iam=false -out=", plans[0])
        self.assertTrue([x for x in self.calls() if x.startswith("tofu apply -input=false ")])
        self.assertIn("will NOT be granted", err)
        self.assert_never_mutates_billing()


class TestScriptsSyntaxAndShape(unittest.TestCase):
    def test_bash_n(self):
        for f in ("apply.sh", "bootstrap.sh", os.path.join("common", "platform_target.sh")):
            r = subprocess.run(["/bin/bash", "-n", os.path.join(SCRIPTS, f)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f + r.stderr)

    def test_apply_sh_never_grants_billing_itself(self):
        src = _read(os.path.join(SCRIPTS, "apply.sh"))
        self.assertNotIn("add-iam-policy-binding", src)
        self.assertNotIn("cloudbilling", src)       # the preflight lives in common/platform_target.sh

    def test_bootstrap_gcloud_grant_is_only_a_fallback(self):
        src = _read(os.path.join(SCRIPTS, "bootstrap.sh"))
        self.assertNotIn("bind_billing_iam                   = ${BIND_BILLING_IAM}", src)
        self.assertIn('sv_gated_apply bootstrap "" ${SV_BILLING_TF_ARGS[@]+"${SV_BILLING_TF_ARGS[@]}"}', src)
        i_pre = src.index("\nsv_billing_iam_preflight\n")
        i_apply = src.index('sv_gated_apply bootstrap ""')
        # RC (owner 10-26, post-install billing access): one `if [ -n "$BILLING_ACCOUNT_ID" ]` block with the
        # Terraform-granted branch first, the print-only not_admin branch, then the prompting fallback (`else`).
        i_true = src.index('    if [ "${SV_BIND_BILLING_IAM}" = "true" ] && [ "${SV_BILLING_CHECK}" = "admin" ]; then')
        i_not_admin = src.index('    elif [ "${SV_BILLING_CHECK}" = "not_admin" ]; then')
        i_fallback = src.index('read -r -p "Grant these three billing bindings now? (Y/n): "')
        i_gcloud = src.index('gcloud billing accounts add-iam-policy-binding "${CLEAN_BILLING}"')   # the only real grant call
        self.assertEqual(src.count('gcloud billing accounts add-iam-policy-binding "${CLEAN_BILLING}"'), 1)
        self.assertLess(i_pre, i_apply)
        self.assertLess(i_apply, i_true)
        self.assertLess(i_true, i_not_admin)        # BG-1-F5: print-only branch before the prompting fallback
        self.assertLess(i_not_admin, i_fallback)
        self.assertLess(i_fallback, i_gcloud)
        self.assertNotIn("read -r", src[i_not_admin:i_fallback])
        self.assertIn("Control Center > Settings", src[i_not_admin:i_fallback])


class TestBootstrapBilling(_BgHarness):
    """Fresh install with a billing account (lane-5 bootstrap answers, billing id filled in)."""

    def setUp(self):
        super().setUp()
        self.plan_json = os.path.join(self.tmp, "plan.json")
        with open(self.plan_json, "w") as f:
            f.write(_lane5._plan_json([["create"], ["create"]]))

    @staticmethod
    def _answers(extra_before_deploy=()):
        # ... GitHub owner, ingress (Enter = Direct IAP), corp domain, CC client, tenant client, typed id
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        return "\n".join([PROJ, "", "", "", BILLING, "", "y", "", "", "octo-org", "", "", "", "", PROJ,
                          *extra_before_deploy, "n"])

    def _run(self, answers, **env):
        env.setdefault("STUB_PLAN_JSON", self.plan_json)
        return self.run_script("bootstrap.sh", [], tty_input=answers, **env)

    def test_admin_terraform_grants_no_gcloud(self):
        rc, out, err = self._run(self._answers(), STUB_CURL_BODY=PERMS_ADMIN, STUB_CURL_CODE="200")
        self.assertEqual(rc, 0, out + err)
        tfvars = _read(os.path.join(self.platform, f"{PROJ}.tfvars"))
        self.assertNotRegex(tfvars, r"(?m)^bind_billing_iam\s*=")       # unset = auto
        self.assertIn(f'billing_account_id                 = "{BILLING}"', tfvars)
        plans = self.plans()
        self.assertEqual(len(plans), 1)
        self.assertIn(" -var=bind_billing_iam=true -out=", plans[0])
        self.assertIn("Terraform granted roles/billing.user", out + err)
        self.assertFalse([x for x in self.calls() if "add-iam-policy-binding" in x])
        # RC F11: BG-1-b granted the viewer in the same apply; no misleading "no billing viewer access" warning.
        self.assertIn("roles/billing.viewer to sa-stackvend-control-center", out + err)
        self.assertNotIn("no billing viewer access", out + err)
        self.assertNotIn("Post-install step: billing access", out + err)

    def test_post_install_step_lists_all_three_grants_when_not_admin(self):
        """Owner 10-26: billing grants are a post-install step when the installer lacks Billing Account Admin."""
        rc, out, err = self._run(self._answers(), STUB_CURL_BODY=PERMS_READ, STUB_CURL_CODE="200")
        self.assertEqual(rc, 0, out + err)
        both = out + err
        tail = both[both.index("Post-install step: billing access"):]
        for sa in SAS:
            self.assertIn(f"--member=serviceAccount:{sa}@{PROJ}.iam.gserviceaccount.com --role=roles/billing.user", tail)
        self.assertIn(f"gcloud billing accounts add-iam-policy-binding {BILLING} --member=serviceAccount:"
                      f"sa-stackvend-control-center@{PROJ}.iam.gserviceaccount.com --role=roles/billing.viewer", tail)
        # apply.sh / preflight warning names the viewer grant too.
        self.assertIn("--role=roles/billing.viewer", err[:err.index("will NOT be granted") + 2000])

    def test_post_install_step_after_declined_fallback(self):
        rc, out, err = self._run(self._answers(extra_before_deploy=("n",)), STUB_CURL_BODY="{}", STUB_CURL_CODE="403")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("Post-install step: billing access", out + err)
        self.assertFalse([x for x in self.calls() if "add-iam-policy-binding" in x])

    # lane18-window-v4: lane 18 S0 adds the Control Center SA's roles/billing.viewer to the gcloud fallback
    # (L18-k3), so the fallback offers three bindings.
    PROMPT = "Grant these three billing bindings now? (Y/n)"

    def _fresh(self):
        """Each loop iteration is a fresh install: drop the call log and the tfvars the previous run wrote."""
        open(self.log, "w").close()
        tfv = os.path.join(self.platform, f"{PROJ}.tfvars")
        if os.path.exists(tfv):
            os.remove(tfv)

    def _assert_skipped_install_ok(self, rc, out, err):
        self.assertEqual(rc, 0, out + err)
        plans = self.plans()
        self.assertEqual(len(plans), 1)
        self.assertIn(" -var=bind_billing_iam=false -out=", plans[0])
        self.assertIn("will NOT be granted", err)
        self.assertTrue([x for x in self.calls() if x.startswith("tofu apply -input=false ")])

    def test_f5_positively_not_admin_prints_fix_without_prompt(self):
        """BG-1-F5 (owner 84e307b): HTTP 200 without setIamPolicy -> no gcloud prompt, fix commands + Settings only."""
        for body in (PERMS_READ, "{}"):
            self._fresh()
            # No extra answer: the prompt must not be asked (an extra 'n' would be read as the next question).
            rc, out, err = self._run(self._answers(), STUB_CURL_BODY=body, STUB_CURL_CODE="200")
            self._assert_skipped_install_ok(rc, out, err)
            both = out + err
            self.assertNotIn(self.PROMPT, both, body)
            self.assertNotIn("Optional: grant roles/billing.user", both, body)
            self.assertIn(f"you are not a Billing Account Administrator for {BILLING}", both)
            self.assertIn(f"PROJECT_ID={PROJ} bash scripts/apply.sh apply", both)
            tail = both[both.index("you are not a Billing Account Administrator for"):]
            for sa in SAS:
                self.assertIn(f"gcloud billing accounts add-iam-policy-binding {BILLING} --member=serviceAccount:{sa}@{PROJ}"
                              ".iam.gserviceaccount.com --role=roles/billing.user", tail)
            self.assertIn("Control Center > Settings", tail)
            self.assertFalse([x for x in self.calls() if "add-iam-policy-binding" in x])

    def test_f5_check_could_not_run_keeps_prompt(self):
        """BG-1-F5: HTTP error (403) or no network (curl error) -> the gcloud fallback prompt is still offered."""
        for env in ({"STUB_CURL_BODY": "{}", "STUB_CURL_CODE": "403"}, {"STUB_CURL_RC": "7"}):
            self._fresh()
            rc, out, err = self._run(self._answers(extra_before_deploy=("n",)), **env)
            self._assert_skipped_install_ok(rc, out, err)
            both = out + err
            self.assertIn(self.PROMPT, both, env)
            self.assertIn("Terraform skipped the billing grants", both)
            self.assertNotIn("you are not a Billing Account Administrator for", both)
            self.assertFalse([x for x in self.calls() if "add-iam-policy-binding" in x])   # answered 'n'

    def test_f5_no_token_keeps_prompt(self):
        """BG-1-F5: no access token -> the check could not run -> prompt kept."""
        gcloud = os.path.join(self.stub, "gcloud")
        with open(gcloud) as f:
            body = f.read()
        # Fail only the preflight's token call (it alone passes 2>/dev/null with no other args); others unchanged.
        marker = 'a="$*"\n'
        assert marker in body
        body = body.replace(marker, marker + '[ -n "${STUB_TOKEN_FAIL_FILE:-}" ] && [ "$a" = "auth print-access-token" ] && '
                                    '[ -e "$STUB_TOKEN_FAIL_FILE" ] && { rm -f "$STUB_TOKEN_FAIL_FILE"; exit 1; }\n', 1)
        with open(gcloud, "w") as f:
            f.write(body)
        flag = os.path.join(self.tmp, "fail-next-token")
        # Bootstrap asks for tokens earlier and later too: arm ONE failure at the first `state list` (just before the
        # preflight), so only the preflight's token call fails.
        st = os.path.join(self.tmp, "state.txt")
        open(st, "w").close()
        tofu = os.path.join(self.stub, "tofu")
        with open(tofu) as f:
            tb = f.read()
        tb = tb.replace('  state) [ -n "${STUB_STATE_LIST:-}" ] && cat "$STUB_STATE_LIST"; exit 0 ;;',
                        '  state) [ -n "${STUB_ARM_TOKEN_FAIL:-}" ] && [ ! -e "$STUB_ARM_TOKEN_FAIL.done" ] && '
                        'touch "$STUB_ARM_TOKEN_FAIL" "$STUB_ARM_TOKEN_FAIL.done"; '
                        '[ -n "${STUB_STATE_LIST:-}" ] && cat "$STUB_STATE_LIST"; exit 0 ;;', 1)
        with open(tofu, "w") as f:
            f.write(tb)
        rc, out, err = self._run(self._answers(extra_before_deploy=("n",)), STUB_TOKEN_FAIL_FILE=flag,
                                 STUB_ARM_TOKEN_FAIL=flag, STUB_STATE_LIST=st)
        self._assert_skipped_install_ok(rc, out, err)
        both = out + err
        self.assertIn("could not get an access token", err)
        self.assertEqual(self.curls(), [])
        self.assertIn(self.PROMPT, both)


# ==============================================================================
# 3. Control Center Settings billing card
# ==============================================================================
CHILD = r'''
import json, os, sys
cc = sys.argv[1]
sys.path.insert(0, cc)
import google.auth


def _no_adc(*a, **k):
    raise google.auth.exceptions.DefaultCredentialsError("ADC disabled in tests")


google.auth.default = _no_adc
from fastapi import FastAPI
from fastapi.testclient import TestClient
import routes.settings as st

app = FastAPI()
app.include_router(st.router)
route = next(r for r in st.router.routes if getattr(r, "path", "") == "/api/settings/billing-status")
for dep in route.dependencies:
    app.dependency_overrides[dep.dependency] = lambda: None
client = TestClient(app, raise_server_exceptions=False)
PROJ = st.PROJECT_ID or os.environ["PROJECT_ID"]


def member(sa):
    return "serviceAccount:%s@%s.iam.gserviceaccount.com" % (sa, PROJ)


class Resp:
    def __init__(self, code, body):
        self.status_code = code
        self._body = body
        self.text = "body"

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


class Session:
    def __init__(self, get_code=200, policy_code=200, policy=None, policy_raises=False):
        self.get_code, self.policy_code, self.policy, self.policy_raises = get_code, policy_code, policy, policy_raises
        self.urls = []

    def get(self, url, params=None, timeout=None):
        self.urls.append((url, params))
        if url.endswith(":getIamPolicy"):
            if self.policy_raises:
                raise ConnectionError("down")
            return Resp(self.policy_code, self.policy)
        return Resp(self.get_code, {"name": "billingAccounts/x"})


def call(session, billing="01AAAA-BBBBBB-CCCCCC"):
    os.environ["BILLING_ACCOUNT_ID"] = billing
    if isinstance(session, Exception):
        def boom():
            raise session
        st._billing_authed_session = boom
    else:
        st._billing_authed_session = lambda: session
    r = client.get("/api/settings/billing-status")
    out = {"http": r.status_code}
    try:
        out["json"] = r.json()
    except Exception:
        out["json"] = None
    if not isinstance(session, Exception):
        out["urls"] = session.urls
    return out


both = {"bindings": [{"role": "roles/billing.user", "members": [member("sa-project-provisioner"), member("sa-castor-developer"), "user:a@example.com"]}]}
only_prov = {"bindings": [{"role": "roles/billing.user", "members": [member("sa-project-provisioner"), "deleted:" + member("sa-castor-developer")]},
                          {"role": "roles/billing.viewer", "members": [member("sa-castor-developer")]}]}
admin_and_cond = {"bindings": [{"role": "roles/billing.admin", "members": [member("sa-project-provisioner")]},
                               {"role": "roles/billing.user", "members": [member("sa-castor-developer")],
                                "condition": {"title": "t", "expression": "true"}}]}
R = {
    "granted": call(Session(policy=both)),
    "missing": call(Session(policy=only_prov)),
    "cannot_403": call(Session(policy_code=403, policy={"error": {}})),
    "cannot_500": call(Session(policy_code=500, policy={})),
    "policy_raises": call(Session(policy_raises=True)),
    "garbage": call(Session(policy=ValueError("not json"))),
    "bindings_not_list": call(Session(policy={"bindings": "x"})),
    "admin_and_conditional": call(Session(policy=admin_and_cond)),
    "no_session": call(RuntimeError("no adc")),
    "not_configured": call(Session(policy=both), billing=""),
    "prefixed": call(Session(policy=both), billing="billingAccounts/01AAAA-BBBBBB-CCCCCC"),
}
# BILLING-CARD-COMMANDS: the helper with unknown values keeps placeholders (never a made-up id).
HELPER = {"unknown": st.billing_grant_fix_commands("", ""),
          "known": st.billing_grant_fix_commands("01AAAA-BBBBBB-CCCCCC", "my-proj"),
          # shell safety: malformed install values never reach a copyable command
          "hostile": st.billing_grant_fix_commands("01AAAA-BBBBBB-CCCCCC; rm -rf ~", "p$(id)"),
          "lower_or_short": st.billing_grant_fix_commands("01aaaa-bbbbbb-cccccc", "abc"),
          "user_fix_hostile": st._billing_user_fix_command("01AAAA-BBBBBB-CCCCCC; rm -rf ~", "sa-castor-developer",
                                                           "p$(id)")}
print(json.dumps({"proj": PROJ, "results": R, "helper": HELPER}))
'''


@pytest.fixture(scope="module")
def cc_results(tmp_path_factory):
    d = tmp_path_factory.mktemp("bg1cc")
    script = d / "child.py"
    script.write_text(CHILD)
    env = hermetic_guard.child_env(drop=("TEST_MODE", "BILLING_ACCOUNT_ID", "BILLING_ACCOUNT"),
                                   extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    r = subprocess.run([sys.executable, str(script), CC_DIR], capture_output=True, text=True, timeout=300, env=env,
                       cwd=str(d))
    assert r.returncode == 0, r.stderr[-4000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def _grants(res):
    return {g["service_account"]: g for g in res["json"]["billing_user_grants"]}


def test_cc_all_granted(cc_results):
    res = cc_results["results"]["granted"]
    assert res["http"] == 200
    g = _grants(res)
    assert {k: v["status"] for k, v in g.items()} == {"sa-project-provisioner": "GRANTED", "sa-castor-developer": "GRANTED"}
    assert res["json"]["billing_healthy"] is True
    assert res["json"]["billing_grants_missing"] == []
    assert res["json"]["has_billing_access"] is True
    assert res["json"]["grant_skip_reason"] == ""
    assert [u for u, _ in res["urls"]] == [
        "https://cloudbilling.googleapis.com/v1/billingAccounts/01AAAA-BBBBBB-CCCCCC",
        "https://cloudbilling.googleapis.com/v1/billingAccounts/01AAAA-BBBBBB-CCCCCC:getIamPolicy"]


def test_cc_missing_developer_shows_reason_and_fix(cc_results):
    proj = cc_results["proj"]
    res = cc_results["results"]["missing"]
    assert res["http"] == 200
    g = _grants(res)
    assert g["sa-project-provisioner"]["status"] == "GRANTED"
    dev = g["sa-castor-developer"]
    assert dev["status"] == "NOT_GRANTED"
    assert dev["role"] == "roles/billing.user"
    assert dev["http_status"] == 200
    assert "does NOT have Billing Account User" in dev["detail"]
    assert "was not a Billing Account Administrator" in dev["detail"]
    assert dev["fix_command"] == ("gcloud billing accounts add-iam-policy-binding 01AAAA-BBBBBB-CCCCCC "
                                  f"--member=serviceAccount:sa-castor-developer@{proj}.iam.gserviceaccount.com "
                                  "--role=roles/billing.user")
    j = res["json"]
    assert j["billing_grants_missing"] == ["sa-castor-developer"]
    assert j["billing_healthy"] is False
    assert "not a Billing Account Administrator" in j["grant_skip_reason"]
    assert j["grant_fix_apply"] == f"PROJECT_ID={proj} bash scripts/apply.sh apply"
    # CC-APPLY-WHERE (owner 11-03): the fix also says where to run apply.sh, with this install's project id.
    assert j["grant_fix_where"] == (
        "Run it from the root of the StackVend folder you installed from: it holds "
        f"infra/platform/{proj}.tfvars (keep a copy; the installer's last step prints the command to back it up to "
        f"gs://castor-tfstate-{proj}/platform/).")


@pytest.mark.parametrize("case,status", [("cannot_403", 403), ("cannot_500", 500), ("garbage", 200),
                                         ("bindings_not_list", 200), ("policy_raises", None)])
def test_cc_cannot_verify_never_fails(cc_results, case, status):
    res = cc_results["results"][case]
    assert res["http"] == 200
    for g in _grants(res).values():
        assert g["status"] == "CANNOT_VERIFY", (case, g)
        assert g["http_status"] == status
        assert g["detail"]
    assert res["json"]["billing_grants_missing"] == []
    if case == "cannot_403":
        assert "HTTP 403" in _grants(res)["sa-project-provisioner"]["detail"]
    # BILLING-CARD-COMMANDS (11-03): the card's Cannot verify state shows the three grants with this install's values,
    # plus the apply.sh re-run and where to run it (CC-APPLY-WHERE).
    proj = cc_results["proj"]
    assert res["json"]["grant_fix_commands"] == _three_commands("01AAAA-BBBBBB-CCCCCC", proj)
    assert res["json"]["grant_fix_apply"] == f"PROJECT_ID={proj} bash scripts/apply.sh apply"
    assert res["json"]["grant_fix_where"].startswith("Run it from the root of the StackVend folder you installed from")


def _three_commands(billing, proj):
    return [
        f"gcloud billing accounts add-iam-policy-binding {billing} "
        f"--member=serviceAccount:sa-project-provisioner@{proj}.iam.gserviceaccount.com --role=roles/billing.user",
        f"gcloud billing accounts add-iam-policy-binding {billing} "
        f"--member=serviceAccount:sa-castor-developer@{proj}.iam.gserviceaccount.com --role=roles/billing.user",
        f"gcloud billing accounts add-iam-policy-binding {billing} "
        f"--member=serviceAccount:sa-stackvend-control-center@{proj}.iam.gserviceaccount.com --role=roles/billing.viewer",
    ]


def test_cc_three_commands_match_quickstart_and_bootstrap(cc_results):
    """The same three grants as billing_iam.tf, bootstrap.sh's post-install block and the quickstart, in that order."""
    res = cc_results["results"]["granted"]
    assert res["json"]["grant_fix_commands"] == _three_commands("01AAAA-BBBBBB-CCCCCC", cc_results["proj"])
    assert res["json"]["billing_healthy"] is True  # always present when configured; the card shows it only on Cannot verify
    assert cc_results["results"]["no_session"]["json"]["grant_fix_commands"] == _three_commands(
        "01AAAA-BBBBBB-CCCCCC", cc_results["proj"])
    assert cc_results["results"]["prefixed"]["json"]["grant_fix_commands"][0].startswith(
        "gcloud billing accounts add-iam-policy-binding 01AAAA-BBBBBB-CCCCCC ")
    assert cc_results["results"]["not_configured"]["json"]["grant_fix_commands"] == []
    assert cc_results["helper"]["known"] == _three_commands("01AAAA-BBBBBB-CCCCCC", "my-proj")
    assert cc_results["helper"]["unknown"] == _three_commands("<billing-account-id>", "<project_id>")


def test_cc_commands_never_carry_malformed_values(cc_results):
    """Shell safety: a value is used only when it fullmatches the Google id shape, else the placeholder."""
    h = cc_results["helper"]
    assert h["hostile"] == _three_commands("<billing-account-id>", "<project_id>")
    assert h["lower_or_short"] == _three_commands("<billing-account-id>", "<project_id>")
    assert h["user_fix_hostile"] == (
        "gcloud billing accounts add-iam-policy-binding <billing-account-id> "
        "--member=serviceAccount:sa-castor-developer@<project_id>.iam.gserviceaccount.com --role=roles/billing.user")
    for cmd in h["hostile"] + [h["user_fix_hostile"]]:
        assert ";" not in cmd and "$(" not in cmd and "rm -rf" not in cmd
    quick = _read(os.path.join(REPO, "documentation", "quickstart.md"))
    target = _read(os.path.join(SCRIPTS, "common", "platform_target.sh"))  # bootstrap.sh's SA lists
    for sa, role in (("sa-project-provisioner", "roles/billing.user"), ("sa-castor-developer", "roles/billing.user"),
                     ("sa-stackvend-control-center", "roles/billing.viewer")):
        assert (f"--member=serviceAccount:{sa}@<your-project-id>.iam.gserviceaccount.com --role={role}") in quick
    assert "\nSV_BILLING_USER_SAS=(sa-project-provisioner sa-castor-developer)\n" in target
    assert re.search(r'^SV_BILLING_VIEWER_SA="sa-stackvend-control-center"(\s|$)', target, re.M)


def test_cc_viewer_service_account_matches_install_warning():
    """The card's third command and the CC_BILLING_VIEWER_MISSING warning name the same Control Center identity."""
    import ast

    def const(path, name):
        tree = ast.parse(_read(path))
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
                return ast.literal_eval(node.value)
        raise AssertionError(f"{name} not in {path}")

    st = os.path.join(CC_DIR, "routes", "settings.py")
    ist = os.path.join(CC_DIR, "routes", "install_status.py")
    assert const(st, "BILLING_VIEWER_SERVICE_ACCOUNT") == const(ist, "CC_SA_ACCOUNT_ID") == "sa-stackvend-control-center"
    assert const(st, "BILLING_VIEWER_ROLE") == const(ist, "BILLING_VIEWER_ROLE") == "roles/billing.viewer"


def test_cc_admin_role_counts_conditional_does_not(cc_results):
    g = _grants(cc_results["results"]["admin_and_conditional"])
    assert g["sa-project-provisioner"]["status"] == "GRANTED"
    assert g["sa-castor-developer"]["status"] == "CANNOT_VERIFY"
    assert "IAM condition" in g["sa-castor-developer"]["detail"]


def test_cc_no_credentials_never_fails(cc_results):
    res = cc_results["results"]["no_session"]
    assert res["http"] == 200
    assert res["json"]["has_billing_access"] is False
    assert {g["status"] for g in res["json"]["billing_user_grants"]} == {"CANNOT_VERIFY"}
    assert res["json"]["billing_healthy"] is False


def test_cc_not_configured_and_prefix(cc_results):
    res = cc_results["results"]["not_configured"]
    assert res["http"] == 200
    assert res["json"]["configured"] is False
    assert res["json"]["billing_user_grants"] == []
    assert res["urls"] == []
    pre = cc_results["results"]["prefixed"]
    assert pre["json"]["billing_account_id"] == "01AAAA-BBBBBB-CCCCCC"
    assert {g["status"] for g in pre["json"]["billing_user_grants"]} == {"GRANTED"}


def test_dashboard_card_renders_per_service_account_status():
    html = _read(DASHBOARD)
    start = html.index("<!-- Google Cloud Billing Account Governance Card -->")
    card = html[start:html.index("<!-- Universal VCS & Git Gateway Governance Card -->")]
    assert "billingStatus.has_billing_access" not in card
    assert 'x-for="g in (billingStatus.billing_user_grants || [])"' in card
    assert "'NOT granted'" in card and "'Cannot verify'" in card
    assert 'x-text="g.fix_command"' in card and 'x-text="billingStatus.grant_fix_apply"' in card
    # under the per-SA fix, under the Cannot verify commands (BILLING-CARD-COMMANDS) and in "Why"
    assert card.count('x-text="billingStatus.grant_fix_where"') == 3
    assert card.count('x-text="billingStatus.grant_fix_apply"') == 2
    # an unknown project (grant_fix_apply == "") hides the "re-runs ... or" clause instead of an empty <code>
    assert ('<span x-show="billingStatus.grant_fix_apply">re-runs <code class="text-indigo-300 font-mono select-all" '
            'x-text="billingStatus.grant_fix_apply"></code>, or </span>runs these three commands') in card
    assert "g.status === 'CANNOT_VERIFY'" in card
    assert 'x-for="cmd in (billingStatus.grant_fix_commands || [])"' in card and 'x-text="cmd"' in card
    assert "grant_fix_commands: []," in html
    # the existing console steps stay
    assert "Steps to Authorize Billing:" in card and "+ Add Principal" in card
    assert "grant_fix_where: ''," in html
    assert "billing_user_grants: []," in html and "billing_healthy: false," in html
