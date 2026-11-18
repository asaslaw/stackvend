import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""BOOTSTRAP-FOLDER-IAM-PREFLIGHT (owner 11-03): scripts/bootstrap.sh and scripts/apply.sh check, read-only, that the
account running them holds resourcemanager.folders.setIamPolicy (Folder IAM Admin) on the managed workloads folder,
and stop with a typed error BEFORE any write when it does not.

scripts/common/folder_iam_preflight.sh: one Cloud Resource Manager v3 folders/<id>:testIamPermissions call (token on
curl's stdin). Granted -> "[OK] Folder IAM Admin preflight"; missing / 403 / 404 -> <PREFIX>_FOLDER_IAM_MISSING with
the grant command; anything else -> <PREFIX>_FOLDER_IAM_UNCHECKED (fail closed). Bootstrap runs it right after the
folder prompt (before any API enable, state bucket, vars file or tofu call); apply.sh before init and the plan of
`apply`. The behavioural tests run the real scripts under lane 5's hermetic harness (stubbed gcloud/tofu/curl; only
`tofu console` is the real engine) and skip without OpenTofu.
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)
import test_lane19_bootstrap_two_clients as L19  # noqa: E402  (module import only)

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
PROJ = L5.PROJ
FOLDER = "4242"
ACCOUNT = "installer@example.com"
SA_ACCOUNT = f"installer-sa@{PROJ}.iam.gserviceaccount.com"
URL = f"https://cloudresourcemanager.googleapis.com/v3/folders/{FOLDER}:testIamPermissions"
GRANT = ("gcloud resource-manager folders add-iam-policy-binding 4242 --member=\"user:installer@example.com\" "
         "--role=\"roles/resourcemanager.folderIamAdmin\"")
# BOOTSTRAP-TAG-ADMIN-CONFIRM: the early tag check's platform state GET answers 404 (no install yet), so with an
# organization the question comes right after the folder ID, as without one.
STATE_404_CASE = ('case "$*" in *platform%2Fstate%2Fdefault.tfstate*) echo "curl $*" >> "$STUB_LOG"; cat >/dev/null; '
                  "printf '404'; exit 0 ;; esac\n")
CURL = "#!/bin/bash\n" + L5.FOLDER_IAM_CURL_CASE + STATE_404_CASE + 'echo "curl $*" >> "$STUB_LOG"\nexit 0\n'
# gcloud: the active account comes from STUB_ACCOUNT; everything else goes to the lane 19 / lane 5 stubs.
ACCOUNT_WRAPPER = r'''#!/bin/bash
case "$*" in
  "config get-value account"*) echo "gcloud $*" >> "$STUB_LOG"; echo "${STUB_ACCOUNT:-}"; exit 0 ;;
esac
exec "$(dirname "$0")/gcloud.l19" "$@"
'''


def _source(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()


class _FolderIam(L19._Boot):
    def setUp(self):
        super().setUp()
        gcloud = os.path.join(self.stub, "gcloud")
        os.rename(gcloud, os.path.join(self.stub, "gcloud.l19"))
        for name, body in (("gcloud", ACCOUNT_WRAPPER), ("curl", CURL)):
            p = os.path.join(self.stub, name)
            with open(p, "w") as f:
                f.write(body)
            os.chmod(p, 0o755)
        self.resp = os.path.join(self.tmp, "folderiam.json")

    def answer(self, body, code="200"):
        with open(self.resp, "w") as f:
            f.write(body)
        return {"STUB_FOLDER_IAM_BODY": self.resp, "STUB_FOLDER_IAM_CODE": code}

    def granted(self, *perms):
        return self.answer(json.dumps({"permissions": list(perms)}))

    def folder_iam_log(self):
        p = self.log + ".folderiam"
        return L5._read(p).splitlines() if os.path.exists(p) else []

    def folder_iam_calls(self):
        return [c for c in self.folder_iam_log() if c.startswith("curl ")]

    def writes(self):
        return [c for c in self.calls() if c.startswith(("gcloud services", "gcloud storage buckets create",
                                                          "gcloud storage buckets update", "gcloud config set",
                                                          "gcloud secrets", "gcloud firestore"))]

    def assert_one_read_only_call(self):
        calls = self.folder_iam_calls()
        self.assertEqual(len(calls), 1, calls)
        self.assertIn(URL, calls[0])
        self.assertIn('--data {"permissions":["resourcemanager.folders.setIamPolicy","resourcemanager.folders.get"]}',
                      calls[0])
        self.assertNotIn("stub-token", calls[0])                # the token goes on stdin only
        self.assertIn("auth-on-stdin", self.folder_iam_log())


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestBootstrapFolderIamPreflight(_FolderIam):
    def boot_folder(self, folder=f"folders/{FOLDER}", **env):
        head = [PROJ, "", "", "", "", folder, "y", "", "", "octo-org"]
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        answers = head + ["", ""] + ["", ""] + [PROJ, "n"]      # IAP ingress, no OAuth clients, confirm, no stage 2
        env.setdefault("STUB_ACCOUNT", ACCOUNT)
        rc, out, err = self.run_script("bootstrap.sh", [], tty_input="\n".join(answers),
                                       STUB_PLAN_JSON=self.plan_json, **env)
        return rc, out + err

    def assert_refused_before_any_write(self, rc, out, code):
        self.assertNotEqual(rc, 0, out)
        self.assertIn(code, out)
        self.assertIn("Nothing was changed.", out)
        self.assertEqual(self.writes(), [])                      # no API enable, no state bucket, no config/secrets
        self.assertFalse(os.path.exists(self.tfvars))            # no vars file
        self.assertEqual(self.tofu_ops(), [])                    # no init / plan / apply
        self.assertNotIn("Select StackVend Deployment Mode", out)  # stopped right after the folder prompt

    def test_granted_continues_to_the_apply(self):
        rc, out = self.boot_folder(**self.granted("resourcemanager.folders.setIamPolicy", "resourcemanager.folders.get"))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"[OK]\x1b[0m Folder IAM Admin preflight: {ACCOUNT} can set IAM on folders/{FOLDER}.", out)
        self.assert_one_read_only_call()
        self.assertIn(f'castor_managed_workloads_folder_id = "folders/{FOLDER}"', L5._read(self.tfvars))
        self.assertTrue([c for c in self.tofu_ops() if c.startswith("tofu apply")])
        # the check ran before the first write
        self.assertTrue(self.writes())

    def test_bare_digits_are_checked_too(self):
        rc, out = self.boot_folder(folder=FOLDER)
        self.assertEqual(rc, 0, out)
        self.assert_one_read_only_call()

    def test_missing_permission_is_refused_before_any_write(self):
        rc, out = self.boot_folder(**self.granted("resourcemanager.folders.get"))
        self.assert_refused_before_any_write(rc, out, "BOOTSTRAP_FOLDER_IAM_MISSING")
        self.assertIn("lacks resourcemanager.folders.setIamPolicy on folders/4242", out)
        self.assertIn("grants StackVend's service accounts their roles on that folder", out)
        self.assertIn(GRANT, out)
        self.assertIn("bash scripts/pre-bootstrap.sh --check-only", out)
        self.assert_one_read_only_call()

    def test_nothing_granted_names_both_permissions(self):
        rc, out = self.boot_folder(**self.answer("{}"))
        self.assert_refused_before_any_write(rc, out, "BOOTSTRAP_FOLDER_IAM_MISSING")
        self.assertIn("lacks resourcemanager.folders.setIamPolicy resourcemanager.folders.get", out)

    def test_403_is_refused_as_missing(self):
        body = json.dumps({"error": {"code": 403, "message": "The caller does not have permission",
                                     "status": "PERMISSION_DENIED"}})
        rc, out = self.boot_folder(**self.answer(body, "403"))
        self.assert_refused_before_any_write(rc, out, "BOOTSTRAP_FOLDER_IAM_MISSING")
        self.assertIn("not visible", out)
        self.assertIn("HTTP 403: The caller does not have permission", out)
        self.assertIn(GRANT, out)
        self.assertNotIn("UNCHECKED", out)

    def test_500_is_unchecked_and_refused(self):
        body = json.dumps({"error": {"code": 500, "message": "Internal error encountered.", "status": "INTERNAL"}})
        rc, out = self.boot_folder(**self.answer(body, "500"))
        self.assert_refused_before_any_write(rc, out, "BOOTSTRAP_FOLDER_IAM_UNCHECKED")
        self.assertIn("HTTP 500: Internal error encountered.", out)
        self.assertNotIn("BOOTSTRAP_FOLDER_IAM_MISSING", out)

    def test_curl_failure_is_unchecked(self):
        rc, out = self.boot_folder(STUB_FOLDER_IAM_MODE="fail")
        self.assert_refused_before_any_write(rc, out, "BOOTSTRAP_FOLDER_IAM_UNCHECKED")
        self.assertIn("curl rc=7", out)

    def test_malformed_body_is_unchecked(self):
        rc, out = self.boot_folder(**self.answer('{"permissions": "all"}'))
        self.assert_refused_before_any_write(rc, out, "BOOTSTRAP_FOLDER_IAM_UNCHECKED")
        self.assertIn("malformed body", out)

    def test_invalid_folder_id_is_refused_without_a_call(self):
        rc, out = self.boot_folder(folder="folders/../../x")
        self.assert_refused_before_any_write(rc, out, "BOOTSTRAP_FOLDER_ID_INVALID")
        self.assertEqual(self.folder_iam_calls(), [])

    def test_service_account_gets_the_serviceaccount_member(self):
        rc, out = self.boot_folder(STUB_ACCOUNT=SA_ACCOUNT, **self.granted())
        self.assertNotEqual(rc, 0, out)
        self.assertIn(f'--member="serviceAccount:{SA_ACCOUNT}"', out)

    def test_no_folder_makes_no_call(self):
        rc, out = self.boot_folder(folder="")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.folder_iam_calls(), [])
        self.assertNotIn("Folder IAM Admin preflight", out)


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestApplyFolderIamPreflight(_FolderIam):
    def setUp(self):
        super().setUp()
        self.write_tfvars(f"folders/{FOLDER}")

    def write_tfvars(self, folder):
        # tag and folder org policy decided in the file: those preflights make no call.
        self.write(f"infra/platform/{PROJ}.tfvars", L5._tfvars(extra=(
            'organization_id                    = "organizations/123456789012"\n'
            f'castor_managed_workloads_folder_id = "{folder}"\n'
            "create_stackvend_managed_tag = false\n"
            "create_folder_vm_external_ip_policy = false\n")))

    def apply(self, args=(), **env):
        env.setdefault("STUB_ACCOUNT", ACCOUNT)
        rc, out, err = self.run_script("apply.sh", ["apply"] + list(args), tty_input=PROJ, PROJECT_ID=PROJ,
                                       STUB_PLAN_JSON=self.plan_json, **env)
        return rc, out + err

    def assert_refused_before_plan(self, rc, out, code):
        self.assertNotEqual(rc, 0, out)
        self.assertIn(code, out)
        self.assertIn("Nothing was changed.", out)
        self.assertEqual(self.tofu_ops(), [])                    # no init, no plan, no apply
        self.assertEqual([c for c in self.calls() if "services enable" in c], [])

    def test_granted_goes_on_to_plan_and_apply(self):
        rc, out = self.apply()
        self.assertEqual(rc, 0, out)
        self.assertIn(f"Folder IAM Admin preflight: {ACCOUNT} can set IAM on folders/{FOLDER}.", out)
        self.assert_one_read_only_call()
        self.assertTrue([c for c in self.tofu_ops() if c.startswith("tofu plan")])
        self.assertTrue([c for c in self.tofu_ops() if c.startswith("tofu apply")])

    def test_missing_is_refused_before_plan(self):
        rc, out = self.apply(**self.granted("resourcemanager.folders.get"))
        self.assert_refused_before_plan(rc, out, "APPLY_FOLDER_IAM_MISSING")
        self.assertIn(GRANT, out)
        self.assertIn("bash scripts/pre-bootstrap.sh --check-only", out)
        self.assertNotIn("BOOTSTRAP_", out)
        self.assert_one_read_only_call()

    def test_403_is_refused_before_plan(self):
        rc, out = self.apply(**self.answer('{"error": {"code": 403, "message": "denied"}}', "403"))
        self.assert_refused_before_plan(rc, out, "APPLY_FOLDER_IAM_MISSING")

    def test_500_is_unchecked_before_plan(self):
        rc, out = self.apply(**self.answer('{"error": {"code": 503, "message": "backend unavailable"}}', "503"))
        self.assert_refused_before_plan(rc, out, "APPLY_FOLDER_IAM_UNCHECKED")
        self.assertIn("HTTP 503: backend unavailable", out)

    def test_empty_folder_is_not_checked(self):
        self.write_tfvars("")
        rc, out = self.apply(**self.granted())
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.folder_iam_calls(), [])

    def test_plan_and_refresh_only_are_not_gated(self):
        for args in (["plan"], ["apply", "-refresh-only"]):
            rc, out, err = self.run_script("apply.sh", args, tty_input=PROJ, PROJECT_ID=PROJ, STUB_ACCOUNT=ACCOUNT,
                                           STUB_PLAN_JSON=self.plan_json, **self.granted())
            self.assertEqual(rc, 0, (args, out + err))
        self.assertEqual(self.folder_iam_calls(), [])


class TestFolderIamPreflightStatic(unittest.TestCase):
    def test_bootstrap_checks_right_after_the_folder_prompt(self):
        boot = _source("scripts/bootstrap.sh")
        call = boot.index('sv_folder_iam_preflight BOOTSTRAP "${FOLDER_ID}" "${ACTIVE_ACCOUNT}"')
        self.assertLess(boot.index("FOLDER_ID=${INPUT_FOLDER_ID:-${STACKVEND_FOLDER_ID:-}}"), call)
        for first_write in ("gcloud services enable", 'gcloud config set project', 'cat <<EOF > "${TFVARS_PATH}"',
                            "sv_gated_apply bootstrap", "buckets create"):
            self.assertLess(call, boot.index(first_write), first_write)
        # the old informational sentence is gone (it contradicted the refusal)
        self.assertNotIn("403 on google_folder_iam_member", boot)

    def test_apply_checks_before_init_and_plan_of_apply_only(self):
        src = _source("scripts/apply.sh")
        case = src[src.index("    apply)\n        "):]
        case = case[:case.index(";;")]
        self.assertLess(case.index("folder_iam_preflight_step"), case.index("tf_ready_existing"))
        self.assertLess(case.index("folder_iam_preflight_step"), case.index("sv_gated_apply"))
        self.assertEqual(src.count("folder_iam_preflight_step\n") + src.count("folder_iam_preflight_step  #"), 1)

    def test_token_never_on_the_command_line(self):
        src = _source("scripts/common/folder_iam_preflight.sh")
        self.assertIn("curl -sS --max-time 20 --config -", src)
        self.assertNotIn('-H "Authorization', src)


if __name__ == "__main__":
    unittest.main()
