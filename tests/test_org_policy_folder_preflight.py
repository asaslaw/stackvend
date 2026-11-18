"""
ORG-POLICY-FOLDER (owner 10-28): scripts/apply.sh and scripts/bootstrap.sh run a READ-ONLY Organization Policy
Administrator preflight (scripts/common/org_policy_preflight.sh: folders/<id>:testIamPermissions over REST, token from
`gcloud auth print-access-token` on curl's stdin). Permissions present -> the folder "no external VM IPs" policy is
planned; absent / any error -> not planned (TF_VAR_create_folder_vm_external_ip_policy = false), a WARNING with the
fix, exit 0 (the install never fails for it); an explicit value in the tfvars wins (no call); a policy already in state
stays planned.

Runs the real scripts with lane 5's logging stubs on PATH (no gcloud, no tofu apply, no network) plus a curl stub that
answers the folder testIamPermissions from a canned body (the tag check asks the organization and answers 403 here
unless the tfvars decide it). `tofu console` (the wrapper's tfvars parser) is the real OpenTofu.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import re
import unittest

import test_platform_safe_apply_lane5 as lane5

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
ORG = "123456789012"
FOLDER = "4242"
URL = f"https://cloudresourcemanager.googleapis.com/v3/folders/{FOLDER}:testIamPermissions"
PERMS = ("orgpolicy.policies.create", "orgpolicy.policies.update", "orgpolicy.policy.get", "orgpolicy.policy.set")
STATE_ADDR = "google_org_policy_policy.managed_folder_vm_external_ip[0]"
EXCLUDE = "-exclude=google_org_policy_policy.managed_folder_vm_external_ip"
GET_URL = f"https://orgpolicy.googleapis.com/v2/folders/{FOLDER}/policies/compute.vmExternalIpAccess"
READ_DATA = '{"permissions":["orgpolicy.policy.get"]}'
NOT_SET_UP = "Folder 'no external VM IPs' policy not set up"

# curl stub: logs argv, records which headers came on stdin (--config -: "auth-on-stdin", "quota=<project>"), and
# answers by URL:
#   - the folder decision check (testIamPermissions) from STUB_ORGPOL_* (body file, HTTP code, mode none|fail|answer);
#   - the FU1 in-state read check (the same URL, data = only orgpolicy.policy.get) from STUB_ORGPOL_READ_* (body,
#     code; default: nothing granted, 200);
#   - the F2 existing-folder-policy GET (Org Policy API v2) with STUB_ORGPOL_GET_CODE (default 404);
#   - the organization (tag) check with 403.
# Other curl calls (bootstrap's Firestore seeding) just log and exit 0.
CURL_STUB = r'''#!/bin/bash
echo "curl $*" >> "$STUB_LOG"
out=""; cfg=""; prev=""; url=""; data=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  [ "$prev" = "--config" ] && cfg="$a"
  [ "$prev" = "--data" ] && data="$a"
  case "$a" in https://*) url="$a" ;; esac
  prev="$a"
done
if [ "$cfg" = "-" ]; then
  stdin="$(cat)"
  if printf '%s\n' "$stdin" | grep -q '^header = "Authorization: Bearer '; then echo "auth-on-stdin" >> "$STUB_LOG.curl"; fi
  q="$(printf '%s\n' "$stdin" | sed -n 's/^header = "x-goog-user-project: \(.*\)"$/\1/p')"
  [ -n "$q" ] && echo "quota=$q" >> "$STUB_LOG.curl"
fi
case "$url" in
  https://orgpolicy.googleapis.com/v2/folders/*/policies/compute.vmExternalIpAccess)
    [ -n "$out" ] && echo '{"name": "folders/x/policies/compute.vmExternalIpAccess"}' > "$out"
    printf '%s' "${STUB_ORGPOL_GET_CODE:-404}"
    exit 0 ;;
  */v3/folders/*:testIamPermissions)
    if [ "$data" = '{"permissions":["orgpolicy.policy.get"]}' ]; then
      [ -n "$out" ] && cat "${STUB_ORGPOL_READ_BODY:-/dev/null}" > "$out"
      [ -n "${STUB_ORGPOL_READ_BODY:-}" ] || echo '{}' > "$out"
      printf '%s' "${STUB_ORGPOL_READ_CODE:-200}"
      exit 0
    fi
    case "${STUB_ORGPOL_MODE:-none}" in
      fail) exit 7 ;;
      none) exit 0 ;;
    esac
    [ -n "$out" ] && cat "$STUB_ORGPOL_BODY" > "$out"
    printf '%s' "${STUB_ORGPOL_CODE:-200}"
    exit 0 ;;
  */v3/organizations/*:testIamPermissions)
    [ -n "$out" ] && echo '{}' > "$out"
    printf '403'
    exit 0 ;;
esac
exit 0
'''

TOFU_EXTRA = ('case "$1" in plan) echo "TFVAR=${TF_VAR_create_folder_vm_external_ip_policy-<unset>}" '
              '>> "$STUB_LOG.tfvar" ;; esac\n')


def _tfvars(extra="", folder=f"folders/{FOLDER}"):
    # The tag decision is explicit, so the tag preflight makes no call and these tests see only the folder check.
    lines = f'organization_id                    = "organizations/{ORG}"\ncreate_stackvend_managed_tag = true\n'
    if folder is not None:
        lines += f'castor_managed_workloads_folder_id = "{folder}"\n'
    return lane5._tfvars(extra=lines + extra)


@unittest.skipUnless(lane5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class _Harness(lane5._Harness):
    def setUp(self):
        super().setUp()
        with open(os.path.join(self.stub, "curl"), "w") as f:
            # the Folder IAM Admin preflight (BOOTSTRAP-FOLDER-IAM-PREFLIGHT) answers "granted"
            f.write(CURL_STUB.replace("#!/bin/bash\n", "#!/bin/bash\n" + lane5.FOLDER_IAM_CURL_CASE, 1))
        tofu = os.path.join(self.stub, "tofu")
        body = lane5.TOFU_STUB.replace('echo "tofu $*" >> "$STUB_LOG"\n', 'echo "tofu $*" >> "$STUB_LOG"\n' + TOFU_EXTRA, 1)
        assert "TFVAR=" in body
        with open(tofu, "w") as f:
            f.write(body)
        self.body = os.path.join(self.tmp, "orgpol.json")
        self.plan_json = os.path.join(self.tmp, "plan.json")
        with open(self.plan_json, "w") as f:
            f.write(lane5._plan_json([["create"]]))

    def respond(self, body, code="200", mode="answer"):
        with open(self.body, "w") as f:
            f.write(body)
        return {"STUB_ORGPOL_BODY": self.body, "STUB_ORGPOL_CODE": code, "STUB_ORGPOL_MODE": mode}

    def granted(self, perms=PERMS):
        return self.respond('{"permissions": [%s]}' % ", ".join(f'"{p}"' for p in perms))

    def tfvar_seen(self):
        p = self.log + ".tfvar"
        return open(p).read().split() if os.path.exists(p) else []

    def folder_calls(self):
        """The decision testIamPermissions calls (not the FU1 read-only check)."""
        return [c for c in self.calls() if c.startswith("curl ") and "/v3/folders/" in c and READ_DATA not in c]

    def read_check_calls(self):
        return [c for c in self.calls() if c.startswith("curl ") and "/v3/folders/" in c and READ_DATA in c]

    def get_calls(self):
        return [c for c in self.calls() if c.startswith("curl ") and "orgpolicy.googleapis.com/v2/folders/" in c]

    def plans(self):
        return [c for c in self.calls() if c.startswith("tofu plan")]

    def read_check(self, perms=(), code="200"):
        p = os.path.join(self.tmp, "read.json")
        with open(p, "w") as f:
            f.write('{"permissions": [%s]}' % ", ".join(f'"{x}"' for x in perms))
        return {"STUB_ORGPOL_READ_BODY": p, "STUB_ORGPOL_READ_CODE": code}

    def plan(self, tfvars=None, **env):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", tfvars if tfvars is not None else _tfvars())
        return self.run_script("apply.sh", ["plan", "-no-color"], PROJECT_ID=lane5.PROJ, **env)

    def state(self, *addrs):
        p = os.path.join(self.tmp, "state.txt")
        with open(p, "w") as f:
            f.write("".join(a + "\n" for a in addrs))
        return p


class TestApplyShOrgPolicyPreflight(_Harness):
    def test_permissions_present_plans_the_folder_policy(self):
        rc, out, err = self.plan(**self.granted())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertNotIn(NOT_SET_UP, err)
        [call] = self.folder_calls()
        self.assertIn(URL, call)
        self.assertIn("-X POST", call)
        for p in PERMS:
            self.assertIn(p, call)
        # The token never appears on curl's command line: it is passed on stdin (--config -).
        self.assertNotIn("stub-token", "\n".join(self.calls()))
        self.assertIn("--config -", call)
        # F2 GET first (token + host quota project on stdin), then the decision call (token on stdin).
        self.assertEqual(open(self.log + ".curl").read().split(),
                         ["auth-on-stdin", f"quota={lane5.PROJ}", "auth-on-stdin"])
        [get] = self.get_calls()
        self.assertIn(GET_URL, get)
        self.assertNotIn("-X ", get)
        self.assertNotIn("--data", get)
        self.assertNotIn("-exclude", "\n".join(self.plans()))
        self.assert_no_mutation_calls()

    def test_missing_permission_skips_the_policy_warns_with_the_fix_and_succeeds(self):
        rc, out, err = self.plan(**self.granted(PERMS[:2]))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn("[WARN]", err)
        self.assertIn(NOT_SET_UP, err)
        self.assertIn("orgpolicy.policy.get orgpolicy.policy.set", err)
        self.assertIn(f"roles/orgpolicy.policyAdmin on organizations/{ORG}", err)
        self.assertIn(f"gcloud organizations add-iam-policy-binding {ORG} --member=user:<your account> "
                      "--role=roles/orgpolicy.policyAdmin", err)
        self.assertIn(f"PROJECT_ID={lane5.PROJ} bash scripts/apply.sh apply", err)
        self.assertIn("VENDING.ORG_POLICY_NOT_ENFORCED", err)
        self.assert_no_mutation_calls()

    def test_no_permission_at_all_skips_the_policy(self):
        rc, out, err = self.plan(**self.granted(()))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])

    def test_http_error_skips_the_policy_and_names_the_explicit_override(self):
        rc, out, err = self.plan(**self.respond('{"error": {"code": 400}}', code="400"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn("(HTTP 400)", err)
        self.assertIn("set create_folder_vm_external_ip_policy = true", err)

    def test_curl_failure_skips_the_policy(self):
        rc, out, err = self.plan(**self.respond("", mode="fail"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn(NOT_SET_UP, err)

    def test_unparseable_body_skips_the_policy(self):
        for body in ("not json", '{"permissions": "orgpolicy.policy.set"}', "[]"):
            with self.subTest(body=body):
                open(self.log, "w").close()
                if os.path.exists(self.log + ".tfvar"):
                    os.remove(self.log + ".tfvar")
                rc, out, err = self.plan(**self.respond(body))
                self.assertEqual(rc, 0, err)
                self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])

    def test_explicit_value_wins_without_a_call(self):
        for value in ("true", "false"):
            with self.subTest(value=value):
                open(self.log, "w").close()
                if os.path.exists(self.log + ".tfvar"):
                    os.remove(self.log + ".tfvar")
                rc, out, err = self.plan(_tfvars(f"create_folder_vm_external_ip_policy = {value}\n"),
                                         **self.granted(()))
                self.assertEqual(rc, 0, err)
                self.assertEqual(self.folder_calls(), [])
                self.assertEqual(self.get_calls() + self.read_check_calls(), [])
                self.assertNotIn("THIS PLAN DELETES IT", err)
                # The wrapper exports nothing; the tfvars value reaches tofu through -var-file.
                self.assertEqual(self.tfvar_seen(), ["TFVAR=<unset>"])
                self.assertIn("explicit value wins", err)
                self.assertEqual(NOT_SET_UP in err, value == "false")

    def test_no_folder_means_no_call(self):
        rc, out, err = self.plan(_tfvars(folder=None), **self.granted())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.folder_calls(), [])
        self.assertEqual(self.tfvar_seen(), ["TFVAR=<unset>"])

    def test_bad_folder_id_skips_without_a_call(self):
        rc, out, err = self.plan(_tfvars(folder="folders/abc"), **self.granted())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.folder_calls(), [])
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])

    # ---- rule 4 + FU1: the policy is in state ----
    def test_policy_in_state_and_readable_stays_planned_without_the_decision_call(self):
        rc, out, err = self.plan(STUB_STATE_LIST=self.state(STATE_ADDR), **self.granted(()),
                                 **self.read_check(("orgpolicy.policy.get",)))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertEqual(self.folder_calls(), [])
        self.assertEqual(self.get_calls(), [])  # no F2 GET: StackVend already manages it
        [read] = self.read_check_calls()
        self.assertIn(URL, read)
        self.assertNotIn("-exclude", "\n".join(self.plans()))
        self.assertNotIn("[WARN]", err)

    def test_fu1_policy_in_state_unreadable_is_excluded_and_the_run_succeeds(self):
        rc, out, err = self.plan(STUB_STATE_LIST=self.state(STATE_ADDR), **self.granted(()), **self.read_check(()))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        [plan] = self.plans()
        self.assertTrue(plan.endswith(" -no-color " + EXCLUDE), plan)
        self.assertIn("lack orgpolicy.policy.get on folders/4242", err)
        self.assertIn("leaves that one resource out of this run", err)
        self.assert_no_mutation_calls()

    def test_fu1_apply_excludes_the_unreadable_policy_and_completes(self):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", _tfvars())
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=lane5.PROJ, PROJECT_ID=lane5.PROJ,
                                       STUB_PLAN_JSON=self.plan_json, STUB_STATE_LIST=self.state(STATE_ADDR),
                                       **self.granted(()), **self.read_check(()))
        self.assertEqual(rc, 0, out + err)
        [plan] = self.plans()
        self.assertIn(EXCLUDE, plan)
        self.assertIn("-out=", plan)
        self.assertIn("tofu apply -input=false", "\n".join(self.calls()))

    def test_fu1_explicit_true_in_state_unreadable_is_excluded(self):
        rc, out, err = self.plan(_tfvars("create_folder_vm_external_ip_policy = true\n"),
                                 STUB_STATE_LIST=self.state(STATE_ADDR), **self.read_check(()))
        self.assertEqual(rc, 0, err)
        self.assertIn(EXCLUDE, "\n".join(self.plans()))

    def test_fu1_negative_read_check_error_is_not_excluded(self):
        for code in ("403", "500"):
            with self.subTest(code=code):
                open(self.log, "w").close()
                rc, out, err = self.plan(STUB_STATE_LIST=self.state(STATE_ADDR), **self.read_check((), code=code))
                self.assertEqual(rc, 0, err)
                self.assertNotIn("-exclude", "\n".join(self.plans()))
                self.assertIn(f"read check failed (HTTP {code}), not excluded", err)

    def test_fu1_target_given_means_no_exclude_and_a_warning(self):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", _tfvars())
        rc, out, err = self.run_script("apply.sh", ["plan", "-target=google_storage_bucket.x"], PROJECT_ID=lane5.PROJ,
                                       STUB_STATE_LIST=self.state(STATE_ADDR), **self.read_check(()))
        self.assertEqual(rc, 0, err)
        [plan] = self.plans()
        self.assertNotIn("-exclude", plan)
        self.assertIn("NOT excluded because -target is set", err)

    def test_fu1_not_in_state_is_never_excluded(self):
        rc, out, err = self.plan(**self.granted(()), **self.read_check(()))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.read_check_calls(), [])
        self.assertNotIn("-exclude", "\n".join(self.plans()))

    # ---- N1: explicit false with the policy in state ----
    def test_n1_explicit_false_in_state_warns_that_the_plan_deletes_it(self):
        rc, out, err = self.plan(_tfvars("create_folder_vm_external_ip_policy = false\n"),
                                 STUB_STATE_LIST=self.state(STATE_ADDR))
        self.assertEqual(rc, 0, err)
        self.assertIn("THIS PLAN DELETES IT", err)
        self.assertIn(f"--allow-destroy={lane5.PROJ}", err)
        self.assertEqual(self.folder_calls() + self.get_calls() + self.read_check_calls(), [])

    # ---- F2: a folder policy already exists outside StackVend ----
    def test_f2_existing_folder_policy_skips_with_the_import_command(self):
        rc, out, err = self.plan(STUB_ORGPOL_GET_CODE="200", **self.granted())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertEqual(self.folder_calls(), [])  # no decision call after the 200
        [get] = self.get_calls()
        self.assertIn(GET_URL, get)
        self.assertIn("--config -", get)
        self.assertIn(f"quota={lane5.PROJ}", open(self.log + ".curl").read().split())
        self.assertIn("already exists on folders/4242 outside StackVend", err)
        self.assertIn("tofu import 'google_org_policy_policy.managed_folder_vm_external_ip[0]' "
                      "folders/4242/policies/compute.vmExternalIpAccess", err)
        self.assertIn("vending records ENFORCED if it is deny all", err)
        self.assert_no_mutation_calls()

    def test_f2_no_existing_policy_or_unreadable_continues_to_the_decision(self):
        for code in ("404", "403", "500"):
            with self.subTest(code=code):
                open(self.log, "w").close()
                if os.path.exists(self.log + ".tfvar"):
                    os.remove(self.log + ".tfvar")
                rc, out, err = self.plan(STUB_ORGPOL_GET_CODE=code, **self.granted())
                self.assertEqual(rc, 0, err)
                self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
                self.assertEqual(len(self.get_calls()), 1)
                self.assertEqual(len(self.folder_calls()), 1)
                self.assertNotIn("outside StackVend", err)

    def test_negative_similar_state_address_is_not_the_policy(self):
        rc, out, err = self.plan(STUB_STATE_LIST=self.state("module.x." + STATE_ADDR,
                                                            "google_org_policy_policy.other[0]"),
                                 **self.granted(()))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])

    def test_apply_without_permission_completes(self):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", _tfvars())
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=lane5.PROJ, PROJECT_ID=lane5.PROJ,
                                       STUB_PLAN_JSON=self.plan_json, **self.respond("{}", code="403"))
        self.assertEqual(rc, 0, out + err)
        self.assertIn("tofu apply -input=false", "\n".join(self.calls()))
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn(NOT_SET_UP, err)

    def test_caller_provided_tf_var_still_refused(self):
        """The wrapper's own export comes after the H1 scrub: a TF_VAR_* from the caller is still refused."""
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", _tfvars())
        rc, out, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=lane5.PROJ,
                                       TF_VAR_create_folder_vm_external_ip_policy="true", **self.granted())
        self.assertNotEqual(rc, 0)
        self.assertIn("TF_VAR_create_folder_vm_external_ip_policy", err)
        self.assertEqual(self.folder_calls(), [])


class TestBootstrapOrgPolicyPreflight(_Harness):
    def _run(self, **env):
        # Same answers as tests/test_lane18_v3_tag_preflight.py (org + folder 4242, stage 2 "n").
        answers = "\n".join([lane5.PROJ, "", "", f"organizations/{ORG}", "", f"folders/{FOLDER}", "", "", 
                             "octo-org", "", "", "", "", "y", lane5.PROJ, "n"])
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question (this stub never grants the tag permissions).
        return self.run_script("bootstrap.sh", [], tty_input=answers, STUB_PLAN_JSON=self.plan_json, **env)

    def test_not_an_org_policy_admin_never_aborts(self):
        rc, out, err = self._run(**self.respond('{"error": {}}', code="403"))
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertEqual(len(self.folder_calls()), 1)
        text = out + err
        self.assertGreaterEqual(text.count(NOT_SET_UP), 2)  # at the preflight and at the end
        self.assertIn("BOOTSTRAP INCOMPLETE: stage 2 did not finish (skipped)", text)

    def test_org_policy_admin_plans_the_policy(self):
        rc, out, err = self._run(**self.granted())
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertNotIn(NOT_SET_UP, out + err)


class TestStatic(unittest.TestCase):
    def _read(self, *p):
        with open(os.path.join(REPO, *p), encoding="utf-8") as f:
            return f.read()

    def test_scripts_source_and_call_the_preflight_without_aborting(self):
        apply_sh = self._read("scripts", "apply.sh")
        boot = self._read("scripts", "bootstrap.sh")
        for src in (apply_sh, boot):
            self.assertIn('. "${SCRIPT_DIR}/common/org_policy_preflight.sh"', src)
        self.assertIn("\nsv_org_policy_preflight || true\n", boot)
        # apply.sh: the 3c step wraps the preflight and is called for plan and apply only; its exclude args (FU1)
        # reach both the plan and the gated apply.
        self.assertIn("    sv_org_policy_preflight || true\n", apply_sh)
        self.assertEqual(apply_sh.count("        orgpol_preflight_step  #"), 2)
        self.assertEqual(apply_sh.count('${ORGPOL_EXCLUDE_ARGS[@]+"${ORGPOL_EXCLUDE_ARGS[@]}"}'), 2)
        self.assertIn('${SV_ORGPOL_PREFLIGHT_WARNING}', boot)  # repeated in the final summary
        self.assertIn('"${SV_ORGPOL_READ_MISSING_IN_STATE:-}" = "1"', boot)  # bootstrap warns only

    def test_f1_both_pre_enable_lists_carry_the_org_policy_api(self):
        """F1: the API is on minutes before the apply that creates the folder policy."""
        boot = self._read("scripts", "bootstrap.sh")
        target = self._read("scripts", "common", "platform_target.sh")
        for src in (boot, target):
            calls = re.findall(r"gcloud services enable(.*?)--project=", src, re.S)
            apis = [set(re.findall(r"[a-z0-9]+\.googleapis\.com", c)) for c in calls]
            self.assertTrue(any("sqladmin.googleapis.com" in a for a in apis))
            self.assertTrue(any("orgpolicy.googleapis.com" in a for a in apis))
        self.assertIn("two gcloud calls, 20 + 1 APIs", target)

    def test_every_pre_enable_call_fits_the_service_usage_batch_limit(self):
        """Service Usage refuses more than 20 services per enable call (SU_MAX_BATCH_SIZE_EXCEEDED, live 10-28)."""
        for parts in (("scripts", "bootstrap.sh"), ("scripts", "common", "platform_target.sh")):
            for c in re.findall(r"gcloud services enable(.*?)--project=", self._read(*parts), re.S):
                self.assertLessEqual(len(re.findall(r"[a-z0-9]+\.googleapis\.com", c)), 20, parts)

    def test_preflight_is_read_only(self):
        pre = self._read("scripts", "common", "org_policy_preflight.sh")
        code = [l for l in pre.splitlines() if not l.lstrip().startswith("#")]
        joined = "\n".join(code)
        self.assertIn(":testIamPermissions", joined)
        self.assertEqual(re.findall(r"-X (\w+)", joined), ["POST"])  # testIamPermissions; the F2 GET has no -X
        # The only gcloud it runs is the token read; the grant command appears only inside the printed fix text.
        runs = [l for l in code if re.search(r"(^|\$\(|\|\s*)\s*gcloud ", l)]
        self.assertEqual(len(runs), 1, runs)
        self.assertIn("gcloud auth print-access-token", runs[0])
        for bad in ("tofu apply", "IAC_BIN}\" apply", "-X PATCH", "-X DELETE", "-X PUT", ":setIamPolicy"):
            self.assertNotIn(bad, joined)
