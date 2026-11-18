"""
Lane 18 v3 (owner rule 10-18): "Install must be simple, smooth and never fail, only providing warnings in settings
for lack of billing user and tag admin."

(a) scripts/apply.sh and scripts/bootstrap.sh run a READ-ONLY Tag Administrator preflight
    (organizations/<org>:testIamPermissions over REST, token from `gcloud auth print-access-token` on curl's stdin):
    permissions present -> the tag is planned; absent / any error -> not planned (TF_VAR_create_stackvend_managed_tag
    = false), a WARNING, exit 0; an explicit create_stackvend_managed_tag in the tfvars wins (no call at all); a tag
    already in state stays planned (prevent_destroy would refuse its destroy).
Runs the real scripts with lane 5's logging stubs on PATH (no gcloud, no tofu apply, no network) plus a curl stub
that answers testIamPermissions from a canned body. `tofu console` (the wrapper's tfvars parser) is the real OpenTofu.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import re
import unittest

import test_platform_safe_apply_lane5 as lane5

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
ORG = "123456789012"
URL = f"https://cloudresourcemanager.googleapis.com/v3/organizations/{ORG}:testIamPermissions"
PERMS = ("resourcemanager.tagKeys.create", "resourcemanager.tagValues.create", "resourcemanager.tagValues.setIamPolicy")
READ_PERMS = ("resourcemanager.tagKeys.get", "resourcemanager.tagValues.get", "resourcemanager.tagValues.getIamPolicy")
FULL_STATE = ("google_tags_tag_key.stackvend_managed[0]", "google_tags_tag_value.stackvend_managed_true[0]",
              "google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user[0]")

# curl stub: consumes the --config on stdin (records only whether an Authorization header came that way), logs the
# argv, writes the canned body to -o and prints the canned HTTP code for -w. Other curl calls (bootstrap's Firestore
# seeding) just log and exit 0.
CURL_STUB = r'''#!/bin/bash
echo "curl $*" >> "$STUB_LOG"
# BOOTSTRAP-TAG-ADMIN-CONFIRM: bootstrap's early tag check GETs the platform state (default 404: no install yet).
case "$*" in *platform%2Fstate%2Fdefault.tfstate*)
  st_out=""; st_prev=""
  for st_a in "$@"; do [ "$st_prev" = "-o" ] && st_out="$st_a"; st_prev="$st_a"; done
  cat >/dev/null
  if [ -n "${STUB_STATE_GET_BODY:-}" ]; then cat "$STUB_STATE_GET_BODY" > "$st_out"; fi
  printf '%s' "${STUB_STATE_GET_CODE:-404}"
  exit 0 ;;
esac
out=""; cfg=""; prev=""
for a in "$@"; do
  [ "$prev" = "-o" ] && out="$a"
  [ "$prev" = "--config" ] && cfg="$a"
  prev="$a"
done
if [ "$cfg" = "-" ]; then
  if grep -q '^header = "Authorization: Bearer ' ; then echo "auth-on-stdin" >> "$STUB_LOG.curl"; fi
fi
case "${STUB_CURL_MODE:-none}" in
  fail) exit 7 ;;
  none) exit 0 ;;
esac
[ -n "$out" ] && cat "$STUB_CURL_BODY" > "$out"
printf '%s' "${STUB_CURL_CODE:-200}"
exit 0
'''

# tofu stub = lane 5's, plus: every plan records the TF_VAR the preflight exported.
TOFU_EXTRA = 'case "$1" in plan) echo "TFVAR=${TF_VAR_create_stackvend_managed_tag-<unset>}" >> "$STUB_LOG.tfvar" ;; esac\n'


def _tfvars(extra=""):
    # create_folder_vm_external_ip_policy explicit: the ORG-POLICY-FOLDER preflight then makes no call and prints no
    # warning, so these tests see only the tag preflight.
    return lane5._tfvars(extra=(f'organization_id                    = "organizations/{ORG}"\n'
                                'castor_managed_workloads_folder_id = "folders/4242"\n'
                                'create_folder_vm_external_ip_policy = true\n' + extra))


@unittest.skipUnless(lane5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class _PreflightHarness(lane5._Harness):
    def setUp(self):
        super().setUp()
        with open(os.path.join(self.stub, "curl"), "w") as f:
            # the Folder IAM Admin preflight (BOOTSTRAP-FOLDER-IAM-PREFLIGHT) answers "granted"
            f.write(CURL_STUB.replace("#!/bin/bash\n", "#!/bin/bash\n" + lane5.FOLDER_IAM_CURL_CASE, 1))
        tofu = os.path.join(self.stub, "tofu")
        body = lane5.TOFU_STUB.replace('echo "tofu $*" >> "$STUB_LOG"\n', 'echo "tofu $*" >> "$STUB_LOG"\n' + TOFU_EXTRA, 1)
        body = body.replace('version) echo "OpenTofu v1.13.1"', 'version) echo "${STUB_ENGINE_VERSION:-OpenTofu v1.13.1}"', 1)
        assert body.count("STUB_ENGINE_VERSION") == 1 and "TFVAR=" in body
        with open(tofu, "w") as f:
            f.write(body)
        self.body = os.path.join(self.tmp, "resp.json")
        self.plan_json = os.path.join(self.tmp, "plan.json")
        with open(self.plan_json, "w") as f:
            f.write(lane5._plan_json([["create"]]))

    def respond(self, body, code="200", mode="answer"):
        with open(self.body, "w") as f:
            f.write(body)
        return {"STUB_CURL_BODY": self.body, "STUB_CURL_CODE": code, "STUB_CURL_MODE": mode}

    def granted(self, perms=PERMS):
        return self.respond('{"permissions": [%s]}' % ", ".join(f'"{p}"' for p in perms))

    def tfvar_seen(self):
        p = self.log + ".tfvar"
        return open(p).read().split() if os.path.exists(p) else []

    def curl_calls(self):
        # Only the tag check (organizations/<org>:testIamPermissions); the ORG-POLICY-FOLDER preflight asks the
        # folder and is tested in tests/test_org_policy_folder_preflight.py.
        return [c for c in self.calls() if c.startswith("curl ") and "testIamPermissions" in c
                and "/v3/organizations/" in c]

    def plan(self, tfvars=None, **env):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", tfvars if tfvars is not None else _tfvars())
        return self.run_script("apply.sh", ["plan", "-no-color"], PROJECT_ID=lane5.PROJ, **env)


class TestApplyShTagPreflight(_PreflightHarness):
    def test_permissions_present_plans_the_tag(self):
        rc, out, err = self.plan(**self.granted())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertNotIn("[WARN]", err)
        [call] = self.curl_calls()
        self.assertIn(URL, call)
        self.assertIn("-X POST", call)
        for p in PERMS:
            self.assertIn(p, call)
        # The token never appears on curl's command line: it is passed on stdin (--config -).
        self.assertNotIn("stub-token", "\n".join(self.calls()))
        self.assertIn("--config -", call)
        self.assertEqual(open(self.log + ".curl").read().split(), ["auth-on-stdin"])
        self.assert_no_mutation_calls()

    def test_missing_permission_skips_the_tag_warns_and_succeeds(self):
        rc, out, err = self.plan(**self.granted(PERMS[:1]))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn("[WARN]", err)
        self.assertIn("Deletion safety tag not set up", err)
        self.assertIn("resourcemanager.tagValues.create resourcemanager.tagValues.setIamPolicy", err)
        self.assertIn(f"roles/resourcemanager.tagAdmin on organizations/{ORG}", err)
        self.assertIn(f"PROJECT_ID={lane5.PROJ} bash scripts/apply.sh apply", err)

    def test_http_error_skips_the_tag(self):
        rc, out, err = self.plan(**self.respond('{"error": {"code": 403}}', code="403"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn("(HTTP 403)", err)

    def test_curl_failure_skips_the_tag(self):
        rc, out, err = self.plan(**self.respond("", mode="fail"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn("[WARN]", err)

    def test_unparseable_body_skips_the_tag(self):
        for body in ("not json", '{"permissions": "resourcemanager.tagKeys.create"}', "[]"):
            with self.subTest(body=body):
                open(self.log + ".tfvar", "w").close()
                rc, out, err = self.plan(**self.respond(body))
                self.assertEqual(rc, 0, err)
                self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])

    def test_explicit_tfvar_wins_and_nothing_is_called(self):
        for value in ("true", "false"):
            with self.subTest(value=value):
                open(self.log, "w").close()
                open(self.log + ".tfvar", "w").close()
                rc, out, err = self.plan(_tfvars(f"create_stackvend_managed_tag = {value}\n"),
                                         **self.granted(PERMS[:1] if value == "true" else PERMS))
                self.assertEqual(rc, 0, err)
                self.assertEqual(self.curl_calls(), [])
                # No TF_VAR from the wrapper: the -var-file value is what tofu uses.
                self.assertEqual(self.tfvar_seen(), ["TFVAR=<unset>"])
                self.assertIn(f"create_stackvend_managed_tag = {value} is set", err)

    def _state(self, *addrs):
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write("google_firestore_database.stackvend_guard\n" + "".join(a + "\n" for a in addrs))
        return state

    def test_tag_already_in_state_stays_planned_without_permission(self):
        rc, out, err = self.plan(STUB_STATE_LIST=self._state(*FULL_STATE), **self.granted(READ_PERMS))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertIn("kept unchanged", err)
        self.assertNotIn("WILL STOP", err)
        [call] = self.curl_calls()
        for p in PERMS + READ_PERMS:
            self.assertIn(p, call)

    def test_partial_tag_in_state_gets_a_distinct_warning_and_exit_0(self):
        """RT F4: key in state, value / IAM not (a pre-v3 apply that died on tagValues.create)."""
        rc, out, err = self.plan(STUB_STATE_LIST=self._state(FULL_STATE[0]), **self.granted(READ_PERMS))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertIn("THIS APPLY WILL STOP AT THE TAG: only 1 of the 3", err)
        self.assertNotIn("kept unchanged", err)

    def test_partial_tag_in_state_with_tag_admin_is_silent(self):
        rc, out, err = self.plan(STUB_STATE_LIST=self._state(FULL_STATE[0]), **self.granted(PERMS + READ_PERMS))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertNotIn("[WARN]", err)

    # ---- row L18-F5: an unreadable in-state tag is excluded from the plan (OpenTofu -exclude) ----
    EXCLUDES = [f"-exclude={a[:-3]}" for a in FULL_STATE]

    def _plans(self):
        return [c for c in self.calls() if c.startswith("tofu plan")]

    def test_tag_in_state_without_read_permission_is_excluded_and_the_run_succeeds(self):
        rc, out, err = self.plan(STUB_STATE_LIST=self._state(*FULL_STATE), **self.granted(()))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        [plan] = self._plans()
        self.assertTrue(plan.endswith(" -no-color " + " ".join(self.EXCLUDES)), plan)
        self.assertIn("roles/resourcemanager.tagViewer", err)
        self.assertIn("DEFERRED", err)
        self.assertIn("google_cloud_run_v2_service.services", err)

    def test_apply_excludes_the_unreadable_tag_and_completes(self):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", _tfvars())
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=lane5.PROJ, PROJECT_ID=lane5.PROJ,
                                       STUB_PLAN_JSON=self.plan_json, STUB_STATE_LIST=self._state(*FULL_STATE),
                                       **self.granted(()))
        self.assertEqual(rc, 0, out + err)
        [plan] = self._plans()
        for x in self.EXCLUDES:
            self.assertIn(x, plan)
        self.assertIn("-out=", plan)
        self.assertIn("tofu apply -input=false", "\n".join(self.calls()))

    def test_tag_in_state_with_read_permission_is_not_excluded(self):
        rc, out, err = self.plan(STUB_STATE_LIST=self._state(*FULL_STATE), **self.granted(READ_PERMS))
        self.assertEqual(rc, 0, err)
        self.assertNotIn("-exclude", "\n".join(self._plans()))
        self.assertNotIn("L18-F5", err)

    def test_tag_not_in_state_is_never_excluded(self):
        rc, out, err = self.plan(**self.granted(()))
        self.assertEqual(rc, 0, err)
        self.assertNotIn("-exclude", "\n".join(self._plans()))

    def test_target_given_means_no_exclude_and_a_warning(self):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", _tfvars())
        rc, out, err = self.run_script("apply.sh", ["plan", "-target=google_storage_bucket.x"], PROJECT_ID=lane5.PROJ,
                                       STUB_STATE_LIST=self._state(*FULL_STATE), **self.granted(()))
        self.assertEqual(rc, 0, err)
        [plan] = self._plans()
        self.assertNotIn("-exclude", plan)
        self.assertIn("-target=google_storage_bucket.x", plan)
        self.assertIn("NOT excluded because -target is set", err)

    def test_engine_without_exclude_means_a_warning_only(self):
        # RC B1: OpenTofu < 1.10 is now refused before anything runs (test below), so the engine without -exclude
        # that can still reach this step is HashiCorp Terraform (>= 1.10).
        for engine, version, semver in (("terraform", "Terraform v1.10.5", "1.10.5"),):
            with self.subTest(engine=engine):
                open(self.log, "w").close()
                if engine == "terraform":
                    os.rename(os.path.join(self.stub, "tofu"), os.path.join(self.stub, "terraform"))
                rc, out, err = self.plan(STUB_STATE_LIST=self._state(*FULL_STATE), STUB_ENGINE_VERSION=version,
                                         STUB_ENGINE_SEMVER=semver, **self.granted(()))
                self.assertEqual(rc, 0, err)
                [plan] = self._plans()
                self.assertNotIn("-exclude", plan)
                self.assertIn("cannot exclude the deletion safety tag", err)
                self.assertIn(f"{engine} cannot exclude", err)
                if engine == "terraform":
                    os.rename(os.path.join(self.stub, "terraform"), os.path.join(self.stub, "tofu"))

    def test_state_lookalike_address_does_not_count(self):
        """Exact state addresses only (no substring match): a different resource whose address contains the text
        does not keep the tag planned."""
        state = os.path.join(self.tmp, "state.txt")
        with open(state, "w") as f:
            f.write('module.x.google_tags_tag_key.stackvend_managed[0]\ngoogle_tags_tag_key.stackvend_managed_old[0]\n')
        rc, out, err = self.plan(STUB_STATE_LIST=state, **self.granted(()))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])

    def test_no_organization_means_no_call(self):
        rc, out, err = self.plan(lane5._tfvars(), **self.granted())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.curl_calls(), [])
        self.assertEqual(self.tfvar_seen(), ["TFVAR=<unset>"])

    def test_bad_org_id_skips_without_a_call(self):
        rc, out, err = self.plan(lane5._tfvars(extra='organization_id = "organizations/abc"\n'
                                                     'castor_managed_workloads_folder_id = "folders/4242"\n'),
                                 **self.granted())
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.curl_calls(), [])
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])

    def test_apply_without_permission_completes(self):
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", _tfvars())
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=lane5.PROJ, PROJECT_ID=lane5.PROJ,
                                       STUB_PLAN_JSON=self.plan_json, **self.respond("{}", code="403"))
        self.assertEqual(rc, 0, out + err)
        self.assertIn("tofu apply -input=false", "\n".join(self.calls()))
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        self.assertIn("Deletion safety tag not set up", err)

    def test_caller_provided_tf_var_still_refused(self):
        """The wrapper's own export comes after the H1 scrub: a TF_VAR_* from the caller is still refused."""
        self.write(f"infra/platform/{lane5.PROJ}.tfvars", _tfvars())
        rc, out, err = self.run_script("apply.sh", ["plan"], PROJECT_ID=lane5.PROJ,
                                       TF_VAR_create_stackvend_managed_tag="true", **self.granted())
        self.assertNotEqual(rc, 0)
        self.assertIn("TF_VAR_create_stackvend_managed_tag", err)
        self.assertEqual(self.curl_calls(), [])


class TestBootstrapTagPreflight(_PreflightHarness):
    def _run(self, tag_answer=(), **env):
        # project, region, zone, org, billing, folder, [BOOTSTRAP-TAG-ADMIN-CONFIRM answer, asked right after the
        # folder only when the tag will not be created], env, VCS, GitHub owner, ingress (Enter = Direct
        # IAP), corp domain, CC OAuth client, tenant client, typed project id, deploy services? (no billing account ->
        # no grant prompt)
        answers = "\n".join([lane5.PROJ, "", "", f"organizations/{ORG}", "", "folders/4242", *tag_answer, "", "",
                             "octo-org", "", "", "", "", lane5.PROJ, "n"])
        return self.run_script("bootstrap.sh", [], tty_input=answers, STUB_PLAN_JSON=self.plan_json, **env)

    def test_not_a_tag_admin_never_aborts(self):
        # BOOTSTRAP-TAG-ADMIN-CONFIRM: after "y" to the question (tests/test_bootstrap_tag_admin_confirm.py).
        rc, out, err = self._run(tag_answer=("y",), **self.respond('{"error": {}}', code="403"))
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=false"])
        # BOOTSTRAP-TAG-ADMIN-CONFIRM: one early check (before any write) and the preflight before the plan.
        self.assertEqual(len(self.curl_calls()), 2)
        text = out + err
        self.assertGreaterEqual(text.count("Deletion safety tag not set up"), 2)  # at the preflight and at the end
        self.assertIn("BOOTSTRAP INCOMPLETE: stage 2 did not finish (skipped)", text)  # stage 2 answered "n"

    def test_tag_admin_plans_the_tag(self):
        rc, out, err = self._run(**self.granted())
        self.assertEqual(rc, 0, out + err)
        self.assertEqual(self.tfvar_seen(), ["TFVAR=true"])
        self.assertNotIn("Deletion safety tag not set up", out + err)


class TestStatic(unittest.TestCase):
    def _read(self, *p):
        with open(os.path.join(REPO, *p), encoding="utf-8") as f:
            return f.read()

    def test_scripts_source_the_preflight_and_bootstrap_never_aborts_on_it(self):
        apply_sh = self._read("scripts", "apply.sh")
        boot = self._read("scripts", "bootstrap.sh")
        for src in (apply_sh, boot):
            self.assertIn('. "${SCRIPT_DIR}/common/tag_admin_preflight.sh"', src)
        self.assertIn("sv_tag_admin_preflight || true", boot)
        self.assertIn("sv_tag_admin_preflight || true", apply_sh)
        # Called for plan and apply only.
        self.assertEqual(apply_sh.count("        lane18_tag_admin_preflight_step\n"), 2)

    def test_preflight_is_read_only(self):
        pre = self._read("scripts", "common", "tag_admin_preflight.sh")
        code = "\n".join(l for l in pre.splitlines() if not l.lstrip().startswith("#"))
        self.assertIn(":testIamPermissions", code)
        # BOOTSTRAP-TAG-ADMIN-CONFIRM: the block PRINTS the grant command (never runs it); only that exact line is set
        # aside.
        grant_line = ('        echo "   gcloud organizations add-iam-policy-binding ${org} --member=\\"$(sv_tag_member '
                      '"${account}")\\" --role=\\"${SV_TAG_REQUIRED_ROLE}\\""')
        self.assertEqual(code.split("\n").count(grant_line), 1)
        printed = "\n".join(l for l in code.split("\n") if l != grant_line)
        for bad in ("add-iam-policy-binding", ":setIamPolicy", "gcloud resource-manager tags",
                    "tofu apply", "IAC_BIN}\" apply", "-X PATCH", "-X DELETE", "-X PUT"):
            self.assertNotIn(bad, printed)
        self.assertEqual(re.findall(r"-X (\w+)", code), ["POST"])

    def test_tag_resources_gated_by_the_new_variable(self):
        guard = self._read("infra", "platform", "destructive_guard.tf")
        self.assertIn("managed_tag_enabled = local.managed_tag_scope_set && var.create_stackvend_managed_tag != false",
                      guard)
        variables = self._read("infra", "platform", "variables.tf")
        blk = variables[variables.index('variable "create_stackvend_managed_tag"'):]
        blk = blk[:blk.index("\n}\n")]
        self.assertIn("type        = bool", blk)
        self.assertIn("default     = null", blk)
