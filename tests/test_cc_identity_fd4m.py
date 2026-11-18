"""FD-4M: Control Center identity and exposure (remainder after FD-4E).

Runtime cases run tests/cc_identity_harness_fd4m.py in clean `python -I` subprocesses (hermetic: outbound
sockets/DNS refused and recorded, ADC disabled, Firestore/Secret Manager stubbed), once per ADMIN_EMAIL
mode. Static cases parse the HCL text. The optional OpenTofu case evaluates the real F6 expressions offline
(no providers, no backend) and is skipped when `tofu` is not on PATH.

Rows marked "legit" are the Do-No-Harm negative tests: the legitimate path must keep working.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
HARNESS = os.path.join(HERE, "cc_identity_harness_fd4m.py")
FINOPS = "sa-castor-finops@mock-stackvend-project.iam.gserviceaccount.com"

PLATFORM_MAIN = os.path.join(REPO, "infra", "platform", "main.tf")
PLATFORM_VARS = os.path.join(REPO, "infra", "platform", "variables.tf")
TFVARS_EXAMPLE = os.path.join(REPO, "infra", "platform", "terraform.tfvars.example")
BOOTSTRAP = os.path.join(REPO, "scripts", "bootstrap.sh")


def _run_harness(mode):
    # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy) for the child.
    env = hermetic_guard.child_env(
        drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL", "CC_INSECURE_LOCAL_COOKIES"),
        extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run([sys.executable, "-I", HARNESS, mode], capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1]), out.stderr


class _HarnessCase(unittest.TestCase):
    MODE = "main"

    @classmethod
    def setUpClass(cls):
        cls.r, cls.stderr = _run_harness(cls.MODE)

    def expect(self, case, value):
        self.assertEqual(self.r[case], value, case)


class TestFD4MMainMode(_HarnessCase):
    """ADMIN_EMAIL=owner@example.com (the FD-4E configuration of the script-deployed dev install)."""
    MODE = "main"

    def test_hermetic(self):
        self.expect("network_attempts", [])
        self.expect("shared_anon_cookie_jar_empty", True)
        self.expect("mode", "main")

    # ------------------------------------------------------------ F1: docs gated
    def test_f1_anonymous_docs_get_sign_in_html(self):
        for p in ("/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"):
            self.expect(f"f1_anon{p}", [401, "text/html", False])

    def test_f1_legit_public_paths_unchanged(self):
        self.expect("f1_anon_health", 200)
        self.expect("f1_anon_google_login_bad_cred", [401, "application/json"])  # reached the route, not the gate
        self.expect("f1_anon_root", [401, True])
        self.expect("sign_in_html_mentions_docs", False)

    def test_f1_legit_signed_in_users_see_docs(self):
        for who in ("viewer", "owner"):
            self.expect(f"f1_{who}_docs", [200, True])
            self.expect(f"f1_{who}_openapi", [200, True])
            self.expect(f"f1_{who}_redoc", 200)

    def test_f1_legit_iap_and_former_platform_bearer_refused(self):
        self.expect("f1_iap_valid_openapi", 200)
        self.expect("f1_iap_no_assertion_docs", 401)
        self.expect("f1_finops_bearer_job_route", 403)   # C10: no platform caller (the job route is ADMIN, humans only)
        self.expect("f1_finops_bearer_openapi", 403)   # C10: refused like every service bearer

    def test_f1_verified_but_unlisted_user_forbidden(self):
        self.expect("f1_stranger_docs", [403, "text/html"])

    # ------------------------------------------------------------ F2/H2/H3: revocation sticks
    def test_f2_inactive_doc_revokes_env_admin(self):
        self.expect("f2_owner_bool_false", None)
        self.expect("f2_owner_bool_false_http", 403)

    def test_h3_string_false_revokes(self):
        self.expect("f2_owner_string_false", None)
        self.expect("f2_owner_string_false_http", 403)
        self.expect("f2_bob_string_false", None)

    def test_h3_null_and_garbage_fail_closed(self):
        self.expect("f2_owner_explicit_null", None)
        self.expect("f2_owner_garbage", None)
        self.assertIn("unreadable is_active='garbage'", self.stderr)

    def test_h2_stale_in_memory_grant_ignored_when_firestore_answers(self):
        self.expect("f2_carol_added", [200, True])
        self.expect("n2_carol_in_registry_after_post", False)
        self.expect("f2_carol_active", "WORKLOAD_MANAGER")
        self.expect("f2_carol_still_in_local_registry", True)  # the stale grant really exists
        self.expect("f2_carol_after_fs_delete", None)
        self.expect("f2_carol_after_fs_delete_http", 403)

    def test_f2_legit_active_records_unchanged(self):
        self.expect("f2_owner_no_doc", "ADMIN")
        self.expect("f2_owner_no_doc_http", 200)
        self.expect("f2_owner_bootstrap_string_true", "ADMIN")
        self.expect("f2_owner_bootstrap_string_true_http", 200)
        self.expect("f2_owner_bool_true", "ADMIN")
        self.expect("f2_owner_no_field", "ADMIN")
        self.expect("f2_owner_viewer_doc", "VIEWER")
        self.expect("f2_viewer_active", "VIEWER")
        self.expect("f2_bob_active", ["WORKLOAD_MANAGER", ["w1"], True])
        self.expect("f2_finops_inactive_doc", None)   # C10: the former platform caller is not an allow-listed ADMIN

    def test_f2_legit_break_glass_on_firestore_outage(self):
        self.expect("f2_outage_owner", "ADMIN")
        self.expect("f2_outage_carol_registry", "WORKLOAD_MANAGER")
        self.expect("f2_outage_viewer", None)
        self.expect("f2_outage_finops", None)   # C10: empty platform-caller allow-list
        self.expect("f2_db_none_owner", "ADMIN")
        self.expect("f2_db_none_carol_registry", "WORKLOAD_MANAGER")

    def test_n2_revoked_user_not_resurrected_by_outage(self):
        self.expect("n2_frank_added", [200, True, False])
        self.expect("n2_frank_put", [200, False, "VIEWER"])
        self.expect("n2_frank_outage_after_revoke", None)

    def test_n2_legit_registry_break_glass_when_firestore_absent_or_failing(self):
        # FD-4CI-b-3b: the break-glass grant still works on this instance, but the answer is 503 (not stored), not 200.
        self.expect("n2_hank_post_during_outage", [503, "WORKLOAD_MANAGER"])
        self.expect("n2_db_none_post", [200, "WORKLOAD_MANAGER"])
        self.expect("n2_db_none_put", [200, ["w2"]])

    def test_n1_owner_demotion_survives_malformed_fields(self):
        self.expect("n1_owner_viewer_ts_added_at", "VIEWER")
        self.expect("n1_owner_viewer_str_workloads", "VIEWER")

    def test_n1_timestamp_added_at_no_lockout(self):
        self.expect("n1_user_ts_added_at", ["WORKLOAD_MANAGER", "2026-10-01T12:00:00+00:00", ["w1", "w2"]])

    def test_n1_unreadable_doc_fails_closed(self):
        self.expect("n1_owner_unreadable_doc", None)

    def test_n1_legit_admin_doc_unchanged(self):
        self.expect("n1_legit_admin_doc", ["ADMIN", "2026-09-01T00:00:00+00:00", "owner@example.com", ["a", "b"]])

    # ------------------------------------------------------------ F3 / H8 with ADMIN_EMAIL set
    def test_f3_legit_env_admin_kept(self):
        self.expect("config_default_admin_email", "owner@example.com")
        self.expect("registry_keys", ["owner@example.com"])
        self.assertNotIn("ADMIN_EMAIL is empty", self.stderr)

    def test_h8_legit_delete_paths(self):
        self.expect("h8_delete_normal_user", [200, False])
        self.expect("h8_delete_env_admin_guard", 400)

    # ------------------------------------------------------------ F4: Secure cookie
    def test_f4_secure_for_every_environment(self):
        for env in ("prod", "production", "dev", "test", "unset"):
            self.expect(f"f4_login_env_{env}", [200, ["castor_session", "stackvend_session"], [True, True]])

    def test_f4_opt_out_ignored_on_cloud_run(self):
        self.expect("f4_login_k_service_ignores_optout", [200, ["castor_session", "stackvend_session"], [True, True]])

    def test_f4_legit_local_opt_out(self):
        self.expect("f4_login_local_optout", [200, ["castor_session", "stackvend_session"], [False, False]])
        self.expect("f4_login_local_optout_other_value", [200, ["castor_session", "stackvend_session"], [True, True]])

    def test_f4_set_cookie_attributes(self):
        self.expect("f4_login_set_cookie_raw", "HttpOnly; Max-Age=604800; Path=/; SameSite=lax; Secure")

    def test_f4_legit_login_round_trip(self):
        self.expect("f4_round_trip", 200)

    def test_f4_logout_matches_cookie_attributes(self):
        attrs = ["httponly", "max-age=0", "path=/", "samesite=lax", "secure"]
        self.expect("f4_logout", [200, [["castor_session", attrs], ["stackvend_session", attrs]]])
        self.expect("f4_logout_post_status", 200)


class TestFD4MAdminEmailUnset(_HarnessCase):
    """ADMIN_EMAIL not set (the trigger-deployed dev install runs with it empty)."""
    MODE = "unset"

    def test_hermetic(self):
        self.expect("network_attempts", [])
        self.expect("mode", "unset")

    def test_f3_no_predictable_default_admin(self):
        self.expect("config_default_admin_email", "")
        self.expect("registry_keys", [])
        self.expect("f3_castor_local_record", None)
        self.expect("f3_castor_local_cookie_users", 403)
        self.expect("f3_castor_local_cookie_root", 403)
        self.expect("f3_outage_castor_local", None)
        self.expect("f3_empty_email_record", None)
        self.expect("sign_in_html_mentions_default_admin", False)

    def test_f3_startup_warning(self):
        self.assertIn("ADMIN_EMAIL is empty", self.stderr)

    def test_f3_legit_firestore_admin_and_delete(self):
        self.expect("f3_fs_admin_users", 200)
        self.expect("f3_h8_delete_with_empty_admin", [200, False])


class TestFD4MAdminEmailEmpty(TestFD4MAdminEmailUnset):
    """ADMIN_EMAIL="" behaves exactly like unset."""
    MODE = "empty"

    def test_hermetic(self):
        self.expect("network_attempts", [])
        self.expect("mode", "empty")


# ---------------------------------------------------------------- static: F5 / F6 / H3 source
def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestFD4MStaticHCL(unittest.TestCase):
    def test_f6_admin_email_no_blind_replace(self):
        # STAGE-JOB-RUNNER: the services' ADMIN_EMAIL value is infra/platform/stage_runner.tf
        # local.platform_service_env["ADMIN_EMAIL"] (shared with the stage-runner job); main.tf points at it.
        self.assertIn('value = local.platform_service_env["ADMIN_EMAIL"]', _read(PLATFORM_MAIN))
        runner = _read(os.path.join(os.path.dirname(PLATFORM_MAIN), "stage_runner.tf"))
        m = re.search(r'\n\s*ADMIN_EMAIL = (.*?\n\s*\))\n', runner, re.S)
        self.assertTrue(m)
        self.assertNotIn("replace(", m.group(1))
        self.assertIn('startswith(try(var.authorized_invoker_members[0], ""), "user:")', m.group(1))

    def test_f6_admin_email_validation_and_check(self):
        var = re.search(r'variable "admin_email" \{.*?\n\}\n', _read(PLATFORM_VARS), re.S)
        self.assertTrue(var)
        self.assertIn("validation {", var.group(0))
        self.assertIn('check "control_center_admin_email"', _read(PLATFORM_MAIN))
        self.assertIn("# admin_email", _read(TFVARS_EXAMPLE))

    def test_h3_bootstrap_writes_boolean_and_lowercase_id(self):
        src = _read(BOOTSTRAP)
        self.assertNotIn('\\"is_active\\": {\\"stringValue\\"', src)
        self.assertIn('\\"is_active\\": {\\"booleanValue\\": true}', src)
        self.assertIn("ADMIN_DOC_ID=$(printf '%s' \"$ACTIVE_ACCOUNT\" | tr '[:upper:]' '[:lower:]')", src)
        self.assertIn("documents/authorized_users/${ADMIN_DOC_ID}", src)


# ---------------------------------------------------------------- optional: OpenTofu offline evaluation (F6/H4)
@unittest.skipUnless(shutil.which("tofu"), "tofu not on PATH")
class TestFD4MTofuOffline(unittest.TestCase):
    """Evaluates the real F6 expression, validation and check block copied from infra/platform. No providers,
    no backend, no modules: OpenTofu never contacts a registry."""

    @classmethod
    def setUpClass(cls):
        main_tf, vars_tf = _read(PLATFORM_MAIN), _read(PLATFORM_VARS)
        # STAGE-JOB-RUNNER: the expression lives in stage_runner.tf local.platform_service_env (main.tf points at it)
        runner_tf = _read(os.path.join(os.path.dirname(PLATFORM_MAIN), "stage_runner.tf"))
        expr = re.search(r'\n\s*ADMIN_EMAIL = (.*?\n\s*\))\n', runner_tf, re.S).group(1)
        check = re.search(r'check "control_center_admin_email" \{.*?\n\}\n', main_tf, re.S).group(0)
        blocks = [re.search(r'variable "%s" \{.*?\n\}\n' % n, vars_tf, re.S).group(0)
                  for n in ("admin_email", "allow_unauthenticated", "authorized_invoker_members")]
        cls.tmp = tempfile.mkdtemp(prefix="fd4m-tofu-")
        with open(os.path.join(cls.tmp, "main.tf"), "w", encoding="utf-8") as f:
            f.write("\n".join(blocks) + "\n" + check + "\noutput \"admin_email_env\" {\n  value = " + expr + "\n}\n")
        cli_cfg = os.path.join(cls.tmp, "empty.tfrc")
        open(cli_cfg, "w").close()
        cls.env = {"PATH": os.environ.get("PATH", ""), "HOME": cls.tmp, "TF_CLI_CONFIG_FILE": cli_cfg,
                   "TF_DATA_DIR": os.path.join(cls.tmp, ".tofu"), "CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "1"}
        init = cls._tofu("init", "-backend=false", "-input=false", "-no-color")
        assert init.returncode == 0, init.stdout + init.stderr

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _tofu(cls, *args):
        return subprocess.run(["tofu", *args], cwd=cls.tmp, env=cls.env, capture_output=True, text=True, timeout=120)

    def _plan(self, admin_email="", members=(), allow=True):
        return self._tofu("plan", "-refresh=false", "-input=false", "-no-color", "-lock=false",
                          "-var", f"admin_email={admin_email}",
                          "-var", f"allow_unauthenticated={'true' if allow else 'false'}",
                          "-var", "authorized_invoker_members=" + json.dumps(list(members)))

    def _value(self, **kw):
        r = self._plan(**kw)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        m = re.search(r'admin_email_env\s*=\s*"([^"]*)"', r.stdout)
        self.assertTrue(m, r.stdout)
        return m.group(1), r.stdout + r.stderr

    def test_validate(self):
        r = self._tofu("validate", "-no-color")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_validation_rejects_prefixed_or_spaced(self):
        for bad in ("user:a@b.com", "a @b.com"):
            r = self._plan(admin_email=bad)
            self.assertNotEqual(r.returncode, 0, bad)
            self.assertIn("Invalid value for variable", r.stdout + r.stderr)

    def test_legit_validation_accepts(self):
        for ok in ("a@b.com", "Owner.Name@Example.COM"):
            self.assertEqual(self._value(admin_email=ok)[0], ok)
        self.assertEqual(self._value()[0], "")

    def test_h4_leading_user_member_still_derives(self):
        self.assertEqual(self._value(members=["user:a@x.com", "group:g@x.com"], allow=False)[0], "a@x.com")

    def test_f6_non_user_leading_member_yields_empty_plus_warning(self):
        for members in (["domain:x.com", "user:a@x.com"], ["group:g@x.com"]):
            val, out = self._value(members=members, allow=False)
            self.assertEqual(val, "")
            self.assertIn("Check block assertion failed", out)

    def test_legit_explicit_admin_email_wins(self):
        val, out = self._value(admin_email="a@b.com", members=["user:z@x.com"], allow=False)
        self.assertEqual(val, "a@b.com")
        self.assertNotIn("Check block assertion failed", out)

    def test_legit_public_mode_no_warning(self):
        val, out = self._value(members=[])
        self.assertEqual(val, "")
        self.assertNotIn("Check block assertion failed", out)


if __name__ == "__main__":
    unittest.main()
