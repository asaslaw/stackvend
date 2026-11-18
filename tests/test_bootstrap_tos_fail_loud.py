import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""BOOTSTRAP-TOS-FAIL-LOUD (live finding 11-03): a failed `gcloud services enable` stops scripts/bootstrap.sh (and
the pre-enable of scripts/apply.sh apply) with a typed error instead of carrying on into the next prompts.

scripts/common/platform_target.sh sv_enable_apis_or_die classifies the failure from gcloud's structured error details:
the `reason` of the google.rpc.ErrorInfo item gcloud prints (as YAML) under its ERROR line. UREQ_TOS_NOT_ACCEPTED ->
<PREFIX>_CLOUD_TERMS_NOT_ACCEPTED; anything else -> <PREFIX>_API_ENABLE_FAILED: <service(s)>: <gcloud's message>.
The failure texts below are gcloud 583's own rendering of the Service Usage error (api_lib/util/exceptions.py
HttpException, default details format). The behavioural tests run the real scripts under lane 5's hermetic harness
(stubbed gcloud/tofu/curl; only `tofu console` is the real engine) and skip without OpenTofu.

Also here: the VCS menu prints the literal "$0/mo" (it used to expand $0 to the script path).
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
ACCOUNT = "new-admin@example.com"

TOS_STDERR = (
    "ERROR: (gcloud.services.enable) FAILED_PRECONDITION: The terms of service 'cloud' for service(s) "
    "'iap.googleapis.com' must be accepted. Please visit the Developers Console to accept the terms of service "
    "(https://console.developers.google.com/terms/cloud).\n"
    "- '@type': type.googleapis.com/google.rpc.PreconditionFailure\n"
    "  violations:\n"
    "  - description: Terms of service not accepted\n"
    "    subject: cloud\n"
    "    type: googleapis.com/tos\n"
    "- '@type': type.googleapis.com/google.rpc.ErrorInfo\n"
    "  domain: serviceusage.googleapis.com\n"
    "  metadata:\n"
    "    services: iap.googleapis.com\n"
    "    tosId: cloud\n"
    "  reason: UREQ_TOS_NOT_ACCEPTED\n")
DENIED_STDERR = (
    "ERROR: (gcloud.services.enable) PERMISSION_DENIED: Permission denied to enable service [iap.googleapis.com]\n"
    "- '@type': type.googleapis.com/google.rpc.ErrorInfo\n"
    "  domain: serviceusage.googleapis.com\n"
    "  metadata:\n"
    "    services: iap.googleapis.com\n"
    "  reason: AUTH_PERMISSION_DENIED\n")
# The ToS words in prose only, no ErrorInfo reason: not classified as the terms (no prose matching).
PROSE_ONLY_STDERR = ("ERROR: (gcloud.services.enable) FAILED_PRECONDITION: The terms of service 'cloud' must be "
                     "accepted. reason: UREQ_TOS_NOT_ACCEPTED\n")
# The enum somewhere other than the ErrorInfo's own `reason` key (here: a metadata value): not the terms either.
NESTED_STDERR = ("ERROR: (gcloud.services.enable) FAILED_PRECONDITION: Precondition check failed.\n"
                 "- '@type': type.googleapis.com/google.rpc.ErrorInfo\n"
                 "  domain: serviceusage.googleapis.com\n"
                 "  metadata:\n"
                 "    reason: UREQ_TOS_NOT_ACCEPTED\n"
                 "  reason: SERVICE_CONFIG_NOT_FOUND\n")
# core/show_structured_logs=always: every stderr line is a JSON record; the message carries the same text.
STRUCTURED_STDERR = json.dumps({"version": "0.0.1", "verbosity": "ERROR", "timestamp": "2026-11-03T10:00:00.000Z",
                                "message": TOS_STDERR[len("ERROR: "):].rstrip("\n"),
                                "error": {"type": "HttpException", "details": None}}) + "\n"

# gcloud: the active account comes from STUB_ACCOUNT; `services enable` fails when its arguments start with
# STUB_ENABLE_FAIL ("iap.googleapis.com " = the single IAP enable only; "serviceusage" = the 20-API batch), printing
# the file STUB_ENABLE_STDERR on stderr; everything else goes to the lane 19 / lane 5 stubs.
WRAPPER = r'''#!/bin/bash
case "$*" in
  "config get-value account"*) echo "gcloud $*" >> "$STUB_LOG"; echo "${STUB_ACCOUNT:-}"; exit 0 ;;
  "services enable "*)
      echo "gcloud $*" >> "$STUB_LOG"
      a="$*"; rest="${a#services enable }"
      if [ -n "${STUB_ENABLE_FAIL:-}" ] && [ "${rest#${STUB_ENABLE_FAIL}}" != "${rest}" ]; then
          [ -n "${STUB_ENABLE_STDERR:-}" ] && cat "${STUB_ENABLE_STDERR}" >&2
          exit "${STUB_ENABLE_RC:-1}"
      fi
      echo "Operation \"operations/acat.p2-stub\" finished successfully." >&2
      exit 0 ;;
esac
exec "$(dirname "$0")/gcloud.l19" "$@"
'''


def _source(rel):
    with open(os.path.join(REPO, rel), encoding="utf-8") as f:
        return f.read()


class _Tos(L19._Boot):
    def setUp(self):
        super().setUp()
        gcloud = os.path.join(self.stub, "gcloud")
        os.rename(gcloud, os.path.join(self.stub, "gcloud.l19"))
        with open(gcloud, "w") as f:
            f.write(WRAPPER)
        os.chmod(gcloud, 0o755)

    def failing(self, match, stderr, rc=1):
        p = os.path.join(self.tmp, "enable-stderr.txt")
        with open(p, "w") as f:
            f.write(stderr)
        return {"STUB_ENABLE_FAIL": match, "STUB_ENABLE_STDERR": p, "STUB_ENABLE_RC": rc}

    def enables(self):
        return [c for c in self.calls() if c.startswith("gcloud services enable")]

    def writes(self):
        return [c for c in self.calls() if c.startswith(("gcloud storage buckets create", "gcloud storage buckets update",
                                                          "gcloud config set", "gcloud secrets", "gcloud firestore"))]


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestBootstrapApiEnable(_Tos):
    def bootstrap(self, **env):
        head = [PROJ, "", "", "", "", "", "y", "", "", "octo-org"]
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        answers = head + ["", ""] + ["", ""] + [PROJ, "n"]       # IAP ingress, no OAuth clients, confirm, no stage 2
        env.setdefault("STUB_ACCOUNT", ACCOUNT)
        rc, out, err = self.run_script("bootstrap.sh", [], tty_input="\n".join(answers),
                                       STUB_PLAN_JSON=self.plan_json, **env)
        return rc, out + err

    def assert_stopped_before_any_write(self, rc, out, code):
        self.assertNotEqual(rc, 0, out)
        self.assertIn(code, out)
        self.assertIn("Nothing was written.", out)
        self.assertEqual(self.writes(), [])                      # no gcloud config, state bucket, secrets
        self.assertFalse(os.path.exists(self.tfvars))            # no vars file
        self.assertEqual(self.tofu_ops(), [])                    # no init / plan / apply
        self.assertNotIn("Google sign-in", out)                  # the next prompts never ran

    def test_success_is_unchanged(self):
        rc, out = self.bootstrap()
        self.assertEqual(rc, 0, out)
        self.assertNotIn("API_ENABLE_FAILED", out)
        self.assertNotIn("CLOUD_TERMS", out)
        e = self.enables()
        self.assertEqual(len(e), 2, e)                           # the 20 base APIs, then the IAP enable
        self.assertEqual(len([s for s in e[0].split() if s.endswith(".googleapis.com")]), 20)
        self.assertTrue(e[1].startswith("gcloud services enable iap.googleapis.com "))
        self.assertIn('Operation "operations/acat.p2-stub" finished successfully.', out)  # gcloud's output shown
        c = self.calls()
        self.assertLess(c.index(e[0]), c.index(f"gcloud config set project {PROJ} --quiet"))
        self.assertTrue(os.path.exists(self.tfvars))
        self.assertTrue([x for x in self.tofu_ops() if x.startswith("tofu apply")])

    def test_vcs_menu_prints_the_literal_zero_dollar_price(self):
        rc, out = self.bootstrap()
        self.assertEqual(rc, 0, out)
        self.assertIn("Bare Git repositories stored in Cloud Storage ($0/mo idle cost, zero database)", out)
        self.assertNotIn("bootstrap.sh/mo", out)

    def test_terms_not_accepted_on_the_base_apis_stops(self):
        rc, out = self.bootstrap(**self.failing("serviceusage.googleapis.com ", TOS_STDERR))
        self.assert_stopped_before_any_write(rc, out, "BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED")
        self.assertIn(f"BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED: {ACCOUNT} has not accepted the Google Cloud Terms of "
                      f"Service. Sign in to https://console.cloud.google.com once as {ACCOUNT}, accept the terms, "
                      "then re-run. Nothing was written.", out)
        self.assertIn("reason: UREQ_TOS_NOT_ACCEPTED", out)     # gcloud's own output is still shown
        self.assertEqual(len(self.enables()), 1)                 # stopped at the first enable
        self.assertNotIn("Control Center Ingress Security Posture", out)
        self.assertNotIn("API_ENABLE_FAILED", out)

    def test_terms_not_accepted_on_the_iap_enable_stops(self):
        rc, out = self.bootstrap(**self.failing("iap.googleapis.com ", TOS_STDERR))
        self.assert_stopped_before_any_write(rc, out, "BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED")
        self.assertIn(f"{ACCOUNT} has not accepted the Google Cloud Terms of Service", out)
        self.assertIn("Ensuring the Identity-Aware Proxy API is enabled", out)
        self.assertNotIn("Additional IAP principal", out)        # the next prompt never ran
        self.assertEqual(len(self.enables()), 2)

    def test_other_iap_failure_is_api_enable_failed(self):
        rc, out = self.bootstrap(**self.failing("iap.googleapis.com ", DENIED_STDERR))
        self.assert_stopped_before_any_write(rc, out, "BOOTSTRAP_API_ENABLE_FAILED")
        self.assertIn("BOOTSTRAP_API_ENABLE_FAILED: iap.googleapis.com: (gcloud.services.enable) PERMISSION_DENIED: "
                      "Permission denied to enable service [iap.googleapis.com] Nothing was written.", out)
        self.assertNotIn("CLOUD_TERMS", out)

    def test_silent_batch_failure_names_the_apis_and_the_exit_code(self):
        rc, out = self.bootstrap(**self.failing("serviceusage.googleapis.com ", "", rc=2))
        self.assert_stopped_before_any_write(rc, out, "BOOTSTRAP_API_ENABLE_FAILED")
        self.assertIn("BOOTSTRAP_API_ENABLE_FAILED: serviceusage.googleapis.com and 19 more (20 APIs): the API enable "
                      "exited with code 2 (the gcloud output is above). Nothing was written.", out)

    def test_terms_words_in_prose_only_are_not_the_terms(self):
        rc, out = self.bootstrap(**self.failing("serviceusage.googleapis.com ", PROSE_ONLY_STDERR))
        self.assert_stopped_before_any_write(rc, out, "BOOTSTRAP_API_ENABLE_FAILED")
        self.assertNotIn("CLOUD_TERMS", out)

    def test_enum_outside_the_errorinfo_reason_is_not_the_terms(self):
        rc, out = self.bootstrap(**self.failing("serviceusage.googleapis.com ", NESTED_STDERR))
        self.assert_stopped_before_any_write(rc, out, "BOOTSTRAP_API_ENABLE_FAILED")
        self.assertNotIn("CLOUD_TERMS", out)

    def test_structured_logs_are_unpacked(self):
        rc, out = self.bootstrap(**self.failing("serviceusage.googleapis.com ", STRUCTURED_STDERR))
        self.assert_stopped_before_any_write(rc, out, "BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED")

    def test_unknown_account_still_says_what_to_do(self):
        rc, out = self.bootstrap(STUB_ACCOUNT="", **self.failing("serviceusage.googleapis.com ", TOS_STDERR))
        self.assert_stopped_before_any_write(rc, out, "BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED")
        self.assertIn("the signed-in gcloud account has not accepted the Google Cloud Terms of Service", out)


@unittest.skipUnless(L5.REAL_TOFU, "needs OpenTofu for the local `tofu console` tfvars parser")
class TestApplyApiEnable(_Tos):
    def setUp(self):
        super().setUp()
        # tag, folder org policy and folder IAM decided in the file: those preflights make no call.
        self.write(f"infra/platform/{PROJ}.tfvars", L5._tfvars(extra=(
            'organization_id                    = "organizations/123456789012"\n'
            'castor_managed_workloads_folder_id = ""\n'
            "create_stackvend_managed_tag = false\n"
            "create_folder_vm_external_ip_policy = false\n")))

    def apply(self, **env):
        env.setdefault("STUB_ACCOUNT", ACCOUNT)
        rc, out, err = self.run_script("apply.sh", ["apply"], tty_input=PROJ, PROJECT_ID=PROJ,
                                       STUB_PLAN_JSON=self.plan_json, **env)
        return rc, out + err

    def test_success_applies(self):
        rc, out = self.apply()
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(self.enables()), 2)
        self.assertTrue([x for x in self.tofu_ops() if x.startswith("tofu apply")])

    def test_terms_not_accepted_stops_before_the_apply(self):
        rc, out = self.apply(**self.failing("serviceusage.googleapis.com ", TOS_STDERR))
        self.assertNotEqual(rc, 0, out)
        self.assertIn(f"APPLY_CLOUD_TERMS_NOT_ACCEPTED: {ACCOUNT} has not accepted the Google Cloud Terms of Service.",
                      out)
        self.assertIn("then re-run. Nothing was applied.", out)
        self.assertNotIn("BOOTSTRAP_", out)
        self.assertFalse([x for x in self.tofu_ops() if x.startswith("tofu apply")])

    def test_other_failure_stops_before_the_apply(self):
        rc, out = self.apply(**self.failing("orgpolicy.googleapis.com ", DENIED_STDERR))
        self.assertNotEqual(rc, 0, out)
        self.assertIn("APPLY_API_ENABLE_FAILED: orgpolicy.googleapis.com: (gcloud.services.enable) PERMISSION_DENIED",
                      out)
        self.assertIn("Nothing was applied.", out)
        self.assertFalse([x for x in self.tofu_ops() if x.startswith("tofu apply")])


class TestApiEnableStatic(unittest.TestCase):
    def test_no_enable_is_ignored_any_more(self):
        for rel in ("scripts/bootstrap.sh", "scripts/common/platform_target.sh", "scripts/apply.sh"):
            src = _source(rel)
            code = [l for l in src.splitlines() if not l.lstrip().startswith("#")]
            for i, line in enumerate(code):
                if "gcloud services enable" not in line:
                    continue
                self.assertIn("sv_enable_apis_or_die", line + code[i - 1], (rel, line))
                j = i
                while code[j].rstrip().endswith("\\"):
                    j += 1
                self.assertNotIn("|| true", code[j], (rel, code[j]))

    def test_bootstrap_enables_before_the_first_write(self):
        boot = _source("scripts/bootstrap.sh")
        first_enable = boot.index('sv_enable_apis_or_die BOOTSTRAP "${ACTIVE_ACCOUNT}" "Nothing was written." gcloud')
        iap = boot.index("gcloud services enable iap.googleapis.com --project=")
        for write in ('gcloud config set project "${PROJECT_ID}" --quiet', 'cat <<EOF > "${TFVARS_PATH}"',
                      'cp -p "${TFVARS_PATH}"', "buckets create", "sv_gated_apply bootstrap"):
            self.assertLess(first_enable, boot.index(write), write)
            self.assertLess(iap, boot.index(write), write)

    def test_classification_matches_the_errorinfo_reason_exactly(self):
        src = _source("scripts/common/platform_target.sh")
        self.assertIn("in_info = line == \"- '@type': type.googleapis.com/google.rpc.ErrorInfo\"", src)
        self.assertIn('re.fullmatch(r"  reason: ([A-Z][A-Z0-9_]*)", line) if in_info else None', src)
        self.assertIn('"UREQ_TOS_NOT_ACCEPTED" in reasons', src)

    def test_quickstart_sign_in_mentions_the_terms(self):
        qs = _source("documentation/quickstart.md")
        sign_in = qs[qs.index("### Sign in"):qs.index("### Prepare the host project and folder")]
        self.assertIn("accept the Google Cloud Terms of Service once", sign_in)
        self.assertIn("verify a phone number once", sign_in)
        self.assertIn("BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED", sign_in)


if __name__ == "__main__":
    unittest.main()
