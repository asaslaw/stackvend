"""Lane 19 L19-0d: bootstrap.sh asks for TWO OAuth clients, refuses equal ids, stores the tenant secret only in
Secret Manager (plan §2.7.2 + Fable R3 check §2 notes 1-4; register rows 27b, 44).

Runs the real scripts/bootstrap.sh under lane 5's hermetic harness (logging stubs for gcloud/tofu/curl/...; no GCP,
no network). The gcloud stub here additionally records the stdin of `secrets versions add` and lets a test choose
whether the tenant secret container exists (the ingress prompt is always asked: install-polish removed the old
org-policy probe, which called a gcloud command that does not exist).
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)

PROJ = L5.PROJ
CC = "123456789012-ccclient.apps.googleusercontent.com"
TENANT = "123456789012-tenantclient.apps.googleusercontent.com"
SECRET = "GOCSPX-lane19-dummy-secret-value"
BOOTSTRAP = os.path.join(L5.SCRIPTS, "bootstrap.sh")

WRAPPER = r'''#!/bin/bash
a="$*"
case "$a" in
  "secrets describe stackvend-tenant-google-client-secret"*) echo "gcloud $*" >> "$STUB_LOG"; exit "${STUB_TENANT_SECRET_RC:-0}" ;;
  "secrets versions add"*) echo "gcloud $*" >> "$STUB_LOG"; { echo "== $4"; cat; echo; } >> "$STUB_LOG.stdin"; exit 0 ;;
esac
exec "$(dirname "$0")/gcloud.orig" "$@"
'''


class _Boot(L5._Harness):
    def setUp(self):
        super().setUp()
        stub = os.path.join(self.stub, "gcloud")
        os.rename(stub, os.path.join(self.stub, "gcloud.orig"))
        with open(stub, "w") as f:
            f.write(WRAPPER)
        os.chmod(stub, 0o755)
        self.tfvars = os.path.join(self.platform, f"{PROJ}.tfvars")
        self.plan_json = os.path.join(self.tmp, "plan.json")
        with open(self.plan_json, "w") as f:
            f.write(L5._plan_json([["create"]]))

    def boot(self, client_answers, public=True, **env):
        head = [PROJ, "", "", "", "", "", "y", "", "", "octo-org"]  # ... GitHub owner
        # "y": the BOOTSTRAP-TAG-ADMIN-CONFIRM question, asked right after the folder ID (no organization: no tag)
        ingress = ["2"] if public else ["", ""]                               # public: mode 2; IAP: Enter + no domain
        answers = head + ingress + list(client_answers) + [PROJ, "n"]
        env.setdefault("STUB_PLAN_JSON", self.plan_json)
        return self.run_script("bootstrap.sh", [], tty_input="\n".join(answers), **env)

    def stdin_log(self):
        p = self.log + ".stdin"
        return open(p).read() if os.path.exists(p) else ""

    def assert_secret_never_leaked(self, out, err):
        self.assertNotIn(SECRET, out + err)
        self.assertNotIn(SECRET, "\n".join(self.calls()))
        if os.path.exists(self.tfvars):
            self.assertNotIn(SECRET, L5._read(self.tfvars))
        for c in self.calls():
            self.assertNotIn("castor-oauth-client", c)


class TestBootstrapTwoClients(_Boot):
    def test_equal_ids_refused_before_tfvars(self):
        rc, out, err = self.boot([CC, CC])
        self.assertNotEqual(rc, 0)
        self.assertIn("the tenant sign-in client are the SAME client", out + err)
        self.assertFalse(os.path.exists(self.tfvars))
        self.assertEqual(self.tofu_ops(), [])

    def test_two_clients_written_and_secret_only_on_secret_manager_stdin(self):
        rc, out, err = self.boot([CC, TENANT, SECRET])
        self.assertEqual(rc, 0, out + err)
        tfvars = L5._read(self.tfvars)
        self.assertIn(f'cc_google_oauth_client_id          = "{CC}"', tfvars)
        self.assertIn(f'tenant_google_client_id            = "{TENANT}"', tfvars)
        self.assert_secret_never_leaked(out, err)
        adds = [c for c in self.calls() if c.startswith("gcloud secrets versions add")]
        self.assertEqual(adds, [f"gcloud secrets versions add stackvend-tenant-google-client-secret --project={PROJ} "
                                "--data-file=- --quiet"])
        self.assertEqual(self.stdin_log(), f"== stackvend-tenant-google-client-secret\n{SECRET}\n")
        # The secret is stored only AFTER the gated apply.
        c = self.calls()
        self.assertLess(c.index(next(x for x in c if x.startswith("tofu apply"))), c.index(adds[0]))

    def test_iap_mode_cc_prompt_is_skippable(self):
        rc, out, err = self.boot(["", ""], public=False)
        self.assertEqual(rc, 0, out + err)
        tfvars = L5._read(self.tfvars)
        self.assertIn('cc_google_oauth_client_id          = ""', tfvars)
        self.assertIn('tenant_google_client_id            = ""', tfvars)
        self.assertEqual([c for c in self.calls() if c.startswith("gcloud secrets versions add")], [])

    def test_install_polish_iap_mode_says_no_oauth_client_is_needed(self):
        rc, out, err = self.boot(["", ""], public=False)
        self.assertEqual(rc, 0, out + err)
        self.assertIn("no OAuth consent screen or OAuth client is needed", out + err)
        self.assertNotIn("First configure the OAuth consent screen", out + err)
        self.assertNotIn("Add now: ", out + err)
        self.assertIn("enable_direct_iap                  = true", L5._read(self.tfvars))
        # the removed probes are never called (one did not exist; the other only decided one [OK] line)
        self.assertEqual([c for c in self.calls() if c.startswith(("gcloud org-policies", "gcloud iap oauth-brands"))], [])

    def test_install_polish_public_mode_prints_the_client_steps(self):
        rc, out, err = self.boot([CC, ""])
        self.assertEqual(rc, 0, out + err)
        self.assertIn("First configure the OAuth consent screen", out + err)
        self.assertIn("Add now: ", out + err)
        self.assertNotIn("no OAuth consent screen or OAuth client is needed", out + err)
        self.assertIn("allow_unauthenticated              = true", L5._read(self.tfvars))

    def test_malformed_ids_reprompt(self):
        rc, out, err = self.boot(["not-a-client", "123-ABC.apps.googleusercontent.com", CC, "bad", TENANT, SECRET])
        self.assertEqual(rc, 0, out + err)
        tfvars = L5._read(self.tfvars)
        self.assertIn(f'cc_google_oauth_client_id          = "{CC}"', tfvars)
        self.assertIn(f'tenant_google_client_id            = "{TENANT}"', tfvars)
        self.assertGreaterEqual((out + err).count("Not a Web OAuth client ID"), 3)

    def test_public_mode_requires_a_cc_client(self):
        rc, out, err = self.boot(["", CC, TENANT, SECRET])   # empty CC answer is re-prompted in public mode
        self.assertEqual(rc, 0, out + err)
        self.assertIn(f'cc_google_oauth_client_id          = "{CC}"', L5._read(self.tfvars))

    def test_missing_secret_container_never_falls_back(self):
        rc, out, err = self.boot([CC, TENANT, SECRET], STUB_TENANT_SECRET_RC="1")
        self.assertEqual(rc, 0, out + err)
        self.assertIn("Tenant sign-in client secret NOT stored", out + err)
        self.assertIn("Never store it in castor-oauth-client-secret", out + err)
        self.assertEqual([c for c in self.calls() if c.startswith("gcloud secrets versions add")], [])
        self.assertEqual(self.stdin_log(), "")
        self.assert_secret_never_leaked(out, err)

    # Lane 19 RT F4: a typed secret is never dropped silently when bootstrap stops before storing it.
    def assert_not_stored_guidance(self, rc, out, err):
        self.assertNotEqual(rc, 0, out + err)
        self.assertIn("Tenant sign-in client secret NOT stored: bootstrap stopped before it was written.", out + err)
        self.assertIn(f"gcloud secrets versions add stackvend-tenant-google-client-secret --project={PROJ} "
                      "--data-file=-", out + err)
        self.assertIn("Never store it in castor-oauth-client-secret", out + err)
        self.assertEqual([c for c in self.calls() if c.startswith("gcloud secrets versions add")], [])
        self.assertEqual(self.stdin_log(), "")
        self.assert_secret_never_leaked(out, err)

    def test_declined_gate_after_secret_prints_not_stored_guidance(self):
        head = [PROJ, "", "", "", "", "", "y", "", "", "octo-org", "2"]  # "y": BOOTSTRAP-TAG-ADMIN-CONFIRM
        rc, out, err = self.run_script("bootstrap.sh", [], tty_input="\n".join(head + [CC, TENANT, SECRET, "nope"]),
                                       STUB_PLAN_JSON=self.plan_json)
        self.assertIn("Confirmation did not match", out + err)
        self.assertEqual([c for c in self.calls() if c.startswith("tofu apply")], [])
        self.assert_not_stored_guidance(rc, out, err)

    def test_failed_apply_after_secret_prints_not_stored_guidance(self):
        # tofu apply fails on all 3 attempts (sleep between attempts stubbed out)
        tofu = os.path.join(self.stub, "tofu")
        os.rename(tofu, tofu + ".orig")
        with open(tofu, "w") as f:
            f.write('#!/bin/bash\nif [ "$1" = apply ]; then echo "tofu $*" >> "$STUB_LOG"; exit 1; fi\n'
                    'exec "$(dirname "$0")/tofu.orig" "$@"\n')
        with open(os.path.join(self.stub, "sleep"), "w") as f:
            f.write("#!/bin/bash\nexit 0\n")
        os.chmod(tofu, 0o755)
        os.chmod(os.path.join(self.stub, "sleep"), 0o755)
        rc, out, err = self.boot([CC, TENANT, SECRET, PROJ, PROJ])  # confirm attempts 2 and 3 as well
        self.assertIn("failed after retries", out + err)
        self.assertEqual(len([c for c in self.calls() if c.startswith("tofu apply")]), 3)
        self.assert_not_stored_guidance(rc, out, err)

    def test_stored_secret_prints_no_not_stored_guidance(self):
        rc, out, err = self.boot([CC, TENANT, SECRET])
        self.assertEqual(rc, 0, out + err)
        self.assertNotIn("NOT stored", out + err)


def test_bootstrap_has_no_xtrace():
    src = L5._read(BOOTSTRAP)
    for line in src.splitlines():
        s = line.strip()
        if s.startswith("#"):
            continue
        assert "set -x" not in s and "set -o xtrace" not in s, line
    assert 'read -r -s -p "Tenant sign-in client SECRET' in src
    assert "printf '%s' \"$TENANT_CLIENT_SECRET\" | gcloud secrets versions add stackvend-tenant-google-client-secret" in src
