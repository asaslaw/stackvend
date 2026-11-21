"""FD-103 (SEC-HOTFIX-FIRST-RUN-CLIENT): the Control Center's first-run sign-in setup takes no client from a request.

Runs tests/cc_identity_harness_fd103.py in a clean `python -I` subprocess (the root suite replaces google.oauth2 /
fastapi with MagicMocks in sys.modules, so real-crypto auth tests must not run in-process; see test_cc_identity_fd4e).

Route order of POST /auth/config-client-id, one test per step: pinned -> 409 | no session and no IAP identity -> 401 |
not ADMIN -> 403 | malformed id -> 400 | state unknown -> 503 | configured -> rotation (unchanged) | absent behind IAP
-> 403 (unchanged) | absent -> typed 409 FIRST_RUN_CLIENT_OUT_OF_BAND. Plus: the R1a-02 replay (also inside a forced
IAP-discovery failure window), the legitimate sign-in paths (negative tests), the Secret Manager error rule of
config.get_google_oauth_client_id, /health without has_google_oauth_client_id, and the absent-state sign-in page.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import json
import os
import subprocess
import sys
import unittest
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "cc_identity_harness_fd103.py")
CC_DIR = os.path.join(HERE, "..", "apps", "control-center")
NEW = "222-owner.apps.googleusercontent.com"
FS_CLIENT = "555-firestore.apps.googleusercontent.com"
CODE = "FIRST_RUN_CLIENT_OUT_OF_BAND"

# Nothing changed, nothing verified, nothing issued.
NO_EFFECT = {"set_cookie": False, "auth_doc_unchanged": True, "cc_identity_unchanged": True, "sm_writes": 0,
             "client_unchanged": True, "verify_calls": 0}


class _Tags(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class TestFirstRunFD103(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET"),
                                       extra={"PROJECT_ID": "mock-stackvend-project",
                                              "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
        out = subprocess.run([sys.executable, "-I", HARNESS], capture_output=True, text=True, timeout=300, env=env)
        assert out.returncode == 0, out.stderr[-4000:]
        cls.r = json.loads(out.stdout.strip().splitlines()[-1])

    def outcome(self, case, status, code=None, state_read=None):
        got = self.r[case]
        self.assertEqual(got["status"], status, (case, got))
        self.assertEqual(got["code"], code, (case, got))
        for k, v in NO_EFFECT.items():
            self.assertEqual(got[k], v, (case, k, got))
        if state_read is False:
            self.assertEqual(got["state_reads"], 0, (case, got))
            self.assertEqual(got["sm_reads"], 0, (case, got))
            self.assertEqual(got["fs_platform_config_reads"], 0, (case, got))
        return got

    def test_harness_made_no_network_calls(self):
        self.assertEqual(self.r["network_attempts"], [])

    # ---------------------------------------------------------------- route order
    def test_step1_pinned_409_unchanged(self):
        for case in ("step1_pinned_anon", "step1_pinned_admin"):
            got = self.outcome(case, 409, state_read=False)
            self.assertIn("cc_google_oauth_client_id", got["detail"])  # the unchanged string detail

    def test_step2_anonymous_401_before_any_state_read(self):
        self.outcome("step2_anonymous", 401, state_read=False)
        self.outcome("step2_anonymous_no_credential", 401, state_read=False)

    def test_step3_not_admin_403_before_any_state_read(self):
        self.outcome("step3_viewer", 403, state_read=False)
        self.outcome("step3_unlisted_user", 403, state_read=False)

    def test_step4_format_400_after_identity(self):
        self.outcome("step4_admin_malformed", 400, state_read=False)
        self.outcome("step4_anonymous_malformed", 401, state_read=False)

    def test_step5_unknown_state_503(self):
        got = self.outcome("step5_admin_unknown", 503)
        self.assertEqual(got["state_reads"], 1)

    def test_step6_configured_admin_rotation_unchanged(self):
        # Negative test (Do No Harm): rotation by an administrator still writes and answers SUCCESS.
        got = self.r["step6_admin_rotation"]
        self.assertEqual([got["status"], got["sm_writes"], got["auth_doc_unchanged"], got["set_cookie"], got["verify_calls"]],
                         [200, 1, False, False, 0])
        self.assertEqual(self.r["step6_rotated_value"], "333-rotated.apps.googleusercontent.com")
        self.outcome("step6_viewer_rotation", 403, state_read=False)

    def test_step7_absent_behind_iap_403_unchanged(self):
        got = self.outcome("step7_iap_admin_absent", 403)
        self.assertEqual(got["state_reads"], 1)

    def test_step8_absent_typed_409(self):
        for case in ("step8_admin_absent", "step8_admin_absent_no_credential"):
            got = self.outcome(case, 409, code=CODE)
            self.assertEqual(got["state_reads"], 1)
            detail = got["detail"]
            self.assertEqual(sorted(detail), ["code", "env", "message", "tfvar"])
            self.assertEqual([detail["tfvar"], detail["env"]], ["cc_google_oauth_client_id", "GOOGLE_OAUTH_CLIENT_ID"])
            msg = detail["message"]
            for needle in ("cc_google_oauth_client_id", "infra/platform/mock-stackvend-project.tfvars",
                           "scripts/apply.sh apply", "GOOGLE_OAUTH_CLIENT_ID"):
                self.assertIn(needle, msg)
            self.assertNotIn("gcloud secrets", msg)  # §8 Q2: tfvar only
        self.assertEqual(self.r["step8_state_after"], "absent")

    # ---------------------------------------------------------------- R1a-02 replay
    def test_replay_refused_public(self):
        self.outcome("replay_public", 401, state_read=False)
        self.assertEqual(self.r["replay_public_client_after"], "")

    def test_replay_refused_in_discovery_failure_window(self):
        self.assertTrue(self.r["window_identity_has_no_iap"])
        self.outcome("replay_window_anonymous", 401, state_read=False)
        self.outcome("replay_window_admin_cookie", 409, code=CODE)
        # IAP trust is off in the window: the assertion is no identity at all.
        self.outcome("replay_window_iap_assertion", 401, state_read=False)
        self.assertEqual(self.r["replay_window_client_after"], "")

    # ---------------------------------------------------------------- legitimate sign-in (negative tests)
    def test_pinned_env_sign_in_unchanged(self):
        self.assertEqual(self.r["legit_pinned_login"], [200, True])

    def test_firestore_configured_install_signs_in(self):
        self.assertEqual(self.r["legit_firestore_login"], [200, True, "firestore"])

    # ---------------------------------------------------------------- Secret Manager error rule (config.py)
    def test_secret_manager_error_means_no_client(self):
        for case in ("sm_permission_denied", "sm_unavailable", "sm_other_error"):
            self.assertEqual(self.r[case], ["", "", ""], case)
        self.assertEqual(self.r["sm_denied_login"], [503, False])  # typed SIGN_IN_CONFIG_UNAVAILABLE, no Firestore fallback

    def test_definitive_absence_still_falls_through_to_firestore(self):
        for case in ("sm_not_found", "sm_failed_precondition", "sm_empty_value"):
            self.assertEqual(self.r[case], [FS_CLIENT, FS_CLIENT, "firestore"], case)

    def test_secret_manager_value_still_wins(self):
        self.assertEqual(self.r["sm_value"], [NEW, NEW, "secret_manager"])

    # ---------------------------------------------------------------- fail loudly: configuration unreadable
    def test_login_sm_outage_typed_503(self):
        got = self.r["login_sm_outage"]
        self.assertEqual([got["status"], got["code"], got["set_cookie"], got["verify_calls"]],
                         [503, "SIGN_IN_CONFIG_UNAVAILABLE", False, 0])
        # Same read budget as before FD-103: one Secret Manager read, and no Firestore fallback after the error.
        self.assertEqual([got["sm_reads"], got["fs_platform_config_reads"]], [1, 0])

    def test_login_missing_credential_reads_nothing(self):
        got = self.r["login_sm_outage_missing_credential"]
        self.assertEqual([got["status"], got["sm_reads"], got["fs_platform_config_reads"]], [400, 0, 0])

    def test_login_fs_outage_typed_503(self):
        got = self.r["login_fs_outage"]
        self.assertEqual([got["status"], got["code"], got["set_cookie"], got["verify_calls"]],
                         [503, "SIGN_IN_CONFIG_UNAVAILABLE", False, 0])

    def test_page_unavailable_notice_instead_of_setup(self):
        for case in ("page_sm_outage_x_data", "page_fs_outage_x_data"):
            self.assertEqual(self.r[case], 'googleAuthController("", "mock-stackvend-project", true)', case)

    def test_absent_unchanged_401_and_setup_panel(self):
        # Negative test: a genuine absence is still "not configured" (401 after verification fails), setup shown.
        got = self.r["login_absent"]
        self.assertEqual([got["status"], got["code"], got["set_cookie"]], [401, None, False])
        self.assertEqual(self.r["page_absent_x_data"], 'googleAuthController("", "mock-stackvend-project", false)')

    def test_configured_unaffected(self):
        for case in ("login_configured", "login_configured_cached"):
            got = self.r[case]
            self.assertEqual([got["status"], got["set_cookie"]], [200, True], case)
        self.assertEqual([self.r["login_configured_cached"]["sm_reads"],
                          self.r["login_configured_cached"]["fs_platform_config_reads"]], [0, 0])
        self.assertEqual(self.r["page_configured_x_data"],
                         f'googleAuthController("{FS_CLIENT}", "mock-stackvend-project", false)')

    # ---------------------------------------------------------------- /health
    def test_health_has_no_client_field(self):
        self.assertEqual(self.r["health_status"], 200)
        self.assertEqual(self.r["health_keys"], ["auth_mode", "environment", "service", "status"])

    # ---------------------------------------------------------------- absent-state sign-in page
    def test_absent_page_is_instructions_only(self):
        self.assertEqual(self.r["page_status"], 401)
        page = self.r["page_text"]
        p = _Tags()
        p.feed(page)
        tags = [t for t, _ in p.tags]
        self.assertNotIn("input", tags)
        self.assertNotIn("form", tags)
        self.assertNotIn("textarea", tags)
        self.assertNotIn("/auth/config-client-id", page)
        self.assertNotIn("console.log", page)
        self.assertNotIn("saveClientId", page)
        for needle in ("cc_google_oauth_client_id", "infra/platform/mock-stackvend-project.tfvars",
                       "PROJECT_ID=mock-stackvend-project bash scripts/apply.sh apply", "GOOGLE_OAUTH_CLIENT_ID=",
                       'x-text="originUrl"'):
            self.assertIn(needle, page)
        # The only POST left on the page is the ordinary sign-in.
        self.assertIn("fetch('/auth/google-login'", page)


class TestFirstRunStaticFD103(unittest.TestCase):
    """In-process, no CC imports: the removed paths must not come back."""

    @staticmethod
    def read(*parts):
        with open(os.path.join(CC_DIR, *parts), encoding="utf-8") as f:
            return f.read()

    def test_sign_in_template_has_no_credential_logging_or_first_run_post(self):
        src = self.read("auth.py")
        i = src.index("def render_sign_in_html(")
        start = src.index('template = """', i) + len('template = """')
        template = src[start:src.index('"""', start)]
        for banned in ("console.log", "/auth/config-client-id", "pendingFirstRunClientId", "manualClientId", "<input"):
            self.assertNotIn(banned, template, banned)

    def test_route_never_verifies_a_token(self):
        src = self.read("routes", "web.py")
        i = src.index("def config_client_id(")
        body = src[i:src.index("\n@router.", i)]
        for banned in ("verify_google_login_credential", "_session_response", "credential"):
            self.assertNotIn(banned, body, banned)

    def test_health_has_no_client_field(self):
        self.assertNotIn("has_google_oauth_client_id", self.read("routes", "web.py"))

    def test_sign_in_template_shows_notice_not_setup_when_unavailable(self):
        src = self.read("auth.py")
        self.assertIn('x-show="configUnavailable"', src)
        # Hidden until Alpine shows it (the page has no [x-cloak] rule): no flash, and hidden if Alpine never loads.
        self.assertIn('<div x-show="configUnavailable" x-cloak style="display:none" ', src)
        self.assertIn('x-show="!clientId &amp;&amp; !configUnavailable"', src)


if __name__ == "__main__":
    unittest.main()
