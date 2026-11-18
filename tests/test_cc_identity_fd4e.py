"""FD-4E: Control Center identity hardening. Runs the real-crypto harness in a clean interpreter.

The root suite replaces google.oauth2.id_token / fastapi with MagicMocks in sys.modules, so real-crypto
auth tests must not run in-process. tests/cc_identity_harness.py is executed with `python -I` and is
hermetic (outbound sockets refused, ADC disabled, Firestore/Secret Manager stubbed).

Rows marked "legit" are the Do-No-Harm negative tests: the legitimate path must keep working.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "cc_identity_harness.py")
CC_DIR = os.path.join(HERE, "..", "apps", "control-center")

CC_URLS = ["https://product-control-center-ui-123456789.us-central1.run.app",
           "https://product-control-center-ui-abcdefghij-uc.a.run.app"]
FINOPS = "sa-castor-finops@mock-stackvend-project.iam.gserviceaccount.com"
IAP_AUD = "/projects/123456789/locations/us-central1/services/product-control-center-ui"


class TestControlCenterIdentityFD4E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy).
        env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET"), extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
        out = subprocess.run([sys.executable, "-I", HARNESS], capture_output=True, text=True, timeout=300, env=env)
        assert out.returncode == 0, out.stderr[-4000:]
        cls.r = json.loads(out.stdout.strip().splitlines()[-1])

    def expect(self, case, value):
        self.assertEqual(self.r[case], value, case)

    # ---------------------------------------------------------------- hermeticity
    def test_harness_made_no_network_calls(self):
        self.expect("network_attempts", [])

    def test_harness_exercised_both_cert_endpoints(self):
        self.expect("cert_urls_fetched", ["https://www.googleapis.com/oauth2/v1/certs",
                                          "https://www.gstatic.com/iap/verify/public_key"])

    def test_shared_client_stayed_cookie_free(self):
        self.expect("shared_client_cookie_jar_empty", True)

    # ---------------------------------------------------------------- public mode: attacks
    def test_pub_forged_iap_header(self):
        self.expect("pub_forged_iap_header", 401)

    def test_pub_signed_iap_jwt_ignored(self):
        self.expect("pub_signed_iap_jwt_ignored", 401)

    def test_pub_unsigned_jwt(self):
        self.expect("pub_unsigned_jwt", 401)

    def test_pub_bad_signature_jwt(self):
        self.expect("pub_bad_signature_jwt", 401)

    def test_pub_cookie_default_secret(self):
        self.expect("pub_cookie_default_secret", 401)

    def test_pub_attacker_sa_genuine(self):
        self.expect("pub_attacker_sa_genuine", 401)

    def test_pub_lookalike_sa(self):
        self.expect("pub_lookalike_sa", 401)

    def test_pub_finops_wrong_aud(self):
        self.expect("pub_finops_wrong_aud", 401)

    def test_pub_finops_path_aud_wrong_path(self):
        self.expect("pub_finops_path_aud_wrong_path", 401)

    def test_pub_finops_expired(self):
        self.expect("pub_finops_expired", 401)

    def test_pub_finops_unverified_email(self):
        self.expect("pub_finops_unverified_email", 401)

    def test_pub_discovery_failed_bearer_fails_closed(self):
        self.expect("pub_discovery_failed_bearer", 401)

    def test_pub_google_login_wrong_client(self):
        self.expect("pub_google_login_wrong_client", 401)

    # ---------------------------------------------------------------- C10: no machine caller any more
    # C10-MACHINE-CALLERS-OFF-CC (owner 11-07): the platform-caller allow-list is empty, so the former FinOps
    # scheduler / push bearer (even one that verifies, as the harness injects) is refused on the job routes (now
    # ADMIN) and on the push route (PUBSUB_PUSH); nothing is processed or written.
    def test_pub_former_scheduler_bearer_refused(self):
        for case in ("pub_scheduler_legit_hash_url", "pub_scheduler_legit_deterministic_url",
                     "pub_scheduler_sync_spend", "pub_scheduler_sweep"):
            self.expect(case, 403)

    def test_pub_former_pubsub_push_refused(self):
        self.expect("pub_pubsub_push_billing", 403)
        self.expect("pub_pubsub_push_billing_spend_written", None)

    def test_pub_pubsub_push_billing_anon_rejected(self):
        self.expect("pub_pubsub_push_billing_anon", 401)

    # ---------------------------------------------------------------- F2: identity resolution off the event loop
    def test_f2_slow_identity_resolution_does_not_block_other_requests(self):
        self.expect("f2_completion_order", ["fast", "slow"])
        self.expect("f2_statuses", [200, 200])
        self.expect("f2_fast_elapsed_under_1s", True)

    def test_f2_extract_runs_in_threadpool(self):
        self.expect("f2_extract_ran_off_main_thread", True)

    def test_pub_google_login_legit(self):
        self.expect("pub_google_login_legit", 200)
        self.expect("pub_google_login_sets_cookie", True)

    def test_pub_cookie_from_login(self):
        self.expect("pub_cookie_from_login", 200)

    def test_pub_viewer_cookie_admin_route(self):
        self.expect("pub_viewer_cookie_admin_route", 403)

    # ---------------------------------------------------------------- X-CloudScheduler bypass removed
    def test_pub_viewer_sweep_with_header(self):
        self.expect("pub_viewer_sweep_with_header", 403)

    def test_pub_anon_sweep_with_header(self):
        self.expect("pub_anon_sweep_with_header", 401)

    def test_pub_owner_sweep_cookie_legit(self):
        self.expect("pub_owner_sweep_cookie", 200)

    # ---------------------------------------------------------------- Direct-IAP mode
    def test_iap_valid_owner(self):
        self.expect("iap_valid_owner", 200)

    def test_iap_valid_viewer_admin_route(self):
        self.expect("iap_valid_viewer_admin_route", 403)

    def test_iap_header_without_jwt(self):
        self.expect("iap_header_without_jwt", 401)

    def test_iap_wrong_aud_lb(self):
        self.expect("iap_wrong_aud_lb", 401)

    def test_iap_wrong_issuer(self):
        self.expect("iap_wrong_issuer", 401)

    def test_iap_expired(self):
        self.expect("iap_expired", 401)

    def test_iap_wrong_key(self):
        self.expect("iap_wrong_key", 401)

    def test_iap_alg_none(self):
        self.expect("iap_alg_none", 401)

    def test_iap_invalid_jwt_plus_admin_cookie(self):
        self.expect("iap_invalid_jwt_plus_admin_cookie", 401)

    def test_iap_former_scheduler_bearer_refused(self):
        self.expect("iap_scheduler_legit", 403)   # C10: no platform caller

    # FINOPS-IAP-ACCESS (owner 10-26) is withdrawn by C10 (owner 11-07): an IAP assertion naming the former platform
    # SA is an ordinary IAP identity with no Control Center user, with or without a bearer: refused everywhere.
    def test_iap_forwarded_former_platform_caller_refused(self):
        for case in ("iap_fwd_scheduler_sync_spend", "iap_fwd_scheduler_sweep", "iap_fwd_pubsub_push_billing",
                     "iap_fwd_admin_route_still_confined", "iap_fwd_assertion_only",
                     "iap_fwd_assertion_plus_foreign_bearer", "iap_fwd_assertion_plus_wrong_aud_bearer"):
            self.expect(case, 403)

    def test_iap_human_assertion_unchanged_by_a_platform_bearer(self):
        self.expect("iap_fwd_human_assertion_plus_finops_bearer", 200)
        self.expect("iap_fwd_human_assertion_job_route", 200)  # a human ADMIN may run the job route (unchanged)

    # ---------------------------------------------------------------- first-run OAuth client-id bootstrap
    # F1: transient read errors fail closed (503, nothing stored), even with a valid phished owner token.
    def test_fr_transient_sm_error_503(self):
        self.expect("fr_state_sm_transient", "unknown")
        self.expect("fr_transient_sm_error_503", 503)

    def test_fr_transient_sm_permission_denied_503(self):
        self.expect("fr_transient_sm_denied_503", 503)

    def test_fr_transient_fs_error_503(self):
        self.expect("fr_state_fs_transient", "unknown")
        self.expect("fr_transient_fs_error_503", 503)

    def test_fr_transient_errors_store_nothing(self):
        self.expect("fr_transient_nothing_stored", ["", False, 0])

    def test_fr_genuine_absence_is_absent(self):
        # Negative test: Secret Manager NotFound AND no Firestore doc still allows first run (see fr_owner_completes).
        self.expect("fr_state_absent", "absent")

    def test_fr_state_configured_after_setup(self):
        self.expect("fr_state_after_configured", "configured")

    def test_fr_precondition_unconfigured(self):
        self.expect("fr_precondition_unconfigured", "")

    def test_fr_no_credential(self):
        self.expect("fr_no_credential", 401)

    def test_fr_empty_id(self):
        self.expect("fr_empty_id", 400)

    def test_fr_malformed_id(self):
        self.expect("fr_malformed_id", 400)

    def test_fr_suffix_only_id(self):
        self.expect("fr_suffix_only_id", 400)

    def test_fr_attacker_own_account(self):
        self.expect("fr_attacker_own_account", 403)

    def test_fr_attacker_replays_owner_token(self):
        self.expect("fr_attacker_replays_owner_token", 401)

    def test_fr_still_unconfigured(self):
        self.expect("fr_still_unconfigured", "")
        self.expect("fr_no_firestore_write_after_attacks", False)

    def test_fr_login_refused_unconfigured(self):
        self.expect("fr_login_refused_unconfigured", 401)

    def test_fr_owner_completes(self):
        self.expect("fr_owner_completes", 200)
        self.expect("fr_owner_completes_cookie", True)

    def test_fr_configured_value(self):
        self.expect("fr_configured_value", "222-owner.apps.googleusercontent.com")
        self.expect("fr_configured_persisted", "222-owner.apps.googleusercontent.com")

    def test_fr_after_unauthenticated(self):
        self.expect("fr_after_unauthenticated", 401)

    def test_fr_after_firstrun_proof_rejected(self):
        self.expect("fr_after_firstrun_proof_rejected", 401)

    def test_fr_after_viewer(self):
        self.expect("fr_after_viewer", 403)
        self.expect("fr_after_value_unchanged", "222-owner.apps.googleusercontent.com")

    def test_fr_after_admin_rotates(self):
        self.expect("fr_after_admin_rotates", 200)
        self.expect("fr_after_rotated_value", "333-x.apps.googleusercontent.com")

    # ---------------------------------------------------------------- session secret resolution
    def test_secret_cloudrun_unset(self):
        self.expect("secret_cloudrun_unset", "RuntimeError")

    def test_secret_cloudrun_default(self):
        self.expect("secret_cloudrun_default", "RuntimeError")

    def test_secret_cloudrun_short(self):
        self.expect("secret_cloudrun_short", "RuntimeError")

    def test_secret_cloudrun_ok(self):
        self.expect("secret_cloudrun_ok", True)

    def test_secret_local_unset(self):
        self.expect("secret_local_unset_len", 64)
        self.expect("secret_local_unset_random", True)
        self.expect("secret_process_value_not_default", True)

    # ---------------------------------------------------------------- runtime identity discovery
    def test_discover_local_public(self):
        self.expect("discover_local_public", ["", [], []])  # C10: empty allow-list

    def test_discover_iap_enabled(self):
        self.expect("discover_iap_enabled", [IAP_AUD, CC_URLS, []])  # C10: empty allow-list
        self.expect("discover_run_api_url",
                    "https://run.googleapis.com/v2/projects/mock-stackvend-project/locations/us-central1/services/product-control-center-ui")

    def test_discover_public_service(self):
        self.expect("discover_public_service", ["", CC_URLS, []])  # C10: empty allow-list

    def test_discover_uri_only_fallback(self):
        self.expect("discover_uri_only_fallback", ["", [CC_URLS[1]], []])  # C10: empty allow-list

    def test_discover_failure_fails_closed(self):
        self.expect("discover_failure_fails_closed", ["", [], []])  # C10: empty allow-list
        self.expect("discover_failure_retry_scheduled", True)
        self.expect("discover_failure_not_cached", True)
        self.expect("discover_failure_backoff_no_call", True)

    # ---------------------------------------------------------------- exact platform-caller allow-list
    def test_allowlist_former_finops_is_not_admin(self):
        self.expect("allowlist_exact_finops", None)   # C10: the allow-list is empty

    def test_allowlist_rejects_other_service_accounts(self):
        self.expect("allowlist_other_sa_denied", True)
        self.expect("allowlist_lookalike_denied", True)
        self.expect("allowlist_any_gsa_denied", True)


class TestControlCenterIdentityStaticGuardFD4E(unittest.TestCase):
    """In-process, no imports of CC code: the deleted trust paths must not come back."""

    def test_no_unverified_identity_paths_remain(self):
        def read(*parts):
            with open(os.path.join(CC_DIR, *parts), encoding="utf-8") as f:
                return f.read()

        src = read("auth.py") + read("routes", "web.py") + read("routes", "workloads.py")
        for banned in ("urlsafe_b64decode", "x-goog-authenticated-user-email", "X-CloudScheduler",
                       "audience=client_id_to_check if", "endswith(\".gserviceaccount.com\")"):
            self.assertNotIn(banned, src, banned)
        cfg = read("config.py")
        self.assertNotIn('os.getenv("SESSION_SECRET", "castor-platform-session-secret-key-2026")', cfg)
        self.assertIn("_PUBLISHED_DEFAULT_SESSION_SECRETS", cfg)


if __name__ == "__main__":
    unittest.main()
