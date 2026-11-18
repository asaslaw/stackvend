"""Lane 19 L19-0c (part): Control Center OAuth client pin guard + platform_config/cc_identity record.

Runtime cases run tests/cc_identity_harness_lane19.py in a clean `python -I` subprocess (same hermetic prefix as the
FD-4E / FD-4M harnesses). The GIS nonce + azp binding (rest of L19-0c) is not in this change: see
docs/handoff/wave2-lane19-stage2-report.md.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import subprocess
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "cc_identity_harness_lane19.py")
PINNED = "123456789012-ccpinned.apps.googleusercontent.com"
OTHER = "333-other.apps.googleusercontent.com"


def _run():
    env = hermetic_guard.child_env(
        drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL", "CC_INSECURE_LOCAL_COOKIES"),
        extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run([sys.executable, "-I", HARNESS], capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


class TestCcIdentityLane19(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.r = _run()

    def test_hermetic(self):
        self.assertEqual(self.r["network_attempts"], [])

    def test_pinned_client_cannot_be_changed_through_the_route(self):
        self.assertEqual(self.r["pinned_admin_status"], 409)
        self.assertEqual(self.r["pinned_anon_status"], 409)
        self.assertTrue(self.r["pinned_detail_names_tfvar"])
        self.assertEqual(self.r["pinned_no_sm_write"], 0)
        self.assertTrue(self.r["pinned_auth_doc_unchanged"])
        self.assertEqual(self.r["pinned_value_unchanged"], PINNED)

    def test_record_carries_client_source_and_revision(self):
        self.assertEqual(self.r["record_env"], [PINNED, "env", True, "product-control-center-ui-00042-abc"])
        self.assertEqual(self.r["record_keys"], ["env_pinned", "google_client_id", "revision", "source", "updated_at"])
        self.assertEqual(self.r["record_iap_source"], "iap_only")

    def test_unpinned_route_unchanged_and_record_follows_rotation(self):
        self.assertEqual(self.r["unpinned_admin_rotation_status"], 200)
        self.assertEqual(self.r["unpinned_rotation_sm_writes"], 1)
        self.assertEqual(self.r["unpinned_rotation_record_source"], "secret_manager")
        self.assertEqual(self.r["unpinned_rotation_record_client"], OTHER)
        self.assertEqual(self.r["unpinned_bad_id_status"], 400)

    def test_record_source_is_firestore_when_secret_manager_write_fails(self):
        # Lane 19 RT F6: the record must not claim Secret Manager holds a value it never received.
        self.assertEqual(self.r["f6_sm_write_failed_status"], 200)
        self.assertEqual(self.r["f6_sm_write_failed_record"], ["firestore", OTHER, OTHER])

    def test_lazy_resolution_after_failed_boot_read_republishes_record(self):
        # Lane 19 RT F3: boot read failed -> "none"; the later successful lazy read republishes.
        self.assertEqual(self.r["f3_boot_record"], ["none", ""])
        self.assertEqual(self.r["f3_still_failing_record"], "none")
        self.assertEqual(self.r["f3_lazy_value"], "444-lazy.apps.googleusercontent.com")
        self.assertEqual(self.r["f3_lazy_record"], ["secret_manager", "444-lazy.apps.googleusercontent.com"])
        self.assertEqual(self.r["f3_state"], "configured")
        self.assertEqual(self.r["f3_state_record"], ["firestore", OTHER])

    def test_startup_publishes_and_outage_never_breaks_boot(self):
        self.assertTrue(self.r["startup_published"])
        self.assertTrue(self.r["publish_outage_swallowed"])
