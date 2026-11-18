"""BOOTSTRAP-NO-GEMINI-KEY-PROMPT (owner 11-16): scripts/bootstrap.sh no longer asks for a Google AI Studio key.

The default (Vertex AI through IAM, what pressing Enter at the old prompt gave) is unchanged, and an install whose
Secret Manager secret castor-gemini-api-key already has an ENABLED version keeps it: bootstrap still writes
cc_gemini_api_key_from_secret = true and wires GEMINI_API_KEY into the Control Center as a secret reference. Bootstrap
never adds a version to that secret.

Runs the real scripts/bootstrap.sh under lane 5's hermetic harness (logging stubs for gcloud/tofu/curl/...; no GCP,
no network), with lane 19's gcloud wrapper, which records the stdin of every `secrets versions add`.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import test_platform_safe_apply_lane5 as L5  # noqa: E402  (module import only: no Test* class is re-collected)
import test_lane19_bootstrap_two_clients as L19  # noqa: E402  (module import only)

PROJ = L5.PROJ
GEMINI_FLAG = "cc_gemini_api_key_from_secret      = true"
WIRE = (f'gcloud run services update product-control-center-ui --update-secrets=GEMINI_API_KEY=castor-gemini-api-key:latest '
        f'--region=us-central1 --project={PROJ} --quiet')
VERSION = "projects/123456789012/secrets/castor-gemini-api-key/versions/1"


def _src():
    with open(os.path.join(L5.SCRIPTS, "bootstrap.sh"), encoding="utf-8") as f:
        return f.read()


class TestBootstrapSourceHasNoGeminiKeyPrompt(unittest.TestCase):
    def test_no_ai_studio_prompt_and_no_secret_version_add(self):
        src = _src()
        self.assertNotIn("AI Studio Gemini API Key", src)
        self.assertNotIn("INPUT_GEMINI_KEY", src)
        self.assertNotRegex(src, r"secrets versions add castor-gemini-api-key")

    def test_existing_key_detection_and_wiring_kept(self):
        src = _src()
        checks = re.findall(r'gcloud secrets versions list castor-gemini-api-key --project="\$\{PROJECT_ID\}" '
                            r'--filter="state=ENABLED"', src)
        self.assertEqual(len(checks), 2, "pre-apply check (tfvars flag) + post-apply check (Control Center wiring)")
        self.assertIn('--update-secrets="GEMINI_API_KEY=castor-gemini-api-key:latest"', src)
        self.assertEqual(src.count(f"echo '{GEMINI_FLAG}' >> \"${{TFVARS_PATH}}\""), 2)


class TestBootstrapRunGemini(L19._Boot):
    def _boot(self, **env):
        rc, out, err = self.boot(["", ""], public=False, **env)      # Direct IAP, no OAuth clients
        self.assertEqual(rc, 0, out + err)
        return out + err

    def _gemini_adds(self):
        return [c for c in self.calls() if c.startswith("gcloud secrets versions add castor-gemini-api-key")]

    def test_never_asks_for_a_key_and_uses_vertex_by_default(self):
        text = self._boot()
        self.assertNotIn("AI Studio", text)
        self.assertNotIn("Gemini API Key", text)
        self.assertIn("StackVend Assistant will use Google Cloud Vertex AI natively via IAM.", text)
        self.assertEqual(self._gemini_adds(), [])
        self.assertNotIn("castor-gemini-api-key", self.stdin_log())
        self.assertNotIn("cc_gemini_api_key_from_secret", L5._read(self.tfvars))
        self.assertNotIn(WIRE, self.calls())
        # both read-only ENABLED-version checks still run (unchanged from an Enter at the old prompt)
        lists = [c for c in self.calls() if c.startswith("gcloud secrets versions list castor-gemini-api-key")]
        self.assertEqual(len(lists), 2, lists)

    def test_existing_enabled_version_is_still_wired(self):
        text = self._boot(STUB_SECRET_VERSION=VERSION)
        self.assertNotIn("AI Studio", text)
        self.assertIn("Gemini API Key is served from Secret Manager (castor-gemini-api-key).", text)
        self.assertEqual(L5._read(self.tfvars).count(GEMINI_FLAG), 1)
        self.assertEqual([c for c in self.calls() if c == WIRE], [WIRE])
        self.assertEqual(self._gemini_adds(), [])
        self.assertNotIn("castor-gemini-api-key", self.stdin_log())


if __name__ == "__main__":
    unittest.main()
